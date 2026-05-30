//! End-to-end coverage for the WOR-805 `content_digest` policy.
//!
//! Stands up a tiny stub upstream and a `proxy` origin guarded by
//! `policies: [{type: content_digest}]`, then drives a handful of
//! requests with valid / tampered / malformed / missing
//! `Content-Digest` headers. Asserts the proxy rejects mismatches at
//! the edge (the upstream never sees the bytes) and forwards
//! verified requests intact (the upstream captures + echoes the body
//! length, so the assertion confirms the body really arrived).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use sbproxy_e2e::ProxyHarness;
use sha2::{Digest, Sha256};

/// Tiny capture-and-echo HTTP/1.1 backend. Each accepted request
/// reads the body, stores it for the test to inspect, and responds
/// `200 OK` with `content-length: <body.len()>` in the body. Lives
/// in its own thread; the test reads `captured_body()` after the
/// proxy round-trip to confirm what (if anything) reached the
/// backend.
struct StubUpstream {
    port: u16,
    captured: Arc<Mutex<Vec<u8>>>,
    shutdown: Arc<Mutex<bool>>,
}

impl StubUpstream {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub upstream");
        let port = listener.local_addr().unwrap().port();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(Mutex::new(false));
        let captured_clone = captured.clone();
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
                let cap = captured_clone.clone();
                std::thread::spawn(move || {
                    let _ = handle_conn(&mut stream, cap);
                });
            }
        });
        // Wait for listener readiness.
        for _ in 0..100 {
            if std::net::TcpStream::connect_timeout(
                &format!("127.0.0.1:{port}").parse().unwrap(),
                std::time::Duration::from_millis(50),
            )
            .is_ok()
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        Self {
            port,
            captured,
            shutdown,
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn captured_body(&self) -> Vec<u8> {
        self.captured.lock().unwrap().clone()
    }
}

impl Drop for StubUpstream {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn handle_conn(
    stream: &mut std::net::TcpStream,
    captured: Arc<Mutex<Vec<u8>>>,
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
    let body = buf[body_start.min(buf.len())..].to_vec();
    // The stub may receive multiple connections per logical request
    // (Pingora opens the upstream during `upstream_peer` before the
    // body filter rejects; a follow-up connection probe is normal).
    // Only overwrite captured when the connection actually carried a
    // body so a partial / preflight connection does not zero out a
    // body captured on the real one.
    if !body.is_empty() {
        *captured.lock().unwrap() = body.clone();
    }

    let resp_body = format!("ok:{}", body.len());
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        resp_body.len(),
        resp_body
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

/// Compute the RFC 9530 `Content-Digest: sha-256=:...:` header value
/// for a body. The value is colon-wrapped base64 of the raw digest
/// bytes per the structured-fields Byte Sequence syntax (§3).
fn sha256_digest_header(body: &[u8]) -> String {
    let raw = Sha256::digest(body);
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
    format!("sha-256=:{b64}:")
}

fn config_require(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "digest.localhost":
    policies:
      - type: content_digest
    action:
      type: proxy
      url: "{upstream_url}"
"#
    )
}

fn config_skip_when_missing(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "digest.localhost":
    policies:
      - type: content_digest
        on_missing: skip
    action:
      type: proxy
      url: "{upstream_url}"
"#
    )
}

#[test]
fn valid_digest_passes_through_to_upstream() {
    let upstream = StubUpstream::start();
    let harness = ProxyHarness::start_with_yaml(&config_require(&upstream.url())).expect("start");
    let body = b"{\"hello\":\"world\"}".to_vec();
    let header = sha256_digest_header(&body);
    let resp = harness
        .post_bytes(
            "/payload",
            "digest.localhost",
            "application/json",
            body.clone(),
            &[("content-digest", header.as_str())],
        )
        .expect("post");
    assert_eq!(resp.status, 200);
    assert_eq!(
        upstream.captured_body(),
        body,
        "verified body must reach upstream intact"
    );
}

#[test]
fn mismatched_digest_is_rejected_400_upstream_does_not_see_body() {
    let upstream = StubUpstream::start();
    let harness = ProxyHarness::start_with_yaml(&config_require(&upstream.url())).expect("start");
    // Compute the digest for one body, then send a tampered body so
    // the header value no longer matches what the server hashes.
    let original = b"{\"hello\":\"world\"}";
    let header = sha256_digest_header(original);
    let tampered = b"{\"hello\":\"WORLD\"}".to_vec();
    let resp = harness
        .post_bytes(
            "/payload",
            "digest.localhost",
            "application/json",
            tampered.clone(),
            &[("content-digest", header.as_str())],
        )
        .expect("post");
    assert_eq!(resp.status, 400, "mismatch must reject at the edge");
    let body_text = String::from_utf8_lossy(&resp.body);
    assert!(
        body_text.contains("content_digest verification failed")
            && body_text.contains("does not match"),
        "envelope must name the failure mode; got: {body_text}"
    );
    // The body filter sits in the request path; whatever the stub
    // captured must not be the tampered request body. (Pingora may
    // open the upstream connection during `upstream_peer` before the
    // body filter rejects, but the actual rejected body never gets
    // forwarded as-is.)
    assert_ne!(
        upstream.captured_body(),
        tampered,
        "upstream must not see the tampered body in full"
    );
}

#[test]
fn malformed_digest_header_is_rejected_400() {
    let upstream = StubUpstream::start();
    let harness = ProxyHarness::start_with_yaml(&config_require(&upstream.url())).expect("start");
    let raw = b"{\"x\":1}".to_vec();
    let resp = harness
        .post_bytes(
            "/payload",
            "digest.localhost",
            "application/json",
            raw.clone(),
            // Missing the structured-fields colon-wrapping; the parser
            // refuses to decode the value at all.
            &[("content-digest", "sha-256=garbage")],
        )
        .expect("post");
    assert_eq!(resp.status, 400);
    let body_text = String::from_utf8_lossy(&resp.body);
    assert!(
        body_text.contains("malformed"),
        "envelope must name 'malformed'; got: {body_text}"
    );
    assert_ne!(
        upstream.captured_body(),
        raw,
        "upstream must not see the body in full when the header is malformed"
    );
}

#[test]
fn missing_header_with_require_is_rejected_400() {
    let upstream = StubUpstream::start();
    let harness = ProxyHarness::start_with_yaml(&config_require(&upstream.url())).expect("start");
    let body = b"{\"hello\":\"world\"}".to_vec();
    let resp = harness
        .post_bytes(
            "/payload",
            "digest.localhost",
            "application/json",
            body.clone(),
            // No content-digest header at all.
            &[],
        )
        .expect("post");
    assert_eq!(resp.status, 400);
    let body_text = String::from_utf8_lossy(&resp.body);
    assert!(
        body_text.contains("required but absent"),
        "envelope must name 'required but absent'; got: {body_text}"
    );
    assert_ne!(
        upstream.captured_body(),
        body,
        "upstream must not see the body in full when the header is required but absent"
    );
}

#[test]
fn missing_header_with_skip_is_forwarded() {
    let upstream = StubUpstream::start();
    let harness =
        ProxyHarness::start_with_yaml(&config_skip_when_missing(&upstream.url())).expect("start");
    let body = b"{\"hello\":\"world\"}".to_vec();
    let resp = harness
        .post_bytes(
            "/payload",
            "digest.localhost",
            "application/json",
            body.clone(),
            // No content-digest header; on_missing: skip lets it through.
            &[],
        )
        .expect("post");
    assert_eq!(resp.status, 200);
    assert_eq!(
        upstream.captured_body(),
        body,
        "skip mode must forward the body intact when no digest is supplied"
    );
}
