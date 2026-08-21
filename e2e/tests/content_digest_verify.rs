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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
    /// TCP connections the listener accepted, readiness probe
    /// included. WOR-2528 asserts on the delta from a baseline taken
    /// right after `start()` so the probe does not skew the count.
    connects: Arc<AtomicUsize>,
    /// Connections that delivered a complete HTTP request header
    /// block. A bare TCP probe never reaches this counter, so a
    /// non-zero value means the proxy really dialed and spoke to the
    /// upstream for a request.
    requests: Arc<AtomicUsize>,
}

impl StubUpstream {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub upstream");
        let port = listener.local_addr().unwrap().port();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(Mutex::new(false));
        let connects = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let captured_clone = captured.clone();
        let shutdown_clone = shutdown.clone();
        let connects_clone = connects.clone();
        let requests_clone = requests.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if *shutdown_clone.lock().unwrap() {
                    break;
                }
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                connects_clone.fetch_add(1, Ordering::SeqCst);
                let cap = captured_clone.clone();
                let req_count = requests_clone.clone();
                std::thread::spawn(move || {
                    let _ = handle_conn(&mut stream, cap, req_count);
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
            connects,
            requests,
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn captured_body(&self) -> Vec<u8> {
        self.captured.lock().unwrap().clone()
    }

    /// TCP connections accepted so far.
    fn connects(&self) -> usize {
        self.connects.load(Ordering::SeqCst)
    }

    /// Requests whose header block fully arrived. This is the
    /// "did the proxy actually talk to the upstream" counter.
    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
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
    requests: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut counted_header = false;
    loop {
        if let Some(end) = find_headers_end(&buf) {
            if !counted_header {
                requests.fetch_add(1, Ordering::SeqCst);
                counted_header = true;
            }
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
fn repr_digest_header_is_accepted_as_fallback() {
    // WOR-805 PR2: per RFC 9530 §2 the proxy honours `Repr-Digest`
    // as an equivalent of `Content-Digest` for inbound requests
    // where we do not decode Content-Encoding. The body-filter wire
    // tries `Content-Digest` first; this test sends only
    // `Repr-Digest` and asserts the proxy accepts it.
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
            &[("repr-digest", header.as_str())],
        )
        .expect("post");
    assert_eq!(
        resp.status, 200,
        "repr-digest should verify just like content-digest"
    );
    assert_eq!(upstream.captured_body(), body);
}

#[test]
fn content_digest_wins_over_repr_digest_on_tie() {
    // When both headers are sent, the proxy honours `Content-Digest`
    // (clients that set both prefer it; falling back to `Repr-Digest`
    // only when the primary header is absent means a typo in the
    // primary value still produces a clear "Mismatch" rejection
    // rather than silently using the parallel header).
    let upstream = StubUpstream::start();
    let harness = ProxyHarness::start_with_yaml(&config_require(&upstream.url())).expect("start");
    let body = b"{\"hello\":\"world\"}".to_vec();
    let real_header = sha256_digest_header(&body);
    // Content-Digest carries a deliberately-wrong value; Repr-Digest
    // is correct. Because Content-Digest is tried first, the proxy
    // should reject.
    let resp = harness
        .post_bytes(
            "/payload",
            "digest.localhost",
            "application/json",
            body,
            &[
                (
                    "content-digest",
                    "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:",
                ),
                ("repr-digest", real_header.as_str()),
            ],
        )
        .expect("post");
    assert_eq!(
        resp.status, 400,
        "Content-Digest wins on tie; its bad value rejects the request"
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

// ---------------------------------------------------------------
// WOR-2528: `on_missing: require` must refuse at the edge.
//
// The refusal was correct and the timing was not. The check ran in
// `request_body_filter`, which Pingora reaches only after
// `upstream_peer` has picked a peer and the upstream connection is
// established, so a request the proxy had already decided to refuse
// paid a full upstream dial first. Against an upstream that does not
// answer, the client waits out the connect timeout for a verdict the
// proxy could have returned from the request headers alone. That is
// an availability bug, not a cosmetic one: the connection slot is
// held for the whole dial.
//
// Both tests below fail on the pre-fix build. The first fails on the
// counter: the upstream receives a request the proxy has already
// decided to refuse. The second fails on the verdict: pointed at an
// upstream it cannot reach, the pre-fix proxy answers 502 rather than
// the policy's 400, so the operator's fail-closed control is replaced
// by an upstream error on the way out. Against an upstream that is
// slow to connect rather than quick to refuse, the same ordering
// produces the multi-minute wait the ticket reported.
// ---------------------------------------------------------------

/// A digest-required origin pointed at TEST-NET-1 (RFC 5737 §3),
/// reserved for documentation and routed nowhere.
///
/// No dial ever happens for this address, on either side of the fix:
/// 192.0.2.0/24 is in the SSRF guard's blocked documentation ranges,
/// so the pre-fix proxy refused it at `upstream_peer` with a 502
/// after the policy had deferred to the body filter. What this test
/// pins is therefore the verdict alone: the policy's own 400 must
/// reach the client, not a 502 minted on the way toward an upstream
/// the proxy was never going to talk to. Timing proves nothing here,
/// so no timing is asserted.
fn config_require_unreachable_upstream() -> String {
    r#"
proxy:
  http_bind_port: 0
origins:
  "digest.localhost":
    policies:
      - type: content_digest
    action:
      type: proxy
      url: "http://192.0.2.1:80"
"#
    .to_string()
}

#[test]
fn missing_header_with_require_never_dials_upstream() {
    let upstream = StubUpstream::start();
    let harness = ProxyHarness::start_with_yaml(&config_require(&upstream.url())).expect("start");

    // Baseline after readiness probing so the harness's own probe and
    // the stub's startup probe are excluded from the delta.
    let connects_before = upstream.connects();
    assert_eq!(
        upstream.requests(),
        0,
        "no HTTP request should have reached the stub before the test body"
    );

    let body = b"{\"hello\":\"world\"}".to_vec();
    let resp = harness
        .post_bytes(
            "/payload",
            "digest.localhost",
            "application/json",
            body.clone(),
            // No content-digest header at all: the policy can decide
            // from the request headers, with no body and no upstream.
            &[],
        )
        .expect("post");

    assert_eq!(resp.status, 400, "missing digest under require is a 400");
    // Give a late upstream connection a chance to land before we
    // assert it did not happen; a race that only sometimes dials is
    // still the bug.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        upstream.requests(),
        0,
        "the upstream must never see a request the proxy already refused"
    );
    assert_eq!(
        upstream.connects(),
        connects_before,
        "the upstream must not even be dialed for a header-phase refusal"
    );
}

#[test]
fn missing_header_with_require_answers_without_the_upstream() {
    let harness =
        ProxyHarness::start_with_yaml(&config_require_unreachable_upstream()).expect("start");
    let body = b"{\"hello\":\"world\"}".to_vec();

    let started = Instant::now();
    let result = harness.post_bytes(
        "/payload",
        "digest.localhost",
        "application/json",
        body,
        &[],
    );
    let elapsed = started.elapsed();

    let resp = result.unwrap_or_else(|e| {
        panic!(
            "the refusal must not wait on the upstream: request failed after {elapsed:?} with {e}"
        )
    });
    assert_eq!(
        resp.status, 400,
        "the policy's own verdict must reach the client, not the upstream's failure; \
         got {} after {elapsed:?}",
        resp.status
    );
    let body_text = String::from_utf8_lossy(&resp.body);
    assert!(
        body_text.contains("required but absent"),
        "envelope must name the reason; got: {body_text}"
    );
}

#[test]
fn missing_header_with_require_honors_configured_error_body() {
    // The header-phase refusal is a different code path from the
    // body-phase one it replaces, so the operator-configured
    // `error_body` / `error_content_type` have to survive the move.
    let upstream = StubUpstream::start();
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "digest.localhost":
    policies:
      - type: content_digest
        on_missing: require
        missing_status: 428
        error_body: "digest required"
        error_content_type: "text/plain"
    action:
      type: proxy
      url: "{}"
"#,
        upstream.url()
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start");
    let resp = harness
        .post_bytes(
            "/payload",
            "digest.localhost",
            "application/json",
            b"{}".to_vec(),
            &[],
        )
        .expect("post");
    assert_eq!(resp.status, 428, "missing_status must be honored");
    assert_eq!(
        String::from_utf8_lossy(&resp.body),
        "digest required",
        "configured error_body must be emitted byte for byte"
    );
}
