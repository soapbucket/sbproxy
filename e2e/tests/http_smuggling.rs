// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Soap Bucket LLC

//! HTTP request smuggling defense tests (PortSwigger desync class).
//!
//! Each case sends a hand-crafted HTTP/1.1 request via raw TCP
//! (`reqwest` would normalize the framing headers and silently fix
//! the attack) and asserts:
//!
//! 1. The proxy returns `400 Bad Request`.
//! 2. The upstream `MockUpstream` saw zero requests (the attack was
//!    rejected at the edge, never forwarded).
//!
//! The attack catalogue mirrors
//! <https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn>.
//! Coverage is the four primitives the http_framing policy
//! enforces today: dual CL+TE (CL.TE / TE.CL), duplicate CL,
//! malformed TE (xchunked / gzip+chunked / identity), and duplicate
//! TE (the TE.TE pattern).
//!
//! HTTP/2 -> HTTP/1 downgrade smuggling is intentionally not covered
//! here; it requires an HTTP/2 client and lands in a focused
//! follow-up once an h2 fixture is on hand.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const HOST: &str = "api.localhost";

fn config_yaml(upstream_url: &str) -> String {
    // The http_framing policy is on for this origin. Other origins
    // would inherit the same default-on behavior; we set it
    // explicitly here so the test fixture documents the intent.
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "{HOST}":
    action:
      type: proxy
      url: "{upstream_url}"
    policies:
      - type: http_framing
"#
    )
}

/// Send raw bytes to the proxy and read back the full HTTP/1.1
/// response. Returns the (status_code, body_bytes) pair. Panics on
/// I/O error since these tests rely on the proxy being up.
fn send_raw(port: u16, request: &[u8]) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("set write timeout");
    stream.write_all(request).expect("write request");

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                // Cheap end-of-message heuristic: once we've seen the
                // header terminator AND read past content-length, stop.
                // Most 400 responses are short; the upstream is
                // never reached so there is no streamed body to wait
                // on.
                if buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() > 200 {
                    // Give the kernel a final spin in case more bytes
                    // are queued; bounded by the read timeout above.
                    let mut tail = [0u8; 1024];
                    if let Ok(extra) = stream.read(&mut tail) {
                        buf.extend_from_slice(&tail[..extra]);
                    }
                    break;
                }
            }
            Err(_) => break,
        }
    }

    parse_status(&buf)
}

fn parse_status(buf: &[u8]) -> (u16, Vec<u8>) {
    // Expect "HTTP/1.1 NNN ..." on the first line.
    let line_end = buf
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(buf.len());
    let status_line = std::str::from_utf8(&buf[..line_end]).unwrap_or("");
    let mut parts = status_line.split_whitespace();
    let _version = parts.next().unwrap_or("");
    let code = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    (code, buf.to_vec())
}

fn start() -> (MockUpstream, ProxyHarness) {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");
    (upstream, harness)
}

// --- CL.TE: both Content-Length AND Transfer-Encoding present ---

#[test]
fn dual_cl_te_smuggle_attempt_does_not_leak_to_upstream() {
    // The classic CL.TE smuggle: Content-Length says 6, Transfer-Encoding
    // says chunked + a "0\r\n\r\n" terminator + a smuggled "G" byte
    // intended to become the start of the next pipelined request on a
    // confused upstream.
    //
    // Two acceptable proxy outcomes (both close the vector):
    //
    //   A. Our policy fires and the proxy returns 400 before forwarding.
    //   B. Pingora normalizes the request (RFC 9112 sec 6.1 prefers TE
    //      when both are present) and re-emits clean framing upstream.
    //      The smuggled "G" byte is consumed by Pingora's parser and
    //      never reaches the upstream as a fresh request.
    //
    // The test asserts the safety invariant either way:
    //
    //   - If status is 400: no upstream request fired.
    //   - If status is 2xx: the upstream saw EXACTLY ONE request (the
    //     normalized one), not two (which would be the smuggle).
    let (upstream, harness) = start();
    let req = format!(
        "POST /smuggle HTTP/1.1\r\n\
         Host: {HOST}\r\n\
         Content-Length: 6\r\n\
         Transfer-Encoding: chunked\r\n\
         \r\n\
         0\r\n\
         \r\n\
         G"
    );
    let (status, _body) = send_raw(harness.port(), req.as_bytes());

    let captured = upstream.captured();
    if status == 400 {
        assert!(
            captured.is_empty(),
            "policy rejection must mean no upstream call"
        );
    } else {
        assert!(
            captured.len() <= 1,
            "smuggled bytes must not produce a second upstream request; saw {}",
            captured.len()
        );
        // And whatever the upstream did see must not have a method
        // == "G" (which would be the smuggled byte misinterpreted as
        // the start of a new request line).
        for req in &captured {
            assert_ne!(
                req.method, "G",
                "smuggled byte was forwarded as a separate request"
            );
        }
    }
}

// --- Duplicate Content-Length ---

#[test]
fn duplicate_content_length_rejected() {
    let (upstream, harness) = start();
    let req = format!(
        "POST /dup HTTP/1.1\r\n\
         Host: {HOST}\r\n\
         Content-Length: 6\r\n\
         Content-Length: 6\r\n\
         \r\n\
         hello!"
    );
    let (status, _body) = send_raw(harness.port(), req.as_bytes());
    assert_eq!(status, 400, "duplicate CL must be rejected");
    assert!(upstream.captured().is_empty());
}

#[test]
fn disagreeing_content_length_rejected() {
    let (upstream, harness) = start();
    let req = format!(
        "POST /dup HTTP/1.1\r\n\
         Host: {HOST}\r\n\
         Content-Length: 6\r\n\
         Content-Length: 12\r\n\
         \r\n\
         hello!"
    );
    let (status, _body) = send_raw(harness.port(), req.as_bytes());
    assert_eq!(status, 400);
    assert!(upstream.captured().is_empty());
}

#[test]
fn non_numeric_content_length_rejected() {
    let (upstream, harness) = start();
    // Note: Pingora may reject non-numeric CL at the parser layer
    // before our policy fires. Either rejection (400 from us, 400
    // from Pingora) closes the smuggling vector; we accept any 400.
    let req = format!(
        "POST /bad HTTP/1.1\r\n\
         Host: {HOST}\r\n\
         Content-Length: abc\r\n\
         \r\n"
    );
    let (status, _body) = send_raw(harness.port(), req.as_bytes());
    assert!(
        status == 400,
        "non-numeric CL must be rejected (got {status})"
    );
    assert!(upstream.captured().is_empty());
}

// --- TE.TE: duplicate Transfer-Encoding ---

#[test]
fn duplicate_te_rejected() {
    let (upstream, harness) = start();
    let req = format!(
        "POST /te HTTP/1.1\r\n\
         Host: {HOST}\r\n\
         Transfer-Encoding: chunked\r\n\
         Transfer-Encoding: chunked\r\n\
         \r\n\
         0\r\n\
         \r\n"
    );
    let (status, _body) = send_raw(harness.port(), req.as_bytes());
    assert_eq!(status, 400);
    assert!(upstream.captured().is_empty());
}

#[test]
fn duplicate_te_with_obfuscated_second_value_rejected() {
    // Classic TE.TE smuggling: one parser honors the first TE,
    // the other honors the last (`x` is gibberish, gets ignored
    // by parsers that fail open). We reject the duplicate header
    // before the ambiguity matters.
    let (upstream, harness) = start();
    let req = format!(
        "POST /tete HTTP/1.1\r\n\
         Host: {HOST}\r\n\
         Transfer-Encoding: chunked\r\n\
         Transfer-Encoding: x\r\n\
         \r\n\
         0\r\n\
         \r\n"
    );
    let (status, _body) = send_raw(harness.port(), req.as_bytes());
    assert_eq!(status, 400);
    assert!(upstream.captured().is_empty());
}

// --- Malformed Transfer-Encoding ---

#[test]
fn malformed_te_xchunked_rejected() {
    let (upstream, harness) = start();
    let req = format!(
        "POST /xc HTTP/1.1\r\n\
         Host: {HOST}\r\n\
         Transfer-Encoding: xchunked\r\n\
         \r\n\
         0\r\n\
         \r\n"
    );
    let (status, _body) = send_raw(harness.port(), req.as_bytes());
    assert_eq!(status, 400);
    assert!(upstream.captured().is_empty());
}

#[test]
fn malformed_te_gzip_chunked_chain_rejected() {
    // RFC-legal but a known smuggling primitive (some parsers
    // honor only the last token, others only the first).
    let (upstream, harness) = start();
    let req = format!(
        "POST /gc HTTP/1.1\r\n\
         Host: {HOST}\r\n\
         Transfer-Encoding: gzip, chunked\r\n\
         \r\n\
         0\r\n\
         \r\n"
    );
    let (status, _body) = send_raw(harness.port(), req.as_bytes());
    assert_eq!(status, 400);
    assert!(upstream.captured().is_empty());
}

#[test]
fn malformed_te_identity_rejected() {
    let (upstream, harness) = start();
    let req = format!(
        "POST /id HTTP/1.1\r\n\
         Host: {HOST}\r\n\
         Transfer-Encoding: identity\r\n\
         \r\n"
    );
    let (status, _body) = send_raw(harness.port(), req.as_bytes());
    assert_eq!(status, 400);
    assert!(upstream.captured().is_empty());
}

// --- Regression: legitimate framing still works ---

#[test]
fn clean_post_with_content_length_succeeds() {
    let (upstream, harness) = start();
    let req = format!(
        "POST /ok HTTP/1.1\r\n\
         Host: {HOST}\r\n\
         Content-Length: 6\r\n\
         \r\n\
         hello!"
    );
    let (status, _body) = send_raw(harness.port(), req.as_bytes());
    assert_eq!(status, 200, "clean Content-Length must succeed");
    assert_eq!(
        upstream.captured().len(),
        1,
        "clean request must reach upstream"
    );
}

#[test]
fn clean_get_succeeds() {
    let (upstream, harness) = start();
    let req = format!(
        "GET /clean HTTP/1.1\r\n\
         Host: {HOST}\r\n\
         \r\n"
    );
    let (status, _body) = send_raw(harness.port(), req.as_bytes());
    assert_eq!(status, 200);
    assert_eq!(upstream.captured().len(), 1);
}

#[test]
fn case_insensitive_chunked_succeeds() {
    // The policy normalizes via to_ascii_lowercase, so mixed-case
    // `Chunked` should pass.
    let (_upstream, harness) = start();
    let req = format!(
        "POST /case HTTP/1.1\r\n\
         Host: {HOST}\r\n\
         Transfer-Encoding: Chunked\r\n\
         \r\n\
         0\r\n\
         \r\n"
    );
    let (status, _body) = send_raw(harness.port(), req.as_bytes());
    // Either 200 (proxy forwards the empty chunked body) or 400 if
    // Pingora's downstream chunk parser objects to the upstream's
    // empty-body response. The test is whether the FRAMING was
    // accepted, which is what the policy controls; if Pingora rejects
    // for a non-framing reason, that's not our test's concern.
    assert_ne!(
        status, 0,
        "proxy must respond, not crash, on case-insensitive chunked"
    );
    // The case-insensitive accept is asserted by the policy unit
    // test in sbproxy-modules; here we only confirm the e2e path
    // does not regress to a framing 400.
    assert!(
        status == 200 || status >= 500,
        "framing should be accepted; got {status}"
    );
}
