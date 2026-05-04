//! End-to-end coverage for the `sse_chunking` response transform.
//!
//! The transform takes a buffered body and emits a Server Sent
//! Events (SSE) framed stream with `data: ` prefixes and double
//! newlines between events. We exercise three scenarios:
//!
//! 1. Default prefix turns plain lines into `data: ...` events.
//! 2. Custom `line_prefix` swaps `data: ` for `event: `.
//! 3. Already-prefixed lines pass through unchanged (no double prefix).
//!
//! These tests use a self-contained `static` action so the suite
//! does not depend on any external upstream.

use sbproxy_e2e::ProxyHarness;

// --- default prefix ---

#[test]
fn sse_chunking_adds_default_data_prefix_and_double_newline() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "sse.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "first event\nsecond event\nthird event"
    transforms:
      - type: sse_chunking
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "sse.local").expect("GET");
    assert_eq!(resp.status, 200);
    let body = resp.text().expect("utf8 body");

    // Each line should be prefixed and followed by a blank line.
    assert_eq!(
        body, "data: first event\n\ndata: second event\n\ndata: third event\n\n",
        "sse_chunking output should be properly framed"
    );
}

// --- custom prefix ---

#[test]
fn sse_chunking_respects_custom_line_prefix() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "sse-evt.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "alpha\nbeta"
    transforms:
      - type: sse_chunking
        line_prefix: "event: "
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "sse-evt.local").expect("GET");
    assert_eq!(resp.status, 200);
    let body = resp.text().expect("utf8 body");
    assert_eq!(body, "event: alpha\n\nevent: beta\n\n");
}

// --- pass-through for already-framed input ---

#[test]
fn sse_chunking_does_not_double_prefix_already_framed_lines() {
    // The upstream is already SSE-framed (an LLM provider, for
    // instance). The transform must keep the existing `data: `
    // prefix instead of producing `data: data: ...`.
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "sse-llm.local":
    action:
      type: static
      status_code: 200
      content_type: text/event-stream
      body: |
        data: {"chunk": 1}
        data: {"chunk": 2}
        data: [DONE]
    transforms:
      - type: sse_chunking
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "sse-llm.local").expect("GET");
    assert_eq!(resp.status, 200);
    let body = resp.text().expect("utf8 body");

    // No double prefix.
    assert!(
        !body.contains("data: data:"),
        "lines that already start with `data: ` must not be re-prefixed: {}",
        body
    );
    // All three events round-trip.
    assert!(body.contains("data: {\"chunk\": 1}\n\n"));
    assert!(body.contains("data: {\"chunk\": 2}\n\n"));
    assert!(body.contains("data: [DONE]\n\n"));
}

// --- empty body ---

#[test]
fn sse_chunking_passes_empty_body_through_unchanged() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "sse-empty.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ""
    transforms:
      - type: sse_chunking
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "sse-empty.local").expect("GET");
    assert_eq!(resp.status, 200);
    assert!(resp.body.is_empty(), "empty body should remain empty");
}
