//! End-to-end coverage for the `request_limit` policy.
//!
//! Exercises the documented behaviour from
//! `examples/34-request-limit/sb.yml`: requests that exceed any of
//! `max_body_size`, `max_url_length`, `max_header_count`, or
//! `max_query_string_length` are rejected with 413 (request entity
//! too large) before any upstream is contacted. See
//! `crates/sbproxy-core/src/server.rs` `Policy::RequestLimit` for
//! the wiring.

use sbproxy_e2e::ProxyHarness;

#[test]
fn body_size_under_limit_passes_and_over_limit_returns_413() {
    // Streaming-time body enforcement: every chunk delivered to
    // `request_body_filter` is summed against the configured cap and
    // rejected with 413 once the cap is crossed. This catches both
    // honest oversize uploads and clients that omit or lie about
    // `Content-Length`.
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "limit.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: request_limit
        max_body_size: 1024
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let client = reqwest::blocking::Client::new();

    // GET with no body - under the cap, must succeed.
    let resp = harness.get("/", "limit.localhost").expect("send");
    assert_eq!(
        resp.status, 200,
        "max_body_size config alone must not break the request path"
    );

    // POST a 4 KiB payload against a 1 KiB cap. Must be rejected with 413.
    let big = vec![b'x'; 4096];
    let oversize = client
        .post(format!("{}/upload", harness.base_url()))
        .header("host", "limit.localhost")
        .header("content-type", "application/octet-stream")
        .body(big)
        .send()
        .expect("send oversize body");
    assert_eq!(
        oversize.status().as_u16(),
        413,
        "body over max_body_size must be rejected with 413"
    );

    // POST a tiny payload, well under the cap.
    let small = client
        .post(format!("{}/upload", harness.base_url()))
        .header("host", "limit.localhost")
        .header("content-type", "application/octet-stream")
        .body(vec![b'x'; 32])
        .send()
        .expect("send small body");
    assert_eq!(
        small.status().as_u16(),
        200,
        "body well under max_body_size must be accepted"
    );
}

#[test]
fn url_over_limit_returns_413() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "limit.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: request_limit
        max_url_length: 4000
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");

    // 5000-character path. Any reqwest path overhead just makes
    // the URL longer, so the limit trips deterministically.
    let long = "a".repeat(5000);
    let resp = harness
        .get(&format!("/{long}"), "limit.localhost")
        .expect("oversize URL request");
    assert_eq!(
        resp.status, 413,
        "URL over max_url_length must be rejected with 413; got {}",
        resp.status
    );
}

#[test]
fn header_count_over_limit_returns_413() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "limit.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: request_limit
        max_header_count: 20
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let client = reqwest::blocking::Client::new();

    // Build a request with 50 custom headers; reqwest plus the
    // Host header pushes the count well past 20.
    let mut req = client
        .get(format!("{}/", harness.base_url()))
        .header("host", "limit.localhost");
    for i in 0..50 {
        req = req.header(format!("x-extra-{i}"), "v");
    }
    let resp = req.send().expect("send fat-header request");
    assert_eq!(
        resp.status().as_u16(),
        413,
        "request with too many headers must be rejected with 413"
    );
}

#[test]
fn query_string_over_limit_returns_413() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "limit.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: request_limit
        max_query_string_length: 100
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");

    // 4000-char query string blows past the 100-char cap. URL itself
    // is comfortably under the default url length budget.
    let long_query: String = "v=".to_string() + &"x".repeat(4000);
    let resp = harness
        .get(&format!("/path?{long_query}"), "limit.localhost")
        .expect("oversize query");
    assert_eq!(
        resp.status, 413,
        "query string over max_query_string_length must be rejected; got {}",
        resp.status
    );
}

#[test]
fn small_request_under_all_limits_passes() {
    // Same shape as the example: tight body / header / URL caps,
    // benign request.
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "limit.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: request_limit
        max_body_size: 1024
        max_header_count: 30
        max_url_length: 256
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");

    let resp = harness.get("/short", "limit.localhost").expect("send");
    assert_eq!(
        resp.status, 200,
        "small benign request must pass under tight limits; got {}",
        resp.status
    );
}
