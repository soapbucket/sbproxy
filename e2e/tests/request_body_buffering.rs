//! Multi-chunk request bodies through the validator buffer (WOR-2138).
//!
//! Policies that set `validate_request_body` make `request_body_filter`
//! consume each inbound chunk into a local accumulator and release the
//! whole payload at end-of-stream. Pingora treats a `None` body slot as
//! end-of-body on both HTTP/1.1 and HTTP/2, so a consumed mid-stream
//! chunk must leave an empty chunk behind; the regression fixed here
//! left `None` and the upstream saw a silently truncated request. The
//! bodies below are large enough that Pingora is guaranteed to deliver
//! them to the body filter across several chunks, on both downstream
//! protocols.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

const VALIDATED_PROXY_CONFIG: &str = r#"
proxy:
  http_bind_port: 0
  http2_cleartext: true
origins:
  "api.localhost":
    action:
      type: proxy
      url: "{base}"
    policies:
      - type: request_validator
        schema:
          type: object
"#;

/// A JSON body large enough to arrive at `request_body_filter` in
/// several chunks, with a position-dependent filler so any dropped,
/// duplicated, or reordered range changes the bytes.
fn multi_chunk_json_body() -> Vec<u8> {
    let mut filler = String::with_capacity(768 * 1024);
    let mut i: u64 = 0;
    while filler.len() < 768 * 1024 {
        filler.push_str(&format!("chunk-{i:08x}-"));
        i += 1;
    }
    serde_json::to_vec(&json!({ "data": filler })).expect("body serialises")
}

fn assert_upstream_saw_every_byte(upstream: &MockUpstream, sent: &[u8]) {
    let captured = upstream.captured();
    assert_eq!(
        captured.len(),
        1,
        "the upstream must see exactly one request"
    );
    assert_eq!(
        captured[0].body.len(),
        sent.len(),
        "the upstream body length must match what the client sent"
    );
    assert_eq!(
        captured[0].body, sent,
        "the upstream must receive every body byte in order"
    );
}

#[test]
fn validated_multi_chunk_body_reaches_upstream_intact_over_http1() {
    let upstream = MockUpstream::start(json!({"ok": true})).unwrap();
    let yaml = VALIDATED_PROXY_CONFIG.replace("{base}", &upstream.base_url());
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let body = multi_chunk_json_body();
    let resp = harness
        .post_bytes(
            "/v1/data",
            "api.localhost",
            "application/json",
            body.clone(),
            &[],
        )
        .expect("send");
    assert!(
        (200..300).contains(&resp.status),
        "a schema-valid body must pass, got {}",
        resp.status
    );
    assert_upstream_saw_every_byte(&upstream, &body);
}

#[test]
fn validated_multi_chunk_body_reaches_upstream_intact_over_http2() {
    let upstream = MockUpstream::start(json!({"ok": true})).unwrap();
    let yaml = VALIDATED_PROXY_CONFIG.replace("{base}", &upstream.base_url());
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    // The harness client speaks HTTP/1.1; build an h2c prior-knowledge
    // client so the downstream leg is HTTP/2. The `resolve` override
    // routes `api.localhost` to the proxy so the `:authority`
    // pseudo-header carries the origin hostname (the proxy strips the
    // port when matching).
    let proxy_addr: std::net::SocketAddr = format!("127.0.0.1:{}", harness.port())
        .parse()
        .expect("proxy addr parses");
    let client = reqwest::blocking::Client::builder()
        .http2_prior_knowledge()
        .resolve("api.localhost", proxy_addr)
        .build()
        .expect("h2c client builds");

    let body = multi_chunk_json_body();
    let resp = client
        .post(format!("http://api.localhost:{}/v1/data", harness.port()))
        .header("content-type", "application/json")
        .body(body.clone())
        .send()
        .expect("send");
    assert!(
        resp.status().is_success(),
        "a schema-valid body must pass, got {}",
        resp.status()
    );
    assert_upstream_saw_every_byte(&upstream, &body);
}
