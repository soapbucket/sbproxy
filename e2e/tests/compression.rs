//! End-to-end coverage for response compression.
//!
//! `examples/67-compression/sb.yml` documents the contract: a
//! `compression:` block with `algorithms: [br, gzip, zstd]` and a
//! `min_size` floor selects the best algorithm advertised in the
//! client's `Accept-Encoding` header. Algorithm negotiation is
//! implemented in `crates/sbproxy-middleware/src/compression.rs`
//! and the response pipeline in `crates/sbproxy-core/src/server.rs`
//! consumes the negotiated encoding to compress the upstream body
//! before it goes to the client.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;
use std::io::Read;

fn config_yaml(upstream_url: &str, algorithms: &str, min_size: usize) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "comp.localhost":
    compression:
      enabled: true
      algorithms: {algorithms}
      min_size: {min_size}
    action:
      type: proxy
      url: "{upstream_url}"
"#
    )
}

/// Build a JSON payload large enough to clear the compression floor
/// and compressible enough to shrink meaningfully.
fn large_compressible_payload() -> serde_json::Value {
    let filler = "abcdefghijklmnopqrstuvwxyz0123456789".repeat(64);
    json!({
        "data": filler,
        "repeated": vec!["sbproxy compression e2e payload"; 64],
    })
}

#[test]
fn compression_block_loads_and_proxy_serves_traffic() {
    // Pin: an origin with compression configured boots cleanly and
    // serves a request end-to-end. Negotiation correctness lives in
    // the middleware unit tests today.
    let upstream = MockUpstream::start(json!({"data": "ok"})).expect("upstream");
    let proxy =
        ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url(), "[br, gzip, zstd]", 512))
            .expect("start proxy");

    let resp = proxy
        .get_with_headers(
            "/payload",
            "comp.localhost",
            &[("accept-encoding", "gzip, br, zstd")],
        )
        .expect("send");
    assert_eq!(resp.status, 200, "proxied request should still succeed");
    assert_eq!(upstream.captured().len(), 1);
}

#[test]
fn gzip_negotiation_yields_gzip_content_encoding() {
    let upstream = MockUpstream::start(large_compressible_payload()).expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url(), "[gzip]", 0))
        .expect("start proxy");

    let resp = proxy
        .get_with_headers("/x", "comp.localhost", &[("accept-encoding", "gzip")])
        .expect("send");

    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.headers.get("content-encoding").map(String::as_str),
        Some("gzip"),
        "gzip should be selected when client accepts it"
    );

    // Body should round-trip through the gzip decoder.
    let mut decoder = flate2::read::GzDecoder::new(&resp.body[..]);
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded).expect("gzip decode");
    let parsed: serde_json::Value = serde_json::from_slice(&decoded).expect("decoded body is JSON");
    assert!(parsed.get("data").is_some());
}

#[test]
fn brotli_negotiation_yields_br_content_encoding() {
    let upstream = MockUpstream::start(large_compressible_payload()).expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url(), "[br]", 0))
        .expect("start proxy");

    let resp = proxy
        .get_with_headers("/x", "comp.localhost", &[("accept-encoding", "br")])
        .expect("send");

    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.headers.get("content-encoding").map(String::as_str),
        Some("br"),
        "brotli should be selected when client accepts it"
    );

    let mut decoder = brotli::Decompressor::new(&resp.body[..], 4096);
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded).expect("brotli decode");
    let parsed: serde_json::Value = serde_json::from_slice(&decoded).expect("decoded body is JSON");
    assert!(parsed.get("data").is_some());
}

#[test]
fn zstd_negotiation_yields_zstd_content_encoding() {
    let upstream = MockUpstream::start(large_compressible_payload()).expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url(), "[zstd]", 0))
        .expect("start proxy");

    let resp = proxy
        .get_with_headers("/x", "comp.localhost", &[("accept-encoding", "zstd")])
        .expect("send");

    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.headers.get("content-encoding").map(String::as_str),
        Some("zstd"),
        "zstd should be selected when client accepts it"
    );

    let decoded = zstd::decode_all(&resp.body[..]).expect("zstd decode");
    let parsed: serde_json::Value = serde_json::from_slice(&decoded).expect("decoded body is JSON");
    assert!(parsed.get("data").is_some());
}

#[test]
fn payload_under_min_size_is_not_compressed() {
    // Tiny upstream JSON well below the 100 000 byte floor.
    let upstream = MockUpstream::start(json!({"data": "ok"})).expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&config_yaml(
        &upstream.base_url(),
        "[gzip, br, zstd]",
        100_000,
    ))
    .expect("start proxy");

    let resp = proxy
        .get_with_headers(
            "/x",
            "comp.localhost",
            &[("accept-encoding", "gzip, br, zstd")],
        )
        .expect("send");

    assert_eq!(resp.status, 200);
    assert!(
        !resp.headers.contains_key("content-encoding"),
        "small bodies must skip the encoder, got headers: {:?}",
        resp.headers
    );
}

#[test]
#[ignore = "MockUpstream hardcodes Content-Type: application/json; binary content-type test \
    needs a custom upstream that emits image/png. Track in the e2e harness backlog."]
fn binary_content_type_is_not_compressed() {
    // The harness's mock upstream always replies with
    // `Content-Type: application/json`, which is on the compress list.
    // A real test of the skip list needs an upstream that returns
    // image/png, video/*, or application/zip. Until the harness grows
    // a content-type override, the unit tests in
    // `compression::tests::test_should_skip_compressed_content_types`
    // cover the skip list logic.
}
