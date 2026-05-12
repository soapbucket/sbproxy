//! End-to-end coverage for `proxy_status` + `problem_details` on the
//! upstream-failure path.
//!
//! Before this fix the proxy stamped the operator-configured
//! `Proxy-Status` header (RFC 9209) and rendered the
//! `application/problem+json` body (RFC 9457) only on
//! proxy-generated errors (auth deny, policy deny, default 404).
//! When an upstream failed (connect refused, timeout, ...) the
//! client received a bare 502 from Pingora's default
//! error-translation path, breaking dashboards that grep for
//! `Proxy-Status` to count upstream failures by mode.
//!
//! These tests use an unreachable upstream (no listener bound) to
//! trigger an upstream connect failure and verify that the
//! configured envelopes ride the response.

use sbproxy_e2e::ProxyHarness;
use std::net::TcpListener;

/// Find an ephemeral port that no one is listening on. We bind a
/// socket to claim the port, capture it, then drop the binding so
/// the proxy's upstream connect will fail with
/// `ConnectRefused`/`ConnectError` against a port that the OS marks
/// as free.
fn unbound_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind for port discovery");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

fn config_for(unreachable_port: u16) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "fail.localhost":
    action:
      type: proxy
      url: http://127.0.0.1:{unreachable_port}
    proxy_status:
      enabled: true
      identity: "sbproxy-test"
    problem_details:
      enabled: true
      type_base_uri: "https://api.example.com/errors"
      include_detail: true
"#
    )
}

#[test]
fn upstream_failure_stamps_proxy_status_header() {
    let port = unbound_port();
    let proxy = ProxyHarness::start_with_yaml(&config_for(port)).expect("start proxy");

    let resp = proxy.get("/whatever", "fail.localhost").expect("send");
    // Upstream is unreachable; the proxy should synthesise a 5xx
    // response. The exact status is 502 (connection_refused) or
    // 504 (timeout) depending on the OS RST timing, so we accept
    // either; both are valid mappings from `map_upstream_failure`.
    assert!(
        (500..600).contains(&resp.status),
        "expected a 5xx upstream-failure response, got {}",
        resp.status
    );

    let header = resp
        .headers
        .get("proxy-status")
        .expect("Proxy-Status header must be stamped when proxy_status.enabled");
    assert!(
        header.starts_with("sbproxy-test;"),
        "expected the configured identity to lead the Proxy-Status value, got: {header}"
    );
    assert!(
        header.contains("received-status="),
        "Proxy-Status value must carry received-status, got: {header}"
    );
    assert!(
        header.contains("error="),
        "upstream failure must surface an error token in Proxy-Status, got: {header}"
    );
}

#[test]
fn upstream_failure_renders_problem_details_body() {
    let port = unbound_port();
    let proxy = ProxyHarness::start_with_yaml(&config_for(port)).expect("start proxy");

    let resp = proxy.get("/v1/orders", "fail.localhost").expect("send");
    assert!(
        (500..600).contains(&resp.status),
        "expected a 5xx upstream-failure response, got {}",
        resp.status
    );
    assert_eq!(
        resp.headers.get("content-type").map(|s| s.as_str()),
        Some("application/problem+json"),
        "problem_details.enabled must override the default text/plain body"
    );
    let body: serde_json::Value = resp.json().expect("body parses as JSON");
    assert!(
        body["type"]
            .as_str()
            .unwrap_or_default()
            .starts_with("https://api.example.com/errors/"),
        "type must derive from type_base_uri + status, got: {}",
        body["type"]
    );
    assert_eq!(body["status"], resp.status);
    assert_eq!(body["instance"], "/v1/orders");
    // Detail field comes from the error token (connection_refused,
    // connection_timeout, ...) which is enabled by include_detail.
    let detail = body["detail"].as_str().unwrap_or_default();
    assert!(
        !detail.is_empty(),
        "detail must carry the upstream failure reason"
    );
}

#[test]
fn upstream_failure_without_config_keeps_default_response() {
    // Origin has no proxy_status / problem_details block. The
    // upstream-failure path must keep the prior behaviour
    // (text/plain 'bad gateway') so adding the wiring did not
    // change defaults.
    let port = unbound_port();
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "fail.localhost":
    action:
      type: proxy
      url: http://127.0.0.1:{port}
"#
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let resp = proxy.get("/whatever", "fail.localhost").expect("send");
    assert!((500..600).contains(&resp.status));
    assert!(
        !resp.headers.contains_key("proxy-status"),
        "Proxy-Status must NOT be stamped when the origin opts out"
    );
    // Default body is plain text. Operators who haven't opted in get
    // the prior behaviour, just with the status code mapped by
    // upstream failure type (502/504).
    let ct = resp
        .headers
        .get("content-type")
        .map(|s| s.as_str())
        .unwrap_or_default();
    assert!(
        ct.starts_with("text/plain"),
        "default content-type must be text/plain; got {ct}"
    );
}
