//! API key authentication.
//!
//! Exercises the `api_key` auth provider in both header and
//! query-parameter modes. Mirrors the contract documented in
//! `examples/06-auth-api-key/sb.yml`: a missing or wrong key gets a
//! 401 before the upstream is contacted; a valid key in the configured
//! header (or the configured query parameter) is forwarded as a 200.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn config_yaml(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "api.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    authentication:
      type: api_key
      header_name: X-Api-Key
      api_keys:
        - dev-key-1
        - dev-key-2
      query_param: api_key
"#
    )
}

#[test]
fn valid_key_in_header_returns_200() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers("/anything", "api.localhost", &[("X-Api-Key", "dev-key-1")])
        .expect("send");
    assert_eq!(resp.status, 200, "valid header key should authorize");
    assert!(
        !upstream.captured().is_empty(),
        "upstream should have received the request"
    );
}

#[test]
fn valid_key_in_query_param_returns_200() {
    // The query_param fallback is only consulted when the configured
    // header is absent or wrong. We send the key in the URL only.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness
        .get("/anything?api_key=dev-key-2", "api.localhost")
        .expect("send");
    assert_eq!(resp.status, 200, "valid query-param key should authorize");
}

#[test]
fn missing_credential_returns_401() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness.get("/anything", "api.localhost").expect("send");
    assert_eq!(
        resp.status, 401,
        "no credential should yield 401 before reaching upstream"
    );
    assert!(
        upstream.captured().is_empty(),
        "upstream must not see unauthenticated requests"
    );
}

#[test]
fn malformed_key_in_header_returns_401() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/anything",
            "api.localhost",
            &[("X-Api-Key", "not-a-real-key")],
        )
        .expect("send");
    assert_eq!(resp.status, 401, "wrong header key should yield 401");
    assert!(upstream.captured().is_empty());
}

#[test]
fn malformed_key_in_query_param_returns_401() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness
        .get("/anything?api_key=wrong-value", "api.localhost")
        .expect("send");
    assert_eq!(resp.status, 401, "wrong query-param key should yield 401");
    assert!(upstream.captured().is_empty());
}
