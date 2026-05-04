//! Bearer token authentication.
//!
//! Validates an opaque bearer token against an allowlist of configured
//! tokens. Matches the contract from `examples/21-auth-bearer/sb.yml`:
//! the token is read from `Authorization: Bearer <token>`; absent or
//! unknown tokens yield a 401 before the upstream is contacted.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn config_yaml(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "bearer.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    authentication:
      type: bearer
      tokens:
        - svc-token-alpha
        - svc-token-beta
"#
    )
}

#[test]
fn valid_token_returns_200() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/get",
            "bearer.localhost",
            &[("authorization", "Bearer svc-token-alpha")],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
    assert!(!upstream.captured().is_empty());
}

#[test]
fn second_allowlisted_token_also_works() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/get",
            "bearer.localhost",
            &[("authorization", "Bearer svc-token-beta")],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
}

#[test]
fn missing_credential_returns_401() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness.get("/get", "bearer.localhost").expect("send");
    assert_eq!(resp.status, 401);
    assert!(upstream.captured().is_empty());
}

#[test]
fn unknown_token_returns_401() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/get",
            "bearer.localhost",
            &[("authorization", "Bearer not-a-real-token")],
        )
        .expect("send");
    assert_eq!(resp.status, 401);
    assert!(upstream.captured().is_empty());
}

#[test]
fn wrong_scheme_returns_401() {
    // The provider only accepts the `Bearer` scheme. Sending a Basic
    // header should be treated as "no bearer credential" and return 401.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/get",
            "bearer.localhost",
            &[("authorization", "Basic c3ZjLXRva2VuLWFscGhh")],
        )
        .expect("send");
    assert_eq!(resp.status, 401, "Basic header is not a Bearer credential");
}
