//! HTTP Basic authentication.
//!
//! The `basic_auth` provider validates the standard
//! `Authorization: Basic <b64(user:pass)>` header against the configured
//! `users` list. The realm is surfaced to the client only as part of the
//! 401 challenge; here we focus on the accept / reject decision and
//! confirm the upstream is bypassed for unauthenticated traffic. Mirrors
//! the contract from `examples/22-auth-basic/sb.yml`.

use base64::Engine;
use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn basic_auth(user: &str, password: &str) -> String {
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
    format!("Basic {token}")
}

fn config_yaml(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "basic.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    authentication:
      type: basic_auth
      realm: "sbproxy demo"
      users:
        - username: admin
          password: s3cret
        - username: readonly
          password: viewonly
"#
    )
}

#[test]
fn valid_credentials_return_200() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/get",
            "basic.localhost",
            &[("authorization", &basic_auth("admin", "s3cret"))],
        )
        .expect("send");
    assert_eq!(resp.status, 200, "valid credentials should authorize");
    assert!(!upstream.captured().is_empty());
}

#[test]
fn second_configured_user_also_works() {
    // Ensures the provider scans every configured user; not just the
    // first one. Same contract as the in-tree unit test
    // `basic_auth_second_user`.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/get",
            "basic.localhost",
            &[("authorization", &basic_auth("readonly", "viewonly"))],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
}

#[test]
fn missing_credential_returns_401() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness.get("/get", "basic.localhost").expect("send");
    assert_eq!(resp.status, 401);
    assert!(upstream.captured().is_empty());
}

#[test]
fn wrong_password_returns_401() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/get",
            "basic.localhost",
            &[("authorization", &basic_auth("admin", "not-the-password"))],
        )
        .expect("send");
    assert_eq!(resp.status, 401);
    assert!(upstream.captured().is_empty());
}

#[test]
fn unknown_user_returns_401() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/get",
            "basic.localhost",
            &[("authorization", &basic_auth("ghost", "s3cret"))],
        )
        .expect("send");
    assert_eq!(resp.status, 401);
}

#[test]
fn malformed_header_returns_401() {
    // Wrong scheme + invalid base64 + missing colon all collapse into the
    // same fail-closed branch in the provider; we exercise one of them.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/get",
            "basic.localhost",
            &[("authorization", "Basic !!!not-base64!!!")],
        )
        .expect("send");
    assert_eq!(resp.status, 401, "garbage credential should yield 401");
    assert!(upstream.captured().is_empty());
}
