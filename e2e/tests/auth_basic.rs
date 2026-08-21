//! HTTP Basic authentication.
//!
//! The `basic_auth` provider validates the standard
//! `Authorization: Basic <b64(user:pass)>` header against the configured
//! `users` list. The realm is surfaced to the client as part of the 401
//! challenge; the rest of the file covers the accept / reject decision
//! and confirms the upstream is bypassed for unauthenticated traffic.
//! Mirrors the contract from `examples/auth-basic/sb.yml`.

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
fn missing_credential_challenges_with_the_configured_realm() {
    // RFC 9110 section 11.6.1: the 401 has to name the scheme and realm
    // or the client has nothing to retry with and a browser never
    // prompts. `realm: "sbproxy demo"` in the config above is the value
    // that must appear here.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness.get("/get", "basic.localhost").expect("send");
    assert_eq!(resp.status, 401);
    assert_eq!(
        resp.headers.get("www-authenticate").map(String::as_str),
        Some(r#"Basic realm="sbproxy demo""#),
        "the configured realm must reach the wire; headers were {:?}",
        resp.headers
    );
}

#[test]
fn wrong_password_also_challenges() {
    // A rejected credential is the case where the client most needs the
    // scheme and realm back, so the challenge cannot be limited to the
    // no-credential branch.
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
    assert_eq!(
        resp.headers.get("www-authenticate").map(String::as_str),
        Some(r#"Basic realm="sbproxy demo""#)
    );
}

#[test]
fn an_authored_401_page_keeps_the_challenge_header() {
    // The challenge and the body are independent choices. Routing the
    // header-carrying denial through the body chooser is what makes an
    // origin able to author its own 401 page without losing
    // `WWW-Authenticate`.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let config = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "basic.localhost":
    action:
      type: proxy
      url: "{}"
    error_pages:
      - status: 401
        content_type: text/html
        body: "<h1>sign in</h1>"
    authentication:
      type: basic_auth
      realm: "sbproxy demo"
      users:
        - username: admin
          password: s3cret
"#,
        upstream.base_url()
    );
    let harness = ProxyHarness::start_with_yaml(&config).expect("start");

    let resp = harness.get("/get", "basic.localhost").expect("send");
    assert_eq!(resp.status, 401);
    assert_eq!(
        resp.headers.get("www-authenticate").map(String::as_str),
        Some(r#"Basic realm="sbproxy demo""#),
        "an authored error page must not cost the origin its challenge"
    );
    assert_eq!(resp.text().expect("utf8 body"), "<h1>sign in</h1>");
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
