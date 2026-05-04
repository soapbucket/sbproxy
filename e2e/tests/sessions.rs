//! End-to-end coverage for session cookies.
//!
//! `examples/65-sessions/sb.yml` documents the contract: when an
//! origin has a `session:` block, the proxy emits a `Set-Cookie`
//! header on every response that doesn't already carry the session
//! cookie. Cookie attributes (`HttpOnly`, `Secure`, `SameSite`,
//! `Max-Age`, `Path`) follow the configured `SessionConfig` shape.
//! Subsequent requests that present the cookie do not get a fresh
//! `Set-Cookie`.
//!
//! The session-cookie injection path lives in the proxied response
//! filter (`upstream_response.append_header`), so the tests here
//! drive a proxy action against a [`MockUpstream`]; the static
//! action follows a different early-return path that bypasses the
//! filter chain.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

#[test]
fn first_request_issues_session_cookie_with_documented_attributes() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "sess.localhost":
    session:
      cookie_name: sb_session
      max_age: 3600
      http_only: true
      secure: false
      same_site: Lax
      allow_non_ssl: true
    action:
      type: proxy
      url: "{}"
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let resp = proxy.get("/", "sess.localhost").expect("first GET");
    assert_eq!(resp.status, 200);

    let cookie = resp
        .headers
        .get("set-cookie")
        .map(|s| s.as_str())
        .expect("response must carry Set-Cookie header");

    assert!(
        cookie.starts_with("sb_session="),
        "cookie name must match config, got: {cookie}"
    );
    assert!(
        cookie.contains("Path=/"),
        "missing Path=/ attribute: {cookie}"
    );
    assert!(
        cookie.contains("Max-Age=3600"),
        "missing Max-Age attribute: {cookie}"
    );
    assert!(
        cookie.contains("SameSite=Lax"),
        "missing SameSite=Lax attribute: {cookie}"
    );
    assert!(
        cookie.contains("HttpOnly"),
        "http_only=true must emit HttpOnly attribute: {cookie}"
    );
    // secure=false and allow_non_ssl=true: Secure must NOT appear.
    assert!(
        !cookie.contains("Secure"),
        "secure=false config must not emit Secure attribute: {cookie}"
    );
}

#[test]
fn secure_attribute_emits_when_secure_true() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "sec.localhost":
    session:
      cookie_name: sb_session
      max_age: 600
      http_only: true
      secure: true
      same_site: Strict
    action:
      type: proxy
      url: "{}"
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let resp = proxy.get("/", "sec.localhost").expect("GET");
    let cookie = resp
        .headers
        .get("set-cookie")
        .map(|s| s.as_str())
        .expect("Set-Cookie required");
    assert!(
        cookie.contains("Secure"),
        "secure=true must emit Secure: {cookie}"
    );
    assert!(
        cookie.contains("SameSite=Strict"),
        "same_site=Strict must round-trip: {cookie}"
    );
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("Max-Age=600"));
}

#[test]
fn presented_cookie_is_not_overwritten() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "reuse.localhost":
    session:
      cookie_name: sb_session
      max_age: 3600
      http_only: true
      same_site: Lax
      allow_non_ssl: true
    action:
      type: proxy
      url: "{}"
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    // Request with the cookie already set: the response should not
    // re-issue Set-Cookie because the client is presenting one.
    let resp = proxy
        .get_with_headers(
            "/",
            "reuse.localhost",
            &[("cookie", "sb_session=abc-123-existing")],
        )
        .expect("GET with cookie");
    assert_eq!(resp.status, 200);
    assert!(
        !resp.headers.contains_key("set-cookie"),
        "client-supplied cookie must not be overwritten, got: {:?}",
        resp.headers.get("set-cookie")
    );
}
