//! End-to-end coverage for the `csrf` policy.
//!
//! Exercises the documented behaviour from `examples/32-csrf/sb.yml`:
//!
//! 1. A safe-method request (GET) issues a `csrf_token` cookie via
//!    `Set-Cookie`.
//! 2. A protected-method request (POST) without the matching token
//!    is rejected with 403.
//! 3. A protected-method request that echoes the cookie value in
//!    `X-CSRF-Token` is accepted.
//! 4. A protected-method request whose header token disagrees with
//!    the cookie value is rejected with 403.
//! 5. Paths listed in `exempt_paths` bypass the check entirely.
//!
//! Why a real proxy upstream rather than `static`: the CSRF cookie
//! is appended in `response_filter`, which only runs on the proxy
//! flow. Static actions short-circuit before that phase. We use
//! `MockUpstream` for the safe-method path that needs the cookie,
//! and rely on the proxy's deny-path which short-circuits cleanly
//! for the rejection assertions.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn config(upstream_base: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "csrf.localhost":
    action:
      type: proxy
      url: "{base}"
    policies:
      - type: csrf
        secret_key: "dev-csrf-secret-change-me"
        cookie_name: csrf_token
        header_name: X-CSRF-Token
        methods: [POST, PUT, DELETE, PATCH]
        safe_methods: [GET, HEAD, OPTIONS]
        cookie_path: /
        cookie_same_site: Lax
        exempt_paths:
          - /webhooks/
"#,
        base = upstream_base,
    )
}

/// Pull the `csrf_token` value out of a `set-cookie` header.
fn extract_csrf_token(set_cookie: &str) -> Option<String> {
    set_cookie
        .split(';')
        .next()
        .and_then(|c| c.split_once('='))
        .map(|(_, v)| v.trim().to_string())
}

#[test]
fn safe_get_issues_csrf_cookie() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config(&upstream.base_url())).expect("start proxy");

    let resp = harness.get("/", "csrf.localhost").expect("GET /");
    assert_eq!(resp.status, 200);
    let cookie = resp
        .headers
        .get("set-cookie")
        .expect("safe GET must issue a Set-Cookie");
    assert!(
        cookie.contains("csrf_token="),
        "Set-Cookie must carry csrf_token; got: {cookie}"
    );
    assert!(
        cookie.contains("Path=/"),
        "Cookie must include configured path; got: {cookie}"
    );
    assert!(
        cookie.contains("SameSite=Lax"),
        "Cookie must include configured SameSite; got: {cookie}"
    );
}

#[test]
fn post_without_token_is_rejected_with_403() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config(&upstream.base_url())).expect("start proxy");
    let client = reqwest::blocking::Client::new();

    let resp = client
        .post(format!("{}/submit", harness.base_url()))
        .header("host", "csrf.localhost")
        .body("payload=1")
        .send()
        .expect("POST without token");
    assert_eq!(
        resp.status().as_u16(),
        403,
        "POST without CSRF token must be rejected with 403"
    );
}

#[test]
fn post_with_valid_token_is_accepted() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config(&upstream.base_url())).expect("start proxy");
    let client = reqwest::blocking::Client::new();

    // 1. Issue the token via a safe GET.
    let issue = harness.get("/", "csrf.localhost").expect("GET /");
    assert_eq!(issue.status, 200);
    let cookie = issue
        .headers
        .get("set-cookie")
        .expect("Set-Cookie expected");
    let token = extract_csrf_token(cookie).expect("csrf_token in cookie");
    assert!(!token.is_empty(), "token must not be empty");

    // 2. Echo the token in both the cookie and the header on a POST.
    let resp = client
        .post(format!("{}/submit", harness.base_url()))
        .header("host", "csrf.localhost")
        .header("cookie", format!("csrf_token={token}"))
        .header("x-csrf-token", &token)
        .body("payload=1")
        .send()
        .expect("POST with valid token");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "POST with matching cookie and header must succeed"
    );
}

#[test]
fn post_with_mismatched_token_is_rejected_with_403() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config(&upstream.base_url())).expect("start proxy");
    let client = reqwest::blocking::Client::new();

    // Issue a token to obtain a real cookie value.
    let issue = harness.get("/", "csrf.localhost").expect("GET /");
    let cookie = issue
        .headers
        .get("set-cookie")
        .expect("Set-Cookie expected");
    let real = extract_csrf_token(cookie).expect("csrf_token in cookie");

    // Submit with a header value that does NOT match the cookie value.
    let resp = client
        .post(format!("{}/submit", harness.base_url()))
        .header("host", "csrf.localhost")
        .header("cookie", format!("csrf_token={real}"))
        .header("x-csrf-token", "wrong-value-attacker-supplied")
        .body("payload=1")
        .send()
        .expect("POST with mismatched token");
    assert_eq!(
        resp.status().as_u16(),
        403,
        "POST with mismatched CSRF token must be rejected"
    );
}

#[test]
fn exempt_path_bypasses_csrf_check() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config(&upstream.base_url())).expect("start proxy");
    let client = reqwest::blocking::Client::new();

    // POST to an exempt path with no token at all.
    let resp = client
        .post(format!("{}/webhooks/stripe", harness.base_url()))
        .header("host", "csrf.localhost")
        .body("event=ok")
        .send()
        .expect("POST exempt path");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "POST to exempt_paths prefix must skip the CSRF check"
    );
}
