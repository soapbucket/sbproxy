//! RFC 9457 `problem_details` covers policy denials, not only auth ones.
//!
//! The renderer used to be reachable from three places: the two
//! authentication-denial arms and the upstream `fail_to_proxy` path. A
//! policy denial (`ip_filter`, `waf`, rate limiting, ...) fell through
//! to a hard-coded `{"error": msg}` in `application/json`, so an origin
//! that turned `problem_details` on got a different body shape
//! depending on which subsystem refused the request, and
//! `include_detail: false` suppressed nothing on the policy path.
//!
//! Tests run from 127.0.0.1, so `proxy.trusted_proxies` plus
//! `X-Forwarded-For` supplies the client IP the `ip_filter` policy
//! evaluates, the same way `policy_ip_filter.rs` does it.

use sbproxy_e2e::ProxyHarness;

/// `include_detail: false` is the setting an operator picks to keep
/// internal error text off the wire, so the assertions below check both
/// the media type and the absence of `detail`.
const RENDERED_CONFIG: &str = r#"
proxy:
  http_bind_port: 0
  trusted_proxies:
    - 127.0.0.1/32
origins:
  "pdpolicy.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    problem_details:
      enabled: true
      type_base_uri: "https://api.example.com/errors"
      include_detail: false
    policies:
      - type: ip_filter
        blacklist:
          - 203.0.113.0/24
"#;

/// The same origin with an authored 403 page. `error_pages` has always
/// promised to cover proxy-generated errors generically; this pins that
/// an authored page still outranks the renderer on the policy path.
const AUTHORED_PAGE_CONFIG: &str = r#"
proxy:
  http_bind_port: 0
  trusted_proxies:
    - 127.0.0.1/32
origins:
  "pdpolicy.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    error_pages:
      - status: 403
        content_type: text/html
        body: "<h1>blocked</h1>"
    problem_details:
      enabled: true
      type_base_uri: "https://api.example.com/errors"
      include_detail: false
    policies:
      - type: ip_filter
        blacklist:
          - 203.0.113.0/24
"#;

fn content_type(resp: &sbproxy_e2e::Response) -> String {
    resp.headers
        .get("content-type")
        .cloned()
        .unwrap_or_default()
}

#[test]
fn ip_filter_denial_renders_as_problem_json() {
    let harness = ProxyHarness::start_with_yaml(RENDERED_CONFIG).expect("start proxy");

    let resp = harness
        .get_with_headers(
            "/anything",
            "pdpolicy.localhost",
            &[("x-forwarded-for", "203.0.113.7")],
        )
        .expect("send");

    assert_eq!(resp.status, 403, "the blacklisted client must be denied");
    assert!(
        content_type(&resp).starts_with("application/problem+json"),
        "a policy denial on a problem_details origin must render as problem+json; got {:?} body {:?}",
        content_type(&resp),
        resp.text().unwrap_or_default()
    );

    let body = resp.json().expect("problem+json body must parse");
    assert_eq!(body["type"], "https://api.example.com/errors/403");
    assert_eq!(body["status"], 403);
    assert!(
        body.get("detail").is_none(),
        "include_detail: false must suppress the policy's own message; got {body}"
    );
}

#[test]
fn an_allowed_request_is_untouched() {
    // The renderer must only fire on the refusal. Without this the test
    // above would pass against a build that broke the allow path.
    let harness = ProxyHarness::start_with_yaml(RENDERED_CONFIG).expect("start proxy");

    let resp = harness
        .get_with_headers(
            "/anything",
            "pdpolicy.localhost",
            &[("x-forwarded-for", "198.51.100.4")],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.text().expect("utf8 body"), "ok");
}

#[test]
fn an_authored_error_page_still_outranks_the_renderer() {
    let harness = ProxyHarness::start_with_yaml(AUTHORED_PAGE_CONFIG).expect("start proxy");

    let resp = harness
        .get_with_headers(
            "/anything",
            "pdpolicy.localhost",
            &[("x-forwarded-for", "203.0.113.7")],
        )
        .expect("send");

    assert_eq!(resp.status, 403);
    assert!(
        content_type(&resp).starts_with("text/html"),
        "an authored page for the status must win over the renderer; got {:?}",
        content_type(&resp)
    );
    assert_eq!(resp.text().expect("utf8 body"), "<h1>blocked</h1>");
}
