//! End-to-end coverage for first-class API deprecation (WOR-2565).
//!
//! The `deprecation:` block must stamp RFC 9745 `Deprecation`,
//! RFC 8594 `Sunset`, and the Link relations on real proxied
//! responses (the unit suite covers the generated-response path), the
//! per-rule block must scope to the requests its rule matches, and
//! `after_sunset: gone` must refuse post-sunset requests with 410.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

#[test]
fn origin_block_stamps_headers_on_proxied_responses() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "dep.localhost":
    deprecation:
      deprecated: 2026-09-01
      sunset: 2026-12-31T23:59:59Z
      successor: https://api.example.com/v2/
    action:
      type: proxy
      url: "{}"
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let resp = proxy.get("/v1/jobs", "dep.localhost").expect("send");
    assert_eq!(resp.status, 200, "the upstream response is relayed");
    assert_eq!(
        resp.headers.get("deprecation").map(String::as_str),
        Some("@1788220800"),
        "headers: {:?}",
        resp.headers
    );
    assert_eq!(
        resp.headers.get("sunset").map(String::as_str),
        Some("Thu, 31 Dec 2026 23:59:59 GMT"),
        "headers: {:?}",
        resp.headers
    );
    assert_eq!(
        resp.headers.get("link").map(String::as_str),
        Some("<https://api.example.com/v2/>; rel=\"successor-version\""),
        "headers: {:?}",
        resp.headers
    );
}

#[test]
fn per_rule_block_scopes_to_matching_paths() {
    let v1 = MockUpstream::start(json!({"v": 1})).expect("v1 upstream");
    let v2 = MockUpstream::start(json!({"v": 2})).expect("v2 upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "dep-rules.localhost":
    action:
      type: static
      status_code: 404
      content_type: text/plain
      body: "no route"
    forward_rules:
      - rules:
          - path:
              prefix: /v1/
        deprecation:
          deprecated: 2026-09-01
          sunset: 2026-12-31
        origin:
          id: v1-legacy
          action:
            type: proxy
            url: "{}"
      - rules:
          - path:
              prefix: /v2/
        origin:
          id: v2
          action:
            type: proxy
            url: "{}"
"#,
        v1.base_url(),
        v2.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let v1_resp = proxy.get("/v1/jobs", "dep-rules.localhost").expect("v1");
    assert_eq!(v1_resp.status, 200);
    assert_eq!(
        v1_resp.headers.get("deprecation").map(String::as_str),
        Some("@1788220800"),
        "the /v1/ rule's block must reach the wire: {:?}",
        v1_resp.headers
    );
    assert_eq!(
        v1_resp.headers.get("sunset").map(String::as_str),
        Some("Thu, 31 Dec 2026 00:00:00 GMT"),
    );

    let v2_resp = proxy.get("/v2/jobs", "dep-rules.localhost").expect("v2");
    assert_eq!(v2_resp.status, 200);
    assert!(
        !v2_resp.headers.contains_key("deprecation") && !v2_resp.headers.contains_key("sunset"),
        "the /v2/ rule on the same origin must stay unmarked: {:?}",
        v2_resp.headers
    );
}

#[test]
fn after_sunset_gone_refuses_with_410_naming_the_successor() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "dep-gone.localhost":
    deprecation:
      deprecated: 2020-01-01
      sunset: 2020-06-01
      after_sunset: gone
      successor: https://api.example.com/v2/
    action:
      type: proxy
      url: "{}"
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let resp = proxy.get("/v1/jobs", "dep-gone.localhost").expect("send");
    assert_eq!(resp.status, 410, "past sunset, `gone` refuses");
    assert_eq!(
        resp.headers.get("sunset").map(String::as_str),
        Some("Mon, 01 Jun 2020 00:00:00 GMT"),
        "the refusal still announces: {:?}",
        resp.headers
    );
    let body = resp.json().expect("410 body is JSON");
    assert_eq!(body["error"], "gone");
    assert_eq!(body["successor"], "https://api.example.com/v2/");
    assert!(
        upstream.captured().is_empty(),
        "a refused request must never reach the upstream"
    );
}
