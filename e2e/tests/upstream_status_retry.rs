//! End-to-end coverage for action-level retries triggered by upstream
//! response status codes.
//!
//! Status retries are decided before downstream response headers are
//! written. Bodyless safe/idempotent methods may be replayed; unsafe
//! methods surface `x-sbproxy-retry-skip-reason` and pass the upstream
//! response through unchanged.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn proxy_retry_config(upstream_url: &str, host: &str, retry_on: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "{host}":
    action:
      type: proxy
      url: {upstream_url}
      retry:
        max_attempts: 2
        retry_on: [{retry_on}]
        backoff_ms: 0
"#
    )
}

#[test]
fn proxy_retries_configured_status_and_returns_later_success() {
    let upstream = MockUpstream::start_sequence(vec![
        (502, json!({"attempt": 1})),
        (200, json!({"attempt": 2})),
    ])
    .expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&proxy_retry_config(
        &upstream.base_url(),
        "retry.localhost",
        "502",
    ))
    .expect("proxy");

    let resp = proxy.get("/", "retry.localhost").expect("GET");

    assert_eq!(resp.status, 200);
    assert_eq!(resp.json().expect("json")["attempt"], 2);
    assert_eq!(
        upstream.captured().len(),
        2,
        "502 must be retried once before returning the later 200"
    );
}

#[test]
fn proxy_passes_through_status_not_listed_in_retry_on() {
    let upstream = MockUpstream::start_sequence(vec![
        (501, json!({"attempt": 1})),
        (200, json!({"attempt": 2})),
    ])
    .expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&proxy_retry_config(
        &upstream.base_url(),
        "pass.localhost",
        "502",
    ))
    .expect("proxy");

    let resp = proxy.get("/", "pass.localhost").expect("GET");

    assert_eq!(resp.status, 501);
    assert_eq!(resp.json().expect("json")["attempt"], 1);
    assert_eq!(
        upstream.captured().len(),
        1,
        "non-retry status must not consume another upstream attempt"
    );
}

#[test]
fn proxy_skips_status_retry_for_non_idempotent_method() {
    let upstream = MockUpstream::start_sequence(vec![
        (502, json!({"attempt": 1})),
        (200, json!({"attempt": 2})),
    ])
    .expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&proxy_retry_config(
        &upstream.base_url(),
        "post.localhost",
        "502",
    ))
    .expect("proxy");

    let resp = proxy
        .post_json("/orders", "post.localhost", &json!({"sku": "abc"}), &[])
        .expect("POST");

    assert_eq!(resp.status, 502);
    assert_eq!(
        resp.headers
            .get("x-sbproxy-retry-skip-reason")
            .map(String::as_str),
        Some("non_idempotent_method")
    );
    assert_eq!(
        upstream.captured().len(),
        1,
        "POST must not be replayed after a response status"
    );
}

#[test]
fn load_balancer_retries_configured_status_on_next_target() {
    let failing = MockUpstream::start_with_status(json!({"target": "failing"}), 502)
        .expect("failing upstream");
    let healthy = MockUpstream::start(json!({"target": "healthy"})).expect("healthy upstream");

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "lb-retry.localhost":
    action:
      type: load_balancer
      algorithm: round_robin
      targets:
        - url: "{}"
          weight: 1
        - url: "{}"
          weight: 1
      retry:
        max_attempts: 2
        retry_on: [502]
        backoff_ms: 0
"#,
        failing.base_url(),
        healthy.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("proxy");

    let resp = proxy.get("/", "lb-retry.localhost").expect("GET");

    assert_eq!(resp.status, 200);
    assert_eq!(resp.json().expect("json")["target"], "healthy");
    assert_eq!(failing.captured().len(), 1);
    assert_eq!(healthy.captured().len(), 1);
}
