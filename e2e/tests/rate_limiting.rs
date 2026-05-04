//! End-to-end coverage for the rate_limiting policy.
//!
//! Exercises the documented behaviour from
//! `examples/02-rate-limiting/sb.yml`: a token bucket on the
//! request path returns 429 with a `Retry-After` header once the
//! burst is exhausted.

use sbproxy_e2e::ProxyHarness;

const CONFIG: &str = r#"
proxy:
  http_bind_port: 0  # overridden by the harness
origins:
  "rl.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: rate_limiting
        requests_per_second: 5
        burst: 5
        key: ip
        headers:
          enabled: true
          include_retry_after: true
"#;

#[test]
fn burst_eventually_returns_429() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");

    // Slam 50 requests; with burst=5 and rps=5 we expect a clear
    // mix of 200s and 429s. We only assert that *both* show up so
    // the test stays robust against scheduler jitter.
    let mut saw_200 = false;
    let mut saw_429 = false;
    for _ in 0..50 {
        let resp = harness.get("/anything", "rl.localhost").expect("send");
        match resp.status {
            200 => saw_200 = true,
            429 => saw_429 = true,
            other => panic!("unexpected status {}: {:?}", other, resp.text()),
        }
    }
    assert!(saw_200, "expected at least one 200 within the burst");
    assert!(saw_429, "expected at least one 429 once the bucket emptied");
}

#[test]
fn rate_limited_response_carries_retry_after() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");

    // Drain the bucket then assert the next 429 carries Retry-After.
    let mut saw_429_with_retry_after = false;
    for _ in 0..50 {
        let resp = harness.get("/anything", "rl.localhost").expect("send");
        if resp.status == 429 && resp.headers.contains_key("retry-after") {
            saw_429_with_retry_after = true;
            break;
        }
    }
    assert!(
        saw_429_with_retry_after,
        "rate-limited response should include Retry-After"
    );
}
