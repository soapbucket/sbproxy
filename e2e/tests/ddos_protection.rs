//! End-to-end coverage for the ddos_protection policy.
//!
//! Exercises the documented behaviour: per-IP request rate above the
//! threshold trips a temporary block. Subsequent requests from the
//! blocked IP return 429 with a `Retry-After` header until the block
//! window expires.

use sbproxy_e2e::ProxyHarness;

const CONFIG: &str = r#"
proxy:
  http_bind_port: 0  # overridden by the harness
origins:
  "ddos.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: ddos_protection
        detection:
          request_rate_threshold: 5
          detection_window: 5s
        mitigation:
          block_duration: 1s
          auto_block: true
"#;

#[test]
fn flood_trips_ddos_block_and_returns_429() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");

    // First five requests fit inside the 1-second window threshold.
    for i in 0..5 {
        let resp = harness.get("/anything", "ddos.localhost").expect("send");
        assert_eq!(
            resp.status, 200,
            "request {i} under threshold should pass, got {}",
            resp.status
        );
    }

    // The next request crosses the threshold and trips a block.
    let resp = harness.get("/anything", "ddos.localhost").expect("send");
    assert_eq!(
        resp.status, 429,
        "threshold-crossing request should return 429, got {}",
        resp.status
    );
}

#[test]
fn blocked_response_carries_retry_after() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");

    // Burst past the threshold; one of the 429s must carry Retry-After.
    let mut saw_429_with_retry_after = false;
    for _ in 0..15 {
        let resp = harness.get("/anything", "ddos.localhost").expect("send");
        if resp.status == 429 && resp.headers.contains_key("retry-after") {
            saw_429_with_retry_after = true;
            break;
        }
    }
    assert!(
        saw_429_with_retry_after,
        "DDoS-blocked response should include Retry-After"
    );
}

#[test]
fn block_clears_after_block_duration() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");

    // Trip the block.
    let mut tripped = false;
    for _ in 0..10 {
        let resp = harness.get("/anything", "ddos.localhost").expect("send");
        if resp.status == 429 {
            tripped = true;
            break;
        }
    }
    assert!(tripped, "expected the burst to trip the DDoS block");

    // Wait out the 1-second block window plus a small grace.
    std::thread::sleep(std::time::Duration::from_millis(1500));

    // The next request should pass; the block cleared and the window reset.
    let resp = harness.get("/anything", "ddos.localhost").expect("send");
    assert_eq!(
        resp.status, 200,
        "expected the proxy to allow traffic again after block_duration; got {}",
        resp.status
    );
}
