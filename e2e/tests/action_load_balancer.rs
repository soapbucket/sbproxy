//! End-to-end coverage for the `load_balancer` action.
//!
//! Spawns multiple [`MockUpstream`] instances and points the proxy
//! at them with different algorithms documented in
//! `examples/04-load-balancer/sb.yml` and
//! `examples/71-load-balancer-deployment/sb.yml`. The mock upstreams
//! capture every accepted request so the test can count the
//! distribution after the run.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

// --- round_robin ---

#[test]
fn round_robin_distributes_across_three_upstreams() {
    let a = MockUpstream::start(json!({"target": "a"})).expect("upstream a");
    let b = MockUpstream::start(json!({"target": "b"})).expect("upstream b");
    let c = MockUpstream::start(json!({"target": "c"})).expect("upstream c");

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "lb.localhost":
    action:
      type: load_balancer
      algorithm: round_robin
      targets:
        - url: "{}"
          weight: 1
        - url: "{}"
          weight: 1
        - url: "{}"
          weight: 1
"#,
        a.base_url(),
        b.base_url(),
        c.base_url()
    );

    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    // Hit the proxy nine times; round-robin must touch each upstream.
    for _ in 0..9 {
        let resp = proxy.get("/get", "lb.localhost").expect("send");
        assert_eq!(resp.status, 200, "round-robin should always succeed");
    }

    let count_a = a.captured().len();
    let count_b = b.captured().len();
    let count_c = c.captured().len();

    assert!(
        count_a > 0 && count_b > 0 && count_c > 0,
        "round_robin should reach every upstream: a={count_a} b={count_b} c={count_c}"
    );
    assert_eq!(
        count_a + count_b + count_c,
        9,
        "every request must land on one upstream"
    );
}

// --- weighted_random ---

#[test]
fn weighted_random_respects_weight_ratio() {
    // Weight ratio 1:3, so the heavier upstream should receive
    // roughly 75% of traffic over a sample of 100 requests. We use
    // a wide tolerance window so scheduler jitter does not flake the
    // test, but the imbalance must be visible.
    let light = MockUpstream::start(json!({"target": "light"})).expect("light upstream");
    let heavy = MockUpstream::start(json!({"target": "heavy"})).expect("heavy upstream");

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "wr.localhost":
    action:
      type: load_balancer
      algorithm: weighted_random
      targets:
        - url: "{}"
          weight: 1
        - url: "{}"
          weight: 3
"#,
        light.base_url(),
        heavy.base_url()
    );

    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    for _ in 0..100 {
        let resp = proxy.get("/", "wr.localhost").expect("send");
        assert_eq!(resp.status, 200);
    }

    let light_n = light.captured().len();
    let heavy_n = heavy.captured().len();
    assert_eq!(light_n + heavy_n, 100, "every request must land somewhere");
    assert!(
        heavy_n > light_n,
        "heavier-weighted target should receive more traffic, got light={light_n} heavy={heavy_n}"
    );
    // Heavy should be at least double light. With weight ratio 3:1
    // the expected ratio is 3:1, so 2:1 is a safe lower bound for
    // 100 samples.
    assert!(
        heavy_n >= 2 * light_n,
        "heavy/light ratio should reflect the configured weights, got light={light_n} heavy={heavy_n}"
    );
}

// --- ip_hash ---

#[test]
fn ip_hash_is_consistent_for_same_client() {
    // Same client (the harness loops through 127.0.0.1) must always
    // hit the same upstream. The other upstreams must stay empty.
    let a = MockUpstream::start(json!({"target": "a"})).expect("upstream a");
    let b = MockUpstream::start(json!({"target": "b"})).expect("upstream b");
    let c = MockUpstream::start(json!({"target": "c"})).expect("upstream c");

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "iph.localhost":
    action:
      type: load_balancer
      algorithm: ip_hash
      targets:
        - url: "{}"
          weight: 1
        - url: "{}"
          weight: 1
        - url: "{}"
          weight: 1
"#,
        a.base_url(),
        b.base_url(),
        c.base_url()
    );

    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    for _ in 0..15 {
        let resp = proxy.get("/", "iph.localhost").expect("send");
        assert_eq!(resp.status, 200);
    }

    let counts = [a.captured().len(), b.captured().len(), c.captured().len()];
    let total: usize = counts.iter().sum();
    assert_eq!(total, 15, "every request must land on exactly one upstream");

    let nonempty = counts.iter().filter(|n| **n > 0).count();
    assert_eq!(
        nonempty, 1,
        "ip_hash must pin the same client to a single upstream, got {counts:?}"
    );
}
