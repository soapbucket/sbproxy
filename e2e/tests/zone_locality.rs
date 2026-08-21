//! End-to-end coverage for zone-aware target selection (WOR-2328).
//!
//! Spawns [`MockUpstream`] instances labeled as different zones and
//! asserts the three behaviors `examples/multi-zone/` documents:
//! same-zone preference while the local zone is healthy, per-request
//! spillover when it is not, and unchanged spread when the proxy has
//! no zone identity. The `SB_ZONE` fallback rides the child process
//! environment, never this test's.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn zoned_yaml(proxy_zone: Option<&str>, zone_a_url: &str, zone_b_url: &str) -> String {
    let zone_line = proxy_zone
        .map(|zone| format!("  zone: {zone}\n"))
        .unwrap_or_default();
    format!(
        r#"
proxy:
  http_bind_port: 0
{zone_line}origins:
  "lb.localhost":
    action:
      type: load_balancer
      algorithm: round_robin
      targets:
        - url: "{zone_a_url}"
          zone: zone-a
        - url: "{zone_b_url}"
          zone: zone-b
"#
    )
}

#[test]
fn same_zone_target_takes_every_request() {
    let local = MockUpstream::start(json!({"zone": "a"})).expect("zone-a upstream");
    let remote = MockUpstream::start(json!({"zone": "b"})).expect("zone-b upstream");

    let yaml = zoned_yaml(Some("zone-a"), &local.base_url(), &remote.base_url());
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    for _ in 0..8 {
        let resp = proxy.get("/get", "lb.localhost").expect("send");
        assert_eq!(resp.status, 200);
    }

    assert_eq!(
        local.captured().len(),
        8,
        "every request must land in the proxy's own zone"
    );
    assert!(
        remote.captured().is_empty(),
        "no request may cross zones while zone-a is healthy"
    );
}

#[test]
fn requests_spill_cross_zone_when_the_local_zone_is_down() {
    // The zone-a upstream answers 503 to everything, including its own
    // health probe, so it goes unhealthy after `unhealthy_threshold`
    // consecutive probe failures and every request spills to zone-b.
    let local = MockUpstream::start_with_status(json!({"zone": "a"}), 503).expect("503 upstream");
    let remote = MockUpstream::start(json!({"zone": "b"})).expect("zone-b upstream");

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
  zone: zone-a
origins:
  "lb.localhost":
    action:
      type: load_balancer
      algorithm: round_robin
      targets:
        - url: "{}"
          zone: zone-a
          health_check:
            path: /healthz
            interval_secs: 1
            timeout_ms: 500
            unhealthy_threshold: 1
            healthy_threshold: 2
        - url: "{}"
          zone: zone-b
"#,
        local.base_url(),
        remote.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    // Before the probe verdict lands, requests still prefer zone-a and
    // surface its 503; afterwards they must spill and succeed. Poll up
    // to well past the first probe interval for the flip.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let resp = proxy.get("/get", "lb.localhost").expect("send");
        if resp.status == 200 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "zone-a never went unhealthy; requests kept answering {}",
            resp.status
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    // Once spilled, traffic stays on zone-b: no blackholing and no
    // flapping back while zone-a stays down.
    let already_remote = remote.captured().len();
    for _ in 0..6 {
        let resp = proxy.get("/get", "lb.localhost").expect("send");
        assert_eq!(resp.status, 200, "spilled requests must succeed on zone-b");
    }
    assert_eq!(
        remote.captured().len(),
        already_remote + 6,
        "every post-spill request must land on the zone-b upstream"
    );
}

#[test]
fn sb_zone_env_supplies_the_zone_identity() {
    let east = MockUpstream::start(json!({"zone": "a"})).expect("zone-a upstream");
    let west = MockUpstream::start(json!({"zone": "b"})).expect("zone-b upstream");

    // No proxy.zone in the config; the child process env carries it.
    let yaml = zoned_yaml(None, &east.base_url(), &west.base_url());
    let proxy = ProxyHarness::start_with_yaml_and_env(&yaml, &[("SB_ZONE", "zone-b")])
        .expect("start proxy");

    for _ in 0..8 {
        let resp = proxy.get("/get", "lb.localhost").expect("send");
        assert_eq!(resp.status, 200);
    }

    assert_eq!(
        west.captured().len(),
        8,
        "SB_ZONE must zone the proxy exactly as proxy.zone would"
    );
    assert!(east.captured().is_empty());
}

#[test]
fn zoned_targets_without_a_proxy_zone_spread_as_before() {
    let a = MockUpstream::start(json!({"zone": "a"})).expect("zone-a upstream");
    let b = MockUpstream::start(json!({"zone": "b"})).expect("zone-b upstream");

    // Labels authored, no proxy zone anywhere: the pre-WOR-2328 shape.
    // Selection must ignore the labels (and warn at boot).
    let yaml = zoned_yaml(None, &a.base_url(), &b.base_url());
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    for _ in 0..8 {
        let resp = proxy.get("/get", "lb.localhost").expect("send");
        assert_eq!(resp.status, 200);
    }

    let count_a = a.captured().len();
    let count_b = b.captured().len();
    assert!(
        count_a > 0 && count_b > 0,
        "an unzoned proxy must keep round-robin across zones: a={count_a} b={count_b}"
    );
    assert_eq!(count_a + count_b, 8);
}
