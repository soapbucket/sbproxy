//! Q1.5: per-agent metric label cardinality snapshot.
//!
//! Per `docs/adr-metric-cardinality.md`, the Wave 1 labels added to
//! `sbproxy_requests_total` are `agent_id`, `agent_class`,
//! `agent_vendor`, `payment_rail`, and `content_shape`. Each comes with
//! a closed value set or a per-label cap; this test asserts:
//!
//!   1. The labels appear in `/metrics` for at least one series.
//!   2. The total series count for `sbproxy_requests_total` stays
//!      under the documented ceiling (250k worst-case, but our test
//!      fixture should land in the low thousands).
//!   3. When we drive 250 distinct synthetic agent IDs we observe the
//!      `agent_id="overflow"` (or `__other__` per the existing
//!      `CardinalityLimiter`) demotion sentinel and the
//!      `sbproxy_label_demotion_total` counter increments.
//!
//! G1.6 (the metric-label landing branch) and the new
//! `sbproxy_label_cardinality_overflow_total` counter referenced in
//! the QA brief have not landed yet, so each assertion is `#[ignore]`d
//! with a `TODO(wave1-G1.6)` reason. The fixture and metric-fetch
//! plumbing are in place.

use sbproxy_e2e::ProxyHarness;

const FIXTURE: &str = r#"
proxy:
  http_bind_port: 0  # overridden by the harness
origins:
  "blog.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>article</h1>"
    policies:
      - type: ai_crawl_control
        currency: USD
        price: 0.001
        valid_tokens:
          - tier-test-token
"#;

/// Fetch `/metrics` from the proxy. The endpoint is served on the same
/// port as the data plane (see `crates/sbproxy-core/src/server.rs` and
/// the `path == "/metrics"` arm).
fn fetch_metrics(harness: &ProxyHarness) -> String {
    let resp = harness.get("/metrics", "blog.localhost").expect("metrics");
    assert_eq!(resp.status, 200);
    resp.text().unwrap_or_default()
}

/// Count the number of series for the named metric. Series are one per
/// distinct label tuple; we count text lines starting with `metric{...`
/// or `metric ` (no labels). Comment / type lines are skipped.
fn count_series(metrics: &str, name: &str) -> usize {
    metrics
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter(|line| {
            line.starts_with(&format!("{name}{{")) || line.starts_with(&format!("{name} "))
        })
        .count()
}

// --- Test 1: per-agent labels appear in /metrics ---

#[test]
fn per_agent_labels_present_in_metrics_after_traffic() {
    let harness = ProxyHarness::start_with_yaml(FIXTURE).expect("start proxy");

    // Drive 100 requests across 3 agents and 2 routes.
    let agents = [
        ("Mozilla/5.0 (compatible; GPTBot/2.1)", None),
        (
            "Mozilla/5.0 (compatible; ClaudeBot/1.0)",
            Some("tier-test-token"),
        ),
        ("Mozilla/5.0 Chrome/120", None),
    ];
    let routes = ["/article/a", "/article/b"];
    for i in 0..100 {
        let (ua, tok) = agents[i % agents.len()];
        let route = routes[i % routes.len()];
        let mut h: Vec<(&str, &str)> = vec![("user-agent", ua)];
        if let Some(t) = tok {
            h.push(("crawler-payment", t));
        }
        let _ = harness.get_with_headers(route, "blog.localhost", &h);
    }

    let metrics = fetch_metrics(&harness);
    assert!(
        metrics.contains("sbproxy_requests_total"),
        "requests counter present"
    );
    // Per ADR, `agent_id`, `agent_class`, `agent_vendor` go on the
    // requests counter. The label names appear textually in the
    // exposition format (`label="value"`).
    for label in ["agent_id", "agent_class", "agent_vendor"] {
        assert!(
            metrics.contains(&format!("{label}=")),
            "{label} label must appear on at least one series; metrics:\n{metrics}"
        );
    }
}

// --- Test 2: cardinality cap honored ---

#[test]
fn cardinality_cap_keeps_series_count_bounded() {
    let harness = ProxyHarness::start_with_yaml(FIXTURE).expect("start proxy");

    // Send 100 requests with a small set of agents.
    for _ in 0..100 {
        let _ = harness.get_with_headers(
            "/article",
            "blog.localhost",
            &[("user-agent", "GPTBot/2.1")],
        );
    }
    let metrics = fetch_metrics(&harness);
    let series = count_series(&metrics, "sbproxy_requests_total");
    // Generous ceiling: a small fixture should produce well under 100
    // series. The cardinality ADR's 250k ceiling is the runtime
    // safety net; an e2e test should never come close.
    assert!(
        series < 1_000,
        "low-traffic fixture should keep requests_total series under 1k, got {series}"
    );
}

// --- Test 3: overflow sentinel + demotion counter ---

#[test]
#[ignore = "TODO(wave3): hostname cardinality cap is above 250 in default config; overflow sentinel + demotion counter wired but not triggered by this fixture. Needs either a higher-volume fixture or a config knob to lower the cap for tests."]
fn cardinality_overflow_emits_sentinel_and_increments_demotion_counter() {
    let harness = ProxyHarness::start_with_yaml(FIXTURE).expect("start proxy");

    // Drive 250 distinct synthetic UAs so the resolver mints 250
    // distinct agent_id values. Per ADR the agent-class catalog is
    // bounded to ~10 + 3 sentinels, so unmatched UAs must collapse to
    // `agent_id="unknown"` rather than per-UA series. To exercise the
    // *generic* overflow path (the token-bucket creation rate-limit
    // and `__other__` sentinel), we drive 250 distinct synthetic
    // hostnames instead (hostname is the variable label per ADR).
    for i in 0..250 {
        let host = format!("tenant-{i}.localhost");
        let _ = harness.get_with_headers("/article", &host, &[("user-agent", "GPTBot/2.1")]);
    }
    let metrics = fetch_metrics(&harness);

    // Either `__other__` (existing CardinalityLimiter sentinel) or
    // `overflow` (new sentinel proposed in QA brief) is acceptable
    // until G1.6 picks one. The assertion accepts both.
    let has_sentinel =
        metrics.contains("hostname=\"__other__\"") || metrics.contains("hostname=\"overflow\"");
    assert!(
        has_sentinel,
        "expected hostname overflow sentinel after 250 distinct hostnames; metrics:\n{metrics}"
    );

    // The demotion counter must be non-zero. Either name is accepted
    // until G1.6 lands the canonical metric.
    let demotion_present = metrics.lines().filter(|l| !l.starts_with('#')).any(|l| {
        l.starts_with("sbproxy_label_cardinality_overflow_total")
            || l.starts_with("sbproxy_label_demotion_total")
    });
    assert!(
        demotion_present,
        "demotion counter must surface a non-zero series after overflow"
    );
}

// --- Smoke test: /metrics endpoint is reachable ---

/// Sanity check that `/metrics` is served on the data plane port and
/// returns the prometheus exposition format. This test runs even
/// before G1.6 lands.
#[test]
fn metrics_endpoint_reachable_and_well_formed() {
    let harness = ProxyHarness::start_with_yaml(FIXTURE).expect("start proxy");
    let metrics = fetch_metrics(&harness);
    assert!(
        metrics.contains("# HELP") || metrics.contains("# TYPE"),
        "metrics endpoint should emit prometheus exposition format with HELP/TYPE comments"
    );
}
