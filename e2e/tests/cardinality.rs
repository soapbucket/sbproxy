//! Cardinality budget regression (Wave 1 / Q1.14).
//!
//! Per `docs/adr-metric-cardinality.md` (A1.1) and
//! `docs/adr-slo-alert-taxonomy.md` (A1.6), every Prometheus metric has
//! a per-label cap and a per-metric series ceiling. Crossing either is
//! a CI block; the proxy degrades to `__other__` (the per-A1.1 spelling
//! is `__other__`; A1.6 mirrors it as `overflow`) and increments
//! `sbproxy_label_demotion_total{metric, label}`.
//!
//! Fixture multi-tenant load:
//!   - 250 distinct `agent_id` values (cap 200 → 50 demoted)
//!   - 1500 distinct `tenant_id` values (cap 1000 → 500 demoted)
//!   - 50 distinct `hostname` values (under cap of 200)
//!
//! Assertions:
//!   1. `sbproxy_requests_total` series count ≤ ceiling.
//!   2. The demotion sentinel appears with non-zero counter values.
//!   3. `sbproxy_label_demotion_total{metric=...,label="agent_id"}` is
//!      non-zero.
//!   4. Same for `label="tenant_id"`.
//!
//! Implementation depends on G1.6 (per-agent labels), the typed
//! enum-derived label types, and the `CardinalityLimiter` wrapper on
//! every metric handle. Until those land the heavy assertions are
//! `#[ignore]`d. The shape-only tests run today.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

/// Per-A1.1 caps. Updating these requires updating
/// `docs/adr-metric-cardinality.md` in the same PR; CI's
/// observability-budgets workflow (B1.12) cross-checks the two.
mod caps {
    pub const AGENT_ID: usize = 200;
    pub const TENANT_ID: usize = 1000;
    /// Aggregate ceiling for `sbproxy_requests_total` per A1.1.
    pub const REQUESTS_TOTAL_SERIES: usize = 250_000;
}

/// Sentinel demotion label per A1.1. The ADR text uses `__other__`;
/// the assertion accepts either spelling so a future rename does not
/// silently break the test. New spellings beyond these two require an
/// ADR amendment.
const DEMOTION_SENTINELS: &[&str] = &["__other__", "overflow"];

/// Drive a fixture multi-tenant load and return a metrics scrape body.
/// Each (agent_id, tenant_id) tuple sees one request so the cardinality
/// is exactly the product of distinct values.
#[test]
#[ignore = "TODO(wave3): G1.6 per-agent labels (agent_id, agent_class, agent_vendor, payment_rail, content_shape) are wired on sbproxy_requests_total but `tenant_id` is not on the label set yet. Test expects tenant_id label demotion which requires the multi-tenant label landing planned for Wave 3."]
fn cardinality_caps_are_respected_under_multi_tenant_load() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("start mock upstream");
    let yaml = build_config(&upstream.base_url());
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    drive_load(&harness, /* agents */ 250, /* tenants */ 1500);

    let metrics = scrape_metrics(&harness).expect("scrape /metrics");

    // 1. Series count under ceiling.
    let series = count_series(&metrics, "sbproxy_requests_total");
    assert!(
        series <= caps::REQUESTS_TOTAL_SERIES,
        "sbproxy_requests_total series {series} exceeds ceiling {}",
        caps::REQUESTS_TOTAL_SERIES
    );

    // 2. Distinct agent_id label values <= cap (rest go to demotion).
    let agent_ids = distinct_label_values(&metrics, "sbproxy_requests_total", "agent_id");
    assert!(
        agent_ids.len() <= caps::AGENT_ID + DEMOTION_SENTINELS.len(),
        "agent_id distinct values {} exceed cap {}; values={:?}",
        agent_ids.len(),
        caps::AGENT_ID,
        agent_ids
    );
    assert!(
        agent_ids
            .iter()
            .any(|v| DEMOTION_SENTINELS.contains(&v.as_str())),
        "expected an `__other__`/`overflow` sentinel for agent_id; got {:?}",
        agent_ids
    );

    // 3. tenant_id label cap.
    let tenant_ids = distinct_label_values(&metrics, "sbproxy_requests_total", "tenant_id");
    assert!(
        tenant_ids.len() <= caps::TENANT_ID + DEMOTION_SENTINELS.len(),
        "tenant_id distinct values {} exceed cap {}",
        tenant_ids.len(),
        caps::TENANT_ID
    );
    assert!(
        tenant_ids
            .iter()
            .any(|v| DEMOTION_SENTINELS.contains(&v.as_str())),
        "expected an `__other__`/`overflow` sentinel for tenant_id"
    );

    // 4. Demotion counter is non-zero for both labels.
    let agent_demoted = sum_label_demotion(&metrics, "sbproxy_requests_total", "agent_id");
    assert!(
        agent_demoted > 0,
        "sbproxy_label_demotion_total{{metric=\"sbproxy_requests_total\",label=\"agent_id\"}} == 0"
    );
    let tenant_demoted = sum_label_demotion(&metrics, "sbproxy_requests_total", "tenant_id");
    assert!(
        tenant_demoted > 0,
        "sbproxy_label_demotion_total{{metric=\"sbproxy_requests_total\",label=\"tenant_id\"}} == 0"
    );

    drop(harness);
    drop(upstream);
}

/// Compile-time shape lock. Asserts the parser helpers handle a
/// standard Prometheus text exposition correctly. Cheap; no proxy boot.
#[test]
fn metrics_text_parser_handles_typical_lines() {
    let text = r#"
# HELP sbproxy_requests_total Total requests served.
# TYPE sbproxy_requests_total counter
sbproxy_requests_total{route="/api",agent_id="bot-1",tenant_id="tenant-a"} 12
sbproxy_requests_total{route="/api",agent_id="bot-2",tenant_id="tenant-a"} 7
sbproxy_requests_total{route="/api",agent_id="__other__",tenant_id="tenant-a"} 33
# HELP sbproxy_label_demotion_total Demoted label tuples.
# TYPE sbproxy_label_demotion_total counter
sbproxy_label_demotion_total{metric="sbproxy_requests_total",label="agent_id"} 50
sbproxy_label_demotion_total{metric="sbproxy_requests_total",label="tenant_id"} 0
"#;
    assert_eq!(count_series(text, "sbproxy_requests_total"), 3);
    let agents = distinct_label_values(text, "sbproxy_requests_total", "agent_id");
    assert_eq!(agents.len(), 3);
    assert!(agents.contains(&"__other__".to_string()));
    assert_eq!(
        sum_label_demotion(text, "sbproxy_requests_total", "agent_id"),
        50
    );
    assert_eq!(
        sum_label_demotion(text, "sbproxy_requests_total", "tenant_id"),
        0
    );
}

#[test]
fn caps_table_matches_adr_constants() {
    // Anchor the constants to the ADR. If the ADR moves, these values
    // must move; the contract is "either both update in one PR or
    // neither does."
    assert_eq!(caps::AGENT_ID, 200, "see adr-metric-cardinality.md table");
    assert_eq!(caps::TENANT_ID, 1000, "see adr-slo-alert-taxonomy.md table");
    const _: () = assert!(
        caps::REQUESTS_TOTAL_SERIES >= caps::AGENT_ID * caps::TENANT_ID / 100,
        "ceiling must be at least 1% of agent x tenant"
    );
}

// --- Fixture builders ---

fn build_config(upstream_base: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
observability:
  metrics:
    enabled: true
origins:
  "card.localhost":
    action:
      type: proxy
      url: "{upstream_base}"
"#
    )
}

/// Drive `agents * tenants` requests, one per (agent_id, tenant_id)
/// pair. The proxy is expected to read tenant from the X-Workspace-Id
/// header and agent_id from a stub UA-only catalog the test config
/// configures (see G1.4 fixture).
fn drive_load(h: &ProxyHarness, agents: usize, tenants: usize) {
    for t in 0..tenants {
        let tenant_hdr = format!("tenant-{t:04}");
        for a in 0..agents {
            let ua = format!("synthetic-agent-{a:03}/1.0");
            let _ = h.get_with_headers(
                "/",
                "card.localhost",
                &[
                    ("user-agent", ua.as_str()),
                    ("x-workspace-id", tenant_hdr.as_str()),
                ],
            );
        }
    }
}

fn scrape_metrics(_h: &ProxyHarness) -> anyhow::Result<String> {
    // Real implementation: GET /metrics on the admin port. Returns the
    // text-exposition body. Placeholder until R1.1 lands the admin-side
    // metrics endpoint contract.
    Ok(String::new())
}

// --- Tiny Prometheus text parser ---
//
// Just enough to count series and pull label values for one metric.
// Avoids pulling in `prometheus-parser` for a Wave-1-stable test stub.

fn count_series(text: &str, metric: &str) -> usize {
    text.lines()
        .filter(|l| {
            !l.starts_with('#')
                && !l.is_empty()
                && l.split_whitespace()
                    .next()
                    .map(|s| s.starts_with(metric))
                    .unwrap_or(false)
        })
        .count()
}

fn distinct_label_values(text: &str, metric: &str, label: &str) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::<String>::new();
    for line in text.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let head = line.split_whitespace().next().unwrap_or("");
        if !head.starts_with(metric) {
            continue;
        }
        if let Some(val) = extract_label(line, label) {
            seen.insert(val.to_string());
        }
    }
    seen.into_iter().collect()
}

fn sum_label_demotion(text: &str, metric: &str, label: &str) -> u64 {
    let mut total: u64 = 0;
    for line in text.lines() {
        let head = line.split_whitespace().next().unwrap_or("");
        if !head.starts_with("sbproxy_label_demotion_total") {
            continue;
        }
        let m = extract_label(line, "metric").unwrap_or("");
        let l = extract_label(line, "label").unwrap_or("");
        if m == metric && l == label {
            if let Some(val) = line.split_whitespace().last() {
                if let Ok(n) = val.parse::<u64>() {
                    total += n;
                }
            }
        }
    }
    total
}

fn extract_label<'a>(line: &'a str, label: &str) -> Option<&'a str> {
    let needle = format!(r#"{label}=""#);
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}
