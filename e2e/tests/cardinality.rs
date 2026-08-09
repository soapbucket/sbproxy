//! Cardinality budget regression, static half.
//!
//! Every Prometheus label in this workspace carries a per-label cap.
//! Crossing one is not a scrape failure: the limiter demotes the
//! offending value to `__other__` and increments
//! `sbproxy_label_cardinality_overflow_total{metric,label}`, so the
//! series count tracks the budget rather than the traffic.
//!
//! This file holds the half of that contract that needs no proxy. It
//! asserts that the caps this suite reasons about are the caps
//! `sbproxy-observe` actually enforces, that the demotion sentinel is
//! the one the limiter actually writes, and that the exposition parser
//! below reads a demoted series correctly.
//!
//! The end-to-end half lives in `metrics_per_agent.rs`, which the same
//! CI lane builds and runs. That file lowers `hostname_cap` in config,
//! drives 250 distinct hostnames through a spawned proxy, and asserts
//! both the `__other__` sentinel and the overflow counter appear in a
//! real `/metrics` scrape. Keeping the two halves apart is deliberate:
//! a cap that disagrees with the runtime table is a millisecond of
//! assertion, and only the behavior underneath it needs a process.
//!
//! ## Why there is no multi-tenant fan-out test here
//!
//! This file used to carry an ignored `#[test]` that drove 250 agents
//! across 1500 tenants and asserted per-tenant demotion on
//! `sbproxy_requests_total`. Its stated blocker was that `tenant_id` is
//! not a label on that counter. That is true, and it is the smallest of
//! four reasons the test could not be made to pass:
//!
//! - Tenancy is resolved from config, not from a request header. An
//!   origin names a tenant, the compiler rejects an origin naming a
//!   tenant that `proxy.tenants` does not declare, and the request
//!   context carries whatever the matched origin resolved to. The
//!   fixture drove tenancy through an `X-Workspace-Id` header that
//!   nothing reads, so all 375 000 requests would have recorded the
//!   same default tenant.
//! - The same follows for the agent dimension: the fixture config
//!   configured no agent classifier, so every request would have
//!   recorded the empty agent sentinel, and one value never demotes.
//! - Its scrape helper returned an empty string rather than fetching
//!   `/metrics`, so every assertion read an empty body.
//! - 250 x 1500 sequential requests through a spawned proxy is not a
//!   five-minute CI lane.
//!
//! Adding `tenant_id` to `sbproxy_requests_total` would have fixed none
//! of those, and it is the wrong change on its own terms. Per-tenant
//! request attribution already exists on
//! `sbproxy_inbound_key_requests_total`, which carries `tenant_id`
//! today, is marked tenant-scoped in the metric registry, and is
//! recorded from the same block of the response path a dozen lines
//! after the requests counter. `sbproxy_requests_total` is the
//! substrate traffic counter, it already carries eight labels, and no
//! dashboard or alert rule in this repository slices it by tenant.

/// Per-label caps this suite reasons about.
///
/// Written out here rather than read straight out of
/// [`sbproxy_observe::cardinality::budget_for_label`] so the assertion
/// below has two independent sides. Lowering a runtime budget then has
/// to be done twice, and the second time is a review of the first.
mod caps {
    /// Sanitized agent registry id.
    pub const AGENT_ID: usize = 200;
    /// Tenant / workspace boundary label.
    pub const TENANT_ID: usize = 1000;
    /// Request hostname, the one traffic-driven label on the requests
    /// counter and the one `metrics_per_agent.rs` overflows for real.
    pub const HOSTNAME: usize = 200;
}

/// Sentinel the limiter substitutes for a demoted label value.
///
/// `overflow` is accepted alongside it so a rename lands as one edit
/// here rather than as a silent miss, but only `__other__` is asserted
/// against the live constant below. A third spelling is a rename, and a
/// rename should break something.
const DEMOTION_SENTINELS: &[&str] = &["__other__", "overflow"];

/// The counter the limiter increments on demotion. Labeled `metric` and
/// `label`, matching the registry declaration.
const OVERFLOW_COUNTER: &str = "sbproxy_label_cardinality_overflow_total";

#[test]
fn caps_agree_with_the_live_budget_table() {
    use sbproxy_observe::cardinality::budget_for_label;

    assert_eq!(
        budget_for_label("agent_id"),
        caps::AGENT_ID,
        "agent_id budget moved in sbproxy-observe without moving here"
    );
    assert_eq!(
        budget_for_label("tenant_id"),
        caps::TENANT_ID,
        "tenant_id budget moved in sbproxy-observe without moving here"
    );
    assert_eq!(
        budget_for_label("hostname"),
        caps::HOSTNAME,
        "hostname budget moved in sbproxy-observe without moving here; \
         metrics_per_agent.rs drives 250 hostnames to overflow this one"
    );
}

#[test]
fn the_demotion_sentinel_is_the_one_the_limiter_writes() {
    assert!(
        DEMOTION_SENTINELS.contains(&sbproxy_observe::cardinality::OTHER_LABEL),
        "the limiter writes {:?}, which this file does not recognize as a \
         demotion sentinel; the e2e assertions in metrics_per_agent.rs \
         match on the same spelling",
        sbproxy_observe::cardinality::OTHER_LABEL
    );
}

/// Shape lock on the exposition parser below, against a body written in
/// the format the proxy actually emits: a demoted series carrying the
/// sentinel, and the overflow counter keyed by `(metric, label)`.
#[test]
fn metrics_text_parser_handles_typical_lines() {
    let text = r#"
# HELP sbproxy_requests_total Total requests served.
# TYPE sbproxy_requests_total counter
sbproxy_requests_total{hostname="a.example",agent_id="bot-1"} 12
sbproxy_requests_total{hostname="b.example",agent_id="bot-2"} 7
sbproxy_requests_total{hostname="__other__",agent_id="bot-2"} 33
# HELP sbproxy_label_cardinality_overflow_total Demoted label values.
# TYPE sbproxy_label_cardinality_overflow_total counter
sbproxy_label_cardinality_overflow_total{metric="sbproxy_requests_total",label="hostname"} 50
sbproxy_label_cardinality_overflow_total{metric="sbproxy_requests_total",label="agent_id"} 0
"#;
    assert_eq!(count_series(text, "sbproxy_requests_total"), 3);

    let hostnames = distinct_label_values(text, "sbproxy_requests_total", "hostname");
    assert_eq!(hostnames.len(), 3);
    assert!(
        hostnames
            .iter()
            .any(|value| DEMOTION_SENTINELS.contains(&value.as_str())),
        "parser dropped the demoted series; got {hostnames:?}"
    );

    assert_eq!(
        sum_overflow_counter(text, "sbproxy_requests_total", "hostname"),
        50
    );
    assert_eq!(
        sum_overflow_counter(text, "sbproxy_requests_total", "agent_id"),
        0
    );
}

// --- Tiny Prometheus text parser ---
//
// Just enough to count series and pull label values for one metric.
// Avoids pulling in `prometheus-parser` for a handful of assertions.

fn count_series(text: &str, metric: &str) -> usize {
    text.lines()
        .filter(|line| {
            !line.starts_with('#')
                && !line.is_empty()
                && line
                    .split_whitespace()
                    .next()
                    .is_some_and(|head| head.starts_with(metric))
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
        if let Some(value) = extract_label(line, label) {
            seen.insert(value.to_string());
        }
    }
    seen.into_iter().collect()
}

/// Sum every [`OVERFLOW_COUNTER`] series whose `metric` and `label`
/// labels match, which is how many values that one dimension has had
/// demoted.
fn sum_overflow_counter(text: &str, metric: &str, label: &str) -> u64 {
    let mut total: u64 = 0;
    for line in text.lines() {
        let head = line.split_whitespace().next().unwrap_or("");
        if !head.starts_with(OVERFLOW_COUNTER) {
            continue;
        }
        if extract_label(line, "metric") != Some(metric) {
            continue;
        }
        if extract_label(line, "label") != Some(label) {
            continue;
        }
        if let Some(value) = line.split_whitespace().last() {
            if let Ok(parsed) = value.parse::<u64>() {
                total += parsed;
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
