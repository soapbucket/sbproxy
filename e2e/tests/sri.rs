//! End-to-end coverage for the `sri` (Subresource Integrity) policy.
//!
//! SRI is observation-only: the policy scans `text/html` responses
//! from the upstream and logs / increments metrics for any external
//! `<script src>` or `<link rel="stylesheet" href>` tag that is
//! missing an `integrity` attribute (or uses a disallowed algorithm).
//! The response body and headers are not modified.
//!
//! The scan hooks into the upstream `response_filter`, which only runs
//! for a genuinely proxied (`type: proxy`) origin. A `static` action
//! writes its response during the request phase and never reaches that
//! hook, so these tests proxy to a `MockUpstream` serving raw HTML,
//! the same shape as `examples/sri/fixture.py`. With a `static` origin
//! every passthrough assertion here stays green with the `sri` policy
//! deleted, which is exactly the blind spot that shipped the original
//! example bug - hence the metric assertions below.
//!
//! These tests confirm three things end-to-end:
//!
//! 1. Missing integrity attributes: the response flows through intact
//!    (no body mutation, no blocking) AND the scan really ran, proved
//!    by `sbproxy_policy_triggers_total{policy_type="sri",
//!    action="violation"}`.
//! 2. Valid integrity attributes: byte-identical passthrough, an
//!    `action="clean"` sample, and no violation sample.
//! 3. A non-HTML response is a no-op even when enforced: passthrough
//!    and no sri-labeled series at all.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use std::time::{Duration, Instant};

fn proxied_sri_config(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "sri.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    policies:
      - type: sri
        enforce: true
        algorithms: [sha256, sha384, sha512]
"#
    )
}

/// True for a `/metrics` sample line of the SRI policy-trigger family
/// with the given `action` label. The family is
/// `sbproxy_policy_triggers_total{origin, policy_type, action, ...}`;
/// the writer is `record_policy(&ctx.hostname, "sri", action)` in the
/// response body filter.
fn is_sri_sample(line: &str, action: &str) -> bool {
    line.starts_with("sbproxy_policy_triggers_total{")
        && line.contains("policy_type=\"sri\"")
        && line.contains(&format!("action=\"{action}\""))
}

/// Scrape `/metrics` until `predicate` matches a sample line or the
/// timeout lapses, and return the matching line. The SRI scan runs in
/// the response path, so a short poll absorbs any scrape-vs-write race
/// without hiding a scan that never happens.
fn wait_for_metric_line(
    harness: &ProxyHarness,
    predicate: impl Fn(&str) -> bool,
) -> Option<String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let metrics = harness
            .get("/metrics", "sri.localhost")
            .ok()
            .and_then(|resp| resp.text().ok())
            .unwrap_or_default();
        if let Some(line) = metrics
            .lines()
            .filter(|line| !line.starts_with('#'))
            .find(|line| predicate(line))
        {
            return Some(line.to_string());
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Fetch `/metrics` once, for negative assertions.
fn metrics_snapshot(harness: &ProxyHarness) -> String {
    let resp = harness.get("/metrics", "sri.localhost").expect("metrics");
    assert_eq!(resp.status, 200);
    resp.text().unwrap_or_default()
}

#[test]
fn html_with_missing_integrity_passes_through_and_counts_a_violation() {
    let body = "<html><body>\n<script src=\"https://cdn.example.com/lib.js\"></script>\n<link rel=\"stylesheet\" href=\"https://cdn.example.com/theme.css\">\n</body></html>";
    let upstream =
        MockUpstream::start_raw(body.as_bytes().to_vec(), "text/html").expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&proxied_sri_config(&upstream.base_url()))
        .expect("start proxy");

    let resp = harness.get("/", "sri.localhost").expect("send");
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.text().expect("decode body"),
        body,
        "SRI is observation-only and must not mutate the response body"
    );

    // The passthrough assertions above hold even when the scanner
    // never runs; this one does not. The violation counter is the
    // proof the scan happened.
    let line = wait_for_metric_line(&harness, |line| is_sri_sample(line, "violation"));
    assert!(
        line.is_some(),
        "expected a sbproxy_policy_triggers_total sample with policy_type=\"sri\" \
         action=\"violation\"; the SRI scan did not run"
    );
}

#[test]
fn html_with_valid_integrity_passes_through_and_counts_clean() {
    let body = "<html>\n<script src=\"https://cdn.example.com/lib.js\"\n        integrity=\"sha384-abcdef\"\n        crossorigin=\"anonymous\"></script>\n</html>";
    let upstream =
        MockUpstream::start_raw(body.as_bytes().to_vec(), "text/html").expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&proxied_sri_config(&upstream.base_url()))
        .expect("start proxy");

    let resp = harness.get("/", "sri.localhost").expect("send");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.text().expect("decode body"), body);

    // The scan ran and found every external reference covered.
    let clean = wait_for_metric_line(&harness, |line| is_sri_sample(line, "clean"));
    assert!(
        clean.is_some(),
        "expected a sbproxy_policy_triggers_total sample with policy_type=\"sri\" \
         action=\"clean\"; the SRI scan did not run"
    );
    // And a fully covered page must not report a violation.
    let metrics = metrics_snapshot(&harness);
    assert!(
        !metrics.lines().any(|line| is_sri_sample(line, "violation")),
        "a page with valid integrity attributes must not count a violation"
    );
}

#[test]
fn non_html_response_is_unaffected_by_sri_policy() {
    let body = r#"{"hello":"world"}"#;
    let upstream =
        MockUpstream::start_raw(body.as_bytes().to_vec(), "application/json").expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&proxied_sri_config(&upstream.base_url()))
        .expect("start proxy");

    let resp = harness.get("/", "sri.localhost").expect("send");
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or(""),
        "application/json"
    );
    assert_eq!(resp.text().expect("decode body"), body);

    // Non-HTML never arms the scan, so no sri-labeled series exists
    // in either direction. The response already completed, so the
    // scan decision has already been taken; one snapshot suffices.
    let metrics = metrics_snapshot(&harness);
    assert!(
        !metrics
            .lines()
            .any(|line| is_sri_sample(line, "violation") || is_sri_sample(line, "clean")),
        "a non-HTML response must not produce any sri policy-trigger sample"
    );
}
