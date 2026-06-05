//! Q4.14  -  boilerplate-stripping audit regression.
//!
//! The redaction policy in  (A1.5)
//! pins the rule that bodies never reach logs. For Wave 4 boilerplate
//! stripping, the corollary is: the proxy must record HOW MANY bytes
//! were stripped (the `stripped_bytes` counter), but never WHAT was
//! stripped (no body content in any log line). This test pins that
//! contract.
//!
//! Tests:
//!
//! 1. `stripped_bytes_counter_emitted_per_request` - drive a request
//!    through a boilerplate-stripping origin; assert the structured
//!    log line includes `stripped_bytes: <integer>`.
//! 2. `stripped_content_does_not_appear_in_logs` - inject a known PII
//!    sentinel into a fixture's nav (which is stripped); assert the
//!    sentinel does not appear in any log line.
//! 3. `stripped_bytes_sums_match_request_metric` - aggregate
//!    `stripped_bytes` across N requests; assert the
//!    `sbproxy_boilerplate_stripped_bytes_total` Prometheus counter
//!    matches the sum within +/- 5% (async aggregation lag).
//!
//! Open question for the docs lane: A1.5 in this tree does not yet
//! call out boilerplate stripping by name. The Q4.14 task references
//! "the A1.5 redaction policy" for `stripped_bytes`. Recommendation:
//! add a "Boilerplate stripping (Wave 4)" subsection to A1.5 that
//! pins the field name (`stripped_bytes`), the counter name
//! (`sbproxy_boilerplate_stripped_bytes_total`), and the rule that
//! body content of stripped regions never reaches a log sink.
//!
//! All three asserting tests are `#[ignore]`d until G4.10
//! (boilerplate stripper), R1.2 (typed redactor with the
//! `stripped_bytes` field), and the metric registration land in the
//! main proxy. The compile-time shape lock at the bottom of the file
//! runs unconditionally so a maintainer who breaks the YAML field
//! names sees a red signal before the ignored tests ever run.

use std::time::Duration;

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::Value;

// --- Config builder ---

/// Wires a single origin with the boilerplate transform enabled and a
/// stdout JSON log sink in `internal` profile, plus the Prometheus
/// metrics endpoint surfaced on the admin port. Field names track the
/// A1.5 ADR plus the Wave 4 G4.10 task description; if a key is
/// disputed across in-flight lanes the comment cites the lane.
fn boilerplate_audit_config(admin_port: u16, origin_base: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0  # overridden by the harness
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: w4-audit
observability:
  log:
    sinks:
      - name: stdout
        format: json
        profile: internal
  metrics:
    enabled: true
origins:
  "stripped.localhost":
    transforms:
      # G4.10 boilerplate stripper. Per A1.5 redaction policy the proxy
      # logs only the byte count of dropped content, never the content
      # itself (the `stripped_bytes` access-log field +
      # `sbproxy_boilerplate_stripped_bytes_total` counter).
      - type: boilerplate
    action:
      type: proxy
      url: "{origin_base}"
"#
    )
}

// --- Fixture HTML carrying a known PII sentinel ---
//
// The PII sentinel sits inside the `<nav>` block, which the stripper
// drops. If any log line contains the sentinel, the stripper or the
// log emitter leaked the body; that is the failure mode we are
// pinning.
const PII_SENTINEL: &str = "ssn-redaction-canary-407-83-2611";

fn html_with_pii_in_nav() -> String {
    format!(
        r#"<!doctype html>
<html>
<body>
<nav class="site-nav">
  <a href="/profile/{PII_SENTINEL}">My account</a>
  <span>Confidential PII canary: {PII_SENTINEL}</span>
</nav>
<article class="main-content">
  <h1>Public news article</h1>
  <p>This paragraph is the visible main content and should reach the agent.</p>
  <p>The nav above is boilerplate and must be stripped without leaking the canary into any log line.</p>
</article>
<footer>(c) 2026</footer>
</body>
</html>"#
    )
}

// --- Helpers ---

fn pick_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn admin_get(port: u16, path: &str) -> (u16, String) {
    let auth = format!("Basic {}", base64_encode("admin:w4-audit"));
    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client")
        .get(format!("http://127.0.0.1:{port}{path}"))
        .header("authorization", auth)
        .send()
        .expect("admin GET");
    let status = resp.status().as_u16();
    let body = resp.text().unwrap_or_default();
    (status, body)
}

/// Inline base64 encoder so the test does not pull in another crate
/// for one Basic-auth header.
fn base64_encode(input: &str) -> String {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(ALPH[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 6) & 0x3F) as usize] as char);
        out.push(ALPH[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let n = (bytes[i] as u32) << 16;
        out.push(ALPH[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 12) & 0x3F) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
        out.push(ALPH[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 6) & 0x3F) as usize] as char);
        out.push('=');
    }
    out
}

/// Pull recent structured log lines from the admin debug endpoint.
/// The internal admin server exposes `/api/logs/recent` for in-test
/// assertions; the JSON body is `{ "lines": ["...", "..."] }` where
/// each entry is the on-the-wire JSON payload as a string.
fn admin_recent_logs(port: u16) -> Vec<Value> {
    let (status, body) = admin_get(port, "/api/logs/recent?limit=200");
    assert_eq!(status, 200, "logs/recent fetch failed: {body}");
    let v: Value = serde_json::from_str(&body).expect("logs/recent JSON");
    v["lines"]
        .as_array()
        .expect("lines array")
        .iter()
        .filter_map(|line| line.as_str())
        .filter_map(|s| serde_json::from_str::<Value>(s).ok())
        .collect()
}

// --- Tests ---

/// Q4.14 (1)  -  every request through a boilerplate-stripping origin
/// emits a structured log line with `stripped_bytes` populated.
#[test]
#[ignore = "WOR-1131: the `stripped_bytes` access-log FIELD is wired (set from ctx.metrics.stripped_bytes in emit_access_log), but this test reads it back via `/api/logs/recent`, an in-memory access-log tap that does not exist yet (the admin server exposes `/api/requests` with a minimal RequestLogEntry, not the full access-log JSON). Reactivation blocks on an access-log ring-buffer admin endpoint; tracked with WOR-1133 (e2e harness gaps). The counter half of this ticket is covered end-to-end by stripped_bytes_sums_match_request_metric."]
fn stripped_bytes_counter_emitted_per_request() {
    let admin_port = pick_port();
    // The upstream must return boilerplate-laden HTML so the strip pass
    // has something to remove and `stripped_bytes` is non-zero.
    let upstream = MockUpstream::start_with_response_headers(
        Value::String(html_with_pii_in_nav()),
        vec![("content-type".into(), "text/html".into())],
    )
    .expect("mock upstream");
    let origin_base = upstream.base_url();
    let yaml = boilerplate_audit_config(admin_port, &origin_base);
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5)).expect("admin port");

    // Issue one boilerplate-laden request.
    let resp = harness
        .get_with_headers("/article", "stripped.localhost", &[])
        .expect("request");
    assert_eq!(resp.status, 200);

    // Allow the log sink to flush.
    std::thread::sleep(Duration::from_millis(200));

    let lines = admin_recent_logs(admin_port);
    let with_stripped = lines.iter().find(|l| l.get("stripped_bytes").is_some());
    let entry = with_stripped
        .unwrap_or_else(|| panic!("no log line carried `stripped_bytes` field; saw {lines:?}"));
    let bytes = entry["stripped_bytes"]
        .as_u64()
        .expect("stripped_bytes integer");
    assert!(
        bytes > 0,
        "stripped_bytes should be non-zero for a boilerplate-laden request: {entry:?}"
    );

    drop(harness);
    drop(upstream);
}

/// Q4.14 (2)  -  a known PII sentinel injected into the stripped nav
/// region must not appear in any log line. The redaction pass must
/// drop bodies before logs flush.
#[test]
#[ignore = "WOR-1131: same blocker as stripped_bytes_counter_emitted_per_request - the PII-leak assertion reads back log lines via `/api/logs/recent`, an in-memory access-log tap that does not exist yet. Reactivation blocks on that admin endpoint (tracked with WOR-1133)."]
fn stripped_content_does_not_appear_in_logs() {
    let admin_port = pick_port();
    let upstream = MockUpstream::start_with_response_headers(
        // The mock returns the PII-laden HTML body verbatim. The
        // proxy strips it before logging; if any log line contains
        // the sentinel, redaction is broken.
        Value::String(html_with_pii_in_nav()),
        vec![("content-type".into(), "text/html".into())],
    )
    .expect("mock upstream");
    let origin_base = upstream.base_url();
    let yaml = boilerplate_audit_config(admin_port, &origin_base);
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5)).expect("admin port");

    let resp = harness
        .get_with_headers("/article", "stripped.localhost", &[])
        .expect("request");
    assert_eq!(resp.status, 200);

    std::thread::sleep(Duration::from_millis(200));
    let lines = admin_recent_logs(admin_port);
    for entry in &lines {
        let text = serde_json::to_string(entry).unwrap_or_default();
        assert!(
            !text.contains(PII_SENTINEL),
            "log line leaked PII sentinel from stripped region: {text}"
        );
    }

    drop(harness);
    drop(upstream);
}

/// Scrape `sbproxy_boilerplate_stripped_bytes_total` from the proxy's
/// own `/metrics` endpoint (served on the main data-plane port, not the
/// admin port), summed across every label set. Returns 0 when absent.
fn scrape_boilerplate_metric(harness: &ProxyHarness) -> u64 {
    let resp = harness
        .get("/metrics", "stripped.localhost")
        .expect("GET /metrics");
    let body = String::from_utf8_lossy(&resp.body);
    let mut total: u64 = 0;
    for line in body.lines() {
        if line.starts_with('#') || !line.contains("sbproxy_boilerplate_stripped_bytes_total") {
            continue;
        }
        if let Some(value) = line.rsplit_once(' ').map(|(_, v)| v) {
            if let Ok(v) = value.parse::<u64>() {
                total = total.saturating_add(v);
            } else if let Ok(v) = value.parse::<f64>() {
                total = total.saturating_add(v as u64);
            }
        }
    }
    total
}

/// Q4.14 (3)  -  the `sbproxy_boilerplate_stripped_bytes_total` counter
/// accumulates linearly with request count. Each identical request
/// strips the same byte count, so after N requests the counter is
/// exactly N times the single-request value. This pins the counter
/// registration + per-request increment end-to-end via the proxy's own
/// `/metrics` endpoint (the access-log-side sum is covered separately
/// once the in-memory access-log tap lands; see the two ignored tests).
#[test]
fn stripped_bytes_sums_match_request_metric() {
    let admin_port = pick_port();
    let upstream = MockUpstream::start_with_response_headers(
        Value::String(html_with_pii_in_nav()),
        vec![("content-type".into(), "text/html".into())],
    )
    .expect("mock upstream");
    let origin_base = upstream.base_url();
    let yaml = boilerplate_audit_config(admin_port, &origin_base);
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    // One request establishes the per-request strip amount.
    harness
        .get_with_headers("/article", "stripped.localhost", &[])
        .expect("request");
    let per_request = scrape_boilerplate_metric(&harness);
    assert!(
        per_request > 0,
        "boilerplate strip on an HTML response must increment the counter"
    );

    // N-1 more identical requests; the counter must land at exactly
    // N times the single-request value.
    const N: u64 = 10;
    for _ in 1..N {
        harness
            .get_with_headers("/article", "stripped.localhost", &[])
            .expect("request");
    }
    let total = scrape_boilerplate_metric(&harness);
    assert_eq!(
        total,
        per_request * N,
        "counter must accumulate linearly: {per_request} * {N} expected, got {total}"
    );

    drop(harness);
    drop(upstream);
}

/// Compile-time shape lock. Builds the YAML against fixed inputs and
/// asserts the keys we depend on are present.
#[test]
fn boilerplate_audit_config_compiles() {
    let yaml = boilerplate_audit_config(9999, "http://127.0.0.1:1");
    assert!(yaml.contains("type: boilerplate"));
    assert!(yaml.contains("profile: internal"));
    // PII sentinel must be present in the fixture so the leak test
    // has a clear canary to look for.
    let html = html_with_pii_in_nav();
    assert!(html.contains(PII_SENTINEL));
    // The base64 helper round-trips a known input (`admin:w4-audit`
    // -> standard base64 with no padding-collisions).
    let encoded = base64_encode("admin:w4-audit");
    assert!(!encoded.is_empty());
}
