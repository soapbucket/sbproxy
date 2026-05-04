//! Wave 5 / Q5.3: headless-browser detection in
//! `sbproxy-security/headless_detect.rs`.
//!
//! Pins the contract from `docs/adr-tls-fingerprint-pipeline.md` § "Worked
//! example: headless Puppeteer detection". The detector reads
//! `request.tls_fingerprint.ja4` and consults the reference catalogue at
//! `crates/sbproxy-classifiers/data/tls-fingerprints.json`. A match
//! produces `HeadlessSignal::Detected { library, confidence }` and feeds
//! the G1.4 resolver chain so `agent_class = "headless-browser"` lands on
//! the request context.
//!
//! Tests in this file rely on the G5.4 lane
//! (`wave5/G5.4-headless-detect`) plus the G5.3 capture lane. Until both
//! land we cannot drive a real Puppeteer JA4 through the pipeline, so
//! every test is `#[ignore]`'d with the appropriate `TODO(wave5-G5.4)`
//! marker. The fixture YAML is shaped against the ADR's worked example so
//! the only remaining work at activation time is pointing the harness at
//! a TLS-capable client path.

use sbproxy_e2e::ProxyHarness;

// --- Test 1: Puppeteer JA4 -> HeadlessSignal::Detected ---

#[test]
#[ignore = "TODO(wave5-day6+): day-5 landed the type: cel transform (Item 4) and the harness loopback trust-CIDR default (Item 5). Reactivation blocks on (1) the test must inject sidecar headers like x-sbproxy-tls-ja4 via get_with_headers so the JA4 actually populates request.tls.ja4, and (2) the day-5 CEL transform writes to the response BODY, not response HEADERS as these tests expect; the tests need to be rewritten to assert against the body."]
fn puppeteer_ja4_detected_with_library_label() {
    let yaml = r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
    trustworthy_client_cidrs:
      - 127.0.0.0/8
  headless_detect:
    enabled: true
origins:
  "headless.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: cel
        on_response: |
          resp.headers["x-headless-library"] = request.headless_signal != null
            ? request.headless_signal.library
            : "absent"
          resp.headers["x-headless-confidence"] = request.headless_signal != null
            ? string(request.headless_signal.confidence)
            : "0"
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    // The harness has no path to drive a literal Puppeteer JA4 yet;
    // when G5.4 lands the test runner will replay a known-Puppeteer
    // ClientHello and assert the catalogue match below.
    let resp = harness.get("/", "headless.localhost").expect("GET");
    assert_eq!(
        resp.headers.get("x-headless-library").map(String::as_str),
        Some("puppeteer"),
        "Puppeteer JA4 must map to library = puppeteer in the reference catalogue"
    );
}

// --- Test 2: Generic browser JA4 -> NotDetected ---

#[test]
#[ignore = "TODO(wave5-day6+): day-5 landed the type: cel transform (Item 4) and the harness loopback trust-CIDR default (Item 5). Reactivation blocks on (1) the test must inject sidecar headers like x-sbproxy-tls-ja4 via get_with_headers so the JA4 actually populates request.tls.ja4, and (2) the day-5 CEL transform writes to the response BODY, not response HEADERS as these tests expect; the tests need to be rewritten to assert against the body."]
fn generic_browser_ja4_not_detected() {
    let yaml = r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
    trustworthy_client_cidrs:
      - 127.0.0.0/8
  headless_detect:
    enabled: true
origins:
  "headless.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: cel
        on_response: |
          resp.headers["x-headless"] = request.headless_signal != null ? "detected" : "none"
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness.get("/", "headless.localhost").expect("GET");
    assert_eq!(
        resp.headers.get("x-headless").map(String::as_str),
        Some("none"),
        "real Chrome/Firefox/Safari JA4 must NOT match the headless catalogue"
    );
}

// --- Test 3: confidence halved when trustworthy = false ---

#[test]
#[ignore = "TODO(wave5-day6+): day-5 landed the type: cel transform (Item 4) and the harness loopback trust-CIDR default (Item 5). Reactivation blocks on (1) the test must inject sidecar headers like x-sbproxy-tls-ja4 via get_with_headers so the JA4 actually populates request.tls.ja4, and (2) the day-5 CEL transform writes to the response BODY, not response HEADERS as these tests expect; the tests need to be rewritten to assert against the body."]
fn confidence_halved_when_not_trustworthy() {
    let yaml = r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
    untrusted_client_cidrs:
      - 127.0.0.0/8
  headless_detect:
    enabled: true
origins:
  "headless.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: cel
        on_response: |
          resp.headers["x-headless-confidence"] = request.headless_signal != null
            ? string(request.headless_signal.confidence)
            : "0"
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness.get("/", "headless.localhost").expect("GET");
    let conf: f32 = resp
        .headers
        .get("x-headless-confidence")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);
    assert!(
        (conf - 0.4).abs() < 0.05,
        "confidence must be ~0.4 when trustworthy=false; got {}",
        conf
    );
}

// --- Test 4: headless verdict feeds the agent_class resolver ---

#[test]
#[ignore = "TODO(wave5-G5.4-harness): the resolver-chain hook (`apply_headless_override` in `sbproxy-core/src/agent_class.rs`) is wired and unit-tested; on a `Fallback` verdict it stamps `agent_id = \"headless-{library}\"` and `agent_id_source = TlsFingerprint`. The catalog already has `headless-browser` / `headless-puppeteer` / `headless-playwright` entries. Reactivation blocks on the same sidecar-header harness path + `type: cel` transform as the rest of the headless suite."]
fn headless_verdict_resolves_to_headless_browser_class() {
    let yaml = r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
    trustworthy_client_cidrs:
      - 127.0.0.0/8
  headless_detect:
    enabled: true
origins:
  "headless.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: cel
        on_response: |
          resp.headers["x-agent-class"] = request.agent_class
          resp.headers["x-agent-source"] = request.agent_id_source
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness.get("/", "headless.localhost").expect("GET");
    assert_eq!(
        resp.headers.get("x-agent-class").map(String::as_str),
        Some("headless-browser"),
        "Puppeteer JA4 with no higher-confidence resolver match must produce agent_class = headless-browser"
    );
    assert_eq!(
        resp.headers.get("x-agent-source").map(String::as_str),
        Some("tls_fingerprint"),
        "agent_id_source must be tls_fingerprint when the resolver chose the A5.1 advisory step"
    );
}

// --- Test 5: detector is no-op when feature is disabled ---

#[test]
#[ignore = "TODO(wave5-G5.4-harness): the headless detector path is gated on the `tls-fingerprint` cargo feature (the wiring lives inside `#[cfg(feature = \"tls-fingerprint\")]` in `request_filter`). The harness binary ships with the feature on, so this test needs a `--no-default-features` harness build alongside the existing one. Same `type: cel` blocker."]
fn headless_detect_disabled_leaves_signal_null() {
    let yaml = r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
    trustworthy_client_cidrs:
      - 127.0.0.0/8
origins:
  "headless.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: cel
        on_response: |
          resp.headers["x-headless"] = request.headless_signal != null ? "detected" : "absent"
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness.get("/", "headless.localhost").expect("GET");
    assert_eq!(
        resp.headers.get("x-headless").map(String::as_str),
        Some("absent"),
        "with `headless_detect` disabled, request.headless_signal must remain null"
    );
}
