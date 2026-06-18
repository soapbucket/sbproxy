//! Wave 5 / Q5.3: headless-browser detection in
//! `sbproxy-security/headless_detect.rs`.
//!
//! Pins the contract from  § "Worked
//! example: headless Puppeteer detection". The detector reads
//! `request.tls_fingerprint.ja4` and consults the reference catalogue at
//! `crates/sbproxy-classifiers/data/tls-fingerprints.json`. A match
//! produces `HeadlessSignal::Detected { library, confidence }` and feeds
//! the G1.4 resolver chain so a headless agent class lands on the
//! request context.
//!
//! The active tests use trusted sidecar JA4 injection because the e2e
//! harness is plaintext. Native TLS ClientHello coverage is tracked by
//! WOR-1444.

use sbproxy_e2e::ProxyHarness;

const PUPPETEER_JA4: &str = "t13d1516h2_8daaf6152771_b1ff8ab2d16f";
const UNKNOWN_BROWSER_JA4: &str = "t13d0000h2_000000000000_000000000000";

// --- Test 1: Puppeteer JA4 -> HeadlessSignal::Detected ---

#[test]
fn puppeteer_ja4_detected_with_library_label() {
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
        headers:
          - op: set
            name: x-headless-library
            value_expr: 'request.headless_signal.library'
          - op: set
            name: x-headless-confidence
            value_expr: 'string(request.headless_signal.confidence)'
          - op: set
            name: x-headless-detected
            value_expr: 'request.headless_signal.detected ? "yes" : "no"'
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/",
            "headless.localhost",
            &[("x-sbproxy-tls-ja4", PUPPETEER_JA4)],
        )
        .expect("GET");
    assert_eq!(
        resp.headers.get("x-headless-library").map(String::as_str),
        Some("puppeteer"),
        "Puppeteer JA4 must map to library = puppeteer in the reference catalogue"
    );
    assert_eq!(
        resp.headers.get("x-headless-detected").map(String::as_str),
        Some("yes"),
        "Puppeteer JA4 must set the detected flag"
    );
    let confidence: f32 = resp
        .headers
        .get("x-headless-confidence")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);
    assert!(
        (confidence - 0.95).abs() < 0.001,
        "trustworthy Puppeteer JA4 must keep 0.95 confidence; got {confidence}"
    );
}

// --- Test 2: Generic browser JA4 -> NotDetected ---

#[test]
fn generic_browser_ja4_not_detected() {
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
        headers:
          - op: set
            name: x-headless
            value_expr: 'request.headless_signal.detected ? "detected" : "none"'
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/",
            "headless.localhost",
            &[("x-sbproxy-tls-ja4", UNKNOWN_BROWSER_JA4)],
        )
        .expect("GET");
    assert_eq!(
        resp.headers.get("x-headless").map(String::as_str),
        Some("none"),
        "real Chrome/Firefox/Safari JA4 must NOT match the headless catalogue"
    );
}

// --- Test 3: confidence halved when trustworthy = false ---

#[test]
fn confidence_halved_when_not_trustworthy() {
    let yaml = r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
    untrusted_client_cidrs:
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
        headers:
          - op: set
            name: x-headless-confidence
            value_expr: 'string(request.headless_signal.confidence)'
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/",
            "headless.localhost",
            &[("x-sbproxy-tls-ja4", PUPPETEER_JA4)],
        )
        .expect("GET");
    let conf: f32 = resp
        .headers
        .get("x-headless-confidence")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);
    assert!(
        (conf - 0.475).abs() < 0.001,
        "confidence must be 0.475 when trustworthy=false; got {}",
        conf
    );
}

// --- Test 4: headless verdict feeds the agent_class resolver ---

#[test]
fn headless_verdict_resolves_to_headless_browser_class() {
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
        headers:
          - op: set
            name: x-agent-class
            value_expr: 'request.agent_class'
          - op: set
            name: x-agent-source
            value_expr: 'request.agent_id_source'
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/",
            "headless.localhost",
            &[
                ("x-sbproxy-tls-ja4", PUPPETEER_JA4),
                ("user-agent", "Mozilla/5.0 Chrome/123.0"),
            ],
        )
        .expect("GET");
    assert_eq!(
        resp.headers.get("x-agent-class").map(String::as_str),
        Some("headless-puppeteer"),
        "Puppeteer JA4 with no higher-confidence resolver match must produce agent_class = headless-puppeteer"
    );
    assert_eq!(
        resp.headers.get("x-agent-source").map(String::as_str),
        Some("tls_fingerprint"),
        "agent_id_source must be tls_fingerprint when the resolver chose the A5.1 advisory step"
    );
}

// --- Test 5: detector is no-op when feature is disabled ---

#[test]
#[ignore = "WOR-1445: needs a no-default-features e2e harness binary so the tls-fingerprint-gated headless detector path is genuinely off."]
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
        headers:
          - op: set
            name: x-headless
            value_expr: 'request.headless_signal.detected ? "detected" : "absent"'
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/",
            "headless.localhost",
            &[("x-sbproxy-tls-ja4", PUPPETEER_JA4)],
        )
        .expect("GET");
    assert_eq!(
        resp.headers.get("x-headless").map(String::as_str),
        Some("absent"),
        "with `headless_detect` disabled, request.headless_signal must remain null"
    );
}
