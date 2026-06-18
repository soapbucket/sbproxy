//! Wave 5 / Q5.2: JA3 / JA4 / JA4H capture in `sbproxy-tls`.
//!
//! These tests pin the TLS-fingerprint capture contract from
//!  (A5.1) and are activated
//! when the G5.3 lane (`wave5/G5.3-tls-fingerprint-capture`) merges
//! the capture point in `crates/sbproxy-tls/`.
//!
//! Contract under test:
//!
//! - JA3 captured for TLS 1.2 ClientHello (32-char hex MD5).
//! - JA4 captured for TLS 1.3 ClientHello (FoxIO structured prefix
//!   + 12-char SHA-256 truncation).
//! - JA4H populated mid-pipeline once headers are read (header-order
//!   fingerprint independent of TLS).
//! - `trustworthy = true` when `client_ip` falls in
//!   `features.tls_fingerprint.trustworthy_client_cidrs`; `false` when
//!   the request arrives via a CDN range listed in
//!   `untrusted_client_cidrs`; `false` (conservative) on no match.
//! - Capture is a no-op when the `tls-fingerprint` cargo feature is
//!   disabled (the field stays `None`, no parse-and-hash work runs).
//!
//! Surface assertions: tests stamp the captured fingerprint into a
//! response header via a CEL transform that reads
//! `request.tls.ja4` / `request.tls.trustworthy` so the value is
//! observable from the harness without reaching into proxy internals.
//!
//! The sidecar-backed tests run against the default harness. Native TLS
//! ClientHello capture and disabled-feature coverage remain ignored with
//! follow-up Linear issues because they need dedicated harness paths.

use sbproxy_e2e::ProxyHarness;

// --- Test 1: JA3 capture for a TLS 1.2 ClientHello ---

#[test]
#[ignore = "WOR-1444: needs a real TLS 1.2 ClientHello e2e client path; trusted sidecar injection validates request.tls plumbing but cannot prove native JA3 capture."]
fn ja3_captured_for_tls12_client() {
    let yaml = r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
    trustworthy_client_cidrs:
      - 127.0.0.1/32
origins:
  "tls-fp.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: cel
        headers:
          - op: set
            name: x-ja3
            value_expr: 'size(request.tls.ja3) > 0 ? request.tls.ja3 : "absent"'
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    // The harness uses plaintext HTTP, so this assertion is a
    // placeholder until a TLS 1.2 client path is wired in. Once
    // G5.3 lands we expect a 32-char hex string here.
    let resp = harness.get("/", "tls-fp.localhost").expect("GET");
    let ja3 = resp.headers.get("x-ja3").map(String::as_str).unwrap_or("");
    assert!(
        ja3.len() == 32 && ja3.chars().all(|c| c.is_ascii_hexdigit()),
        "expected 32-char hex JA3; got {:?}",
        ja3
    );
}

// --- Test 2: JA4 capture for a TLS 1.3 ClientHello ---

#[test]
#[ignore = "WOR-1444: needs a real TLS 1.3 ClientHello e2e client path; trusted sidecar injection validates request.tls plumbing but cannot prove native JA4 capture."]
fn ja4_captured_for_tls13_client() {
    let yaml = r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
    trustworthy_client_cidrs:
      - 127.0.0.1/32
origins:
  "tls-fp.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: cel
        headers:
          - op: set
            name: x-ja4
            value_expr: 'size(request.tls.ja4) > 0 ? request.tls.ja4 : "absent"'
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness.get("/", "tls-fp.localhost").expect("GET");
    let ja4 = resp.headers.get("x-ja4").map(String::as_str).unwrap_or("");
    // FoxIO JA4 = 10-char prefix + `_` + 12-char hex hash.
    assert!(
        ja4.len() == 23 && ja4.as_bytes()[10] == b'_',
        "expected JA4 with 10-char prefix + _ + 12-char hash; got {:?}",
        ja4
    );
}

// --- Test 3: JA4H populated mid-pipeline once headers land ---

#[test]
fn ja4h_captured_mid_pipeline() {
    let yaml = r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
    trustworthy_client_cidrs:
      - 127.0.0.1/32
origins:
  "tls-fp.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: cel
        headers:
          - op: set
            name: x-ja4h
            value_expr: 'size(request.tls.ja4h) > 0 ? request.tls.ja4h : "absent"'
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/",
            "tls-fp.localhost",
            &[
                ("x-sbproxy-tls-ja4", "t13d1516h2_8daaf6152771_b1ff8ab2d16f"),
                ("user-agent", "Mozilla/5.0 (test)"),
                ("accept", "text/plain"),
                ("accept-language", "en-US"),
            ],
        )
        .expect("GET");
    let ja4h = resp.headers.get("x-ja4h").map(String::as_str).unwrap_or("");
    // FoxIO JA4H is a 12-char hex truncation of SHA-256.
    assert!(
        ja4h.len() == 12 && ja4h.chars().all(|c| c.is_ascii_hexdigit()),
        "expected 12-char hex JA4H; got {:?}",
        ja4h
    );
}

// --- Test 4: trustworthy = true when client IP is in the trust list ---

// Smoke test for the day-6 Item 1 header-mutating CEL transform: the
// CEL `headers:` array runs at response_filter time and stamps a
// constant header onto the static response. The full
// `request.tls.trustworthy` plumbing depends on the day-6 Item 3
// TlsFingerprintConfig wiring landing in CompiledPipeline; this test
// exercises only the header-mutating surface so subsequent
// reactivations can layer on top.
#[test]
fn cel_header_transform_stamps_static_response() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "tls-fp.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: cel
        headers:
          - op: set
            name: x-cel-set
            value_expr: '"set-from-cel"'
          - op: set
            name: x-status
            value_expr: 'string(response.status)'
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness.get("/", "tls-fp.localhost").expect("GET");
    assert_eq!(
        resp.headers.get("x-cel-set").map(String::as_str),
        Some("set-from-cel"),
        "CEL header transform must stamp the literal value onto the response",
    );
    assert_eq!(
        resp.headers.get("x-status").map(String::as_str),
        Some("200"),
        "CEL header transform must read response.status",
    );
}

// WOR-1128: `features.tls_fingerprint:` is threaded onto
// CompiledPipeline (TlsFingerprintConfig::from_extensions) and the
// header-mutating CEL surface now sees `request.tls.*` (the per-request
// view is passed into evaluate_headers_lossy_with_tls). These tests
// drive the full path: a trusted loopback sidecar supplies
// `x-sbproxy-tls-ja4` so capture fires, the per-origin CIDR config
// decides `trustworthy`, and a `headers:` CEL rule stamps the verdict
// onto the response for assertion. The harness marks loopback trusted
// by default, so the sidecar header survives the trust-boundary strip.
#[test]
fn trustworthy_true_for_direct_client_cidr() {
    let yaml = r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
    trustworthy_client_cidrs:
      - 127.0.0.0/8
origins:
  "tls-fp.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: cel
        headers:
          - op: set
            name: x-tls-trust
            value_expr: 'request.tls.trustworthy ? "yes" : "no"'
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/",
            "tls-fp.localhost",
            &[("x-sbproxy-tls-ja4", "t13d1516h2_8daaf6152771_b186095e22b6")],
        )
        .expect("GET");
    assert_eq!(
        resp.headers.get("x-tls-trust").map(String::as_str),
        Some("yes"),
        "127.0.0.1 must match trustworthy_client_cidrs and surface trustworthy=true"
    );
}

// --- Test 5: trustworthy = false when client IP is in a CDN range ---

#[test]
fn trustworthy_false_behind_cdn_range() {
    let yaml = r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
    trustworthy_client_cidrs:
      - 203.0.113.0/24
    untrusted_client_cidrs:
      - 127.0.0.0/8
origins:
  "tls-fp.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: cel
        headers:
          - op: set
            name: x-tls-trust
            value_expr: 'request.tls.trustworthy ? "yes" : "no"'
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/",
            "tls-fp.localhost",
            &[("x-sbproxy-tls-ja4", "t13d1516h2_8daaf6152771_b186095e22b6")],
        )
        .expect("GET");
    assert_eq!(
        resp.headers.get("x-tls-trust").map(String::as_str),
        Some("no"),
        "loopback listed under untrusted_client_cidrs must surface trustworthy=false"
    );
}

// --- Test 6: trustworthy defaults to false when no CIDR matches ---

#[test]
fn trustworthy_defaults_false_when_no_cidr_match() {
    let yaml = r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
    trustworthy_client_cidrs:
      - 203.0.113.0/24
origins:
  "tls-fp.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: cel
        headers:
          - op: set
            name: x-tls-trust
            value_expr: 'request.tls.trustworthy ? "yes" : "no"'
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/",
            "tls-fp.localhost",
            &[("x-sbproxy-tls-ja4", "t13d1516h2_8daaf6152771_b186095e22b6")],
        )
        .expect("GET");
    assert_eq!(
        resp.headers.get("x-tls-trust").map(String::as_str),
        Some("no"),
        "no CIDR match must default to trustworthy=false (conservative default per A5.1)"
    );
}

// --- Test 7: capture is a no-op when the cargo feature is off ---

#[test]
#[ignore = "WOR-1445: needs a no-default-features e2e harness binary so the tls-fingerprint cargo feature is genuinely off."]
fn capture_noop_when_feature_disabled() {
    let yaml = r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
origins:
  "tls-fp.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: cel
        headers:
          - op: set
            name: x-ja4
            value_expr: 'request.tls.ja4'
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/",
            "tls-fp.localhost",
            &[("x-sbproxy-tls-ja4", "t13d1516h2_8daaf6152771_b1ff8ab2d16f")],
        )
        .expect("GET");
    assert_eq!(
        resp.headers.get("x-ja4").map(String::as_str),
        None,
        "with the tls-fingerprint feature off, request.tls.ja4 must not be exposed"
    );
}
