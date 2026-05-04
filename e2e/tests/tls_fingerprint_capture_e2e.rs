//! Wave 5 / Q5.2: JA3 / JA4 / JA4H capture in `sbproxy-tls`.
//!
//! These tests pin the TLS-fingerprint capture contract from
//! `docs/adr-tls-fingerprint-pipeline.md` (A5.1) and are activated
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
//! All tests in this file are `#[ignore]`'d with a `TODO(wave5-G5.3)`
//! marker until the capture lands. The fixture YAML is shaped against
//! the schema from `adr-tls-fingerprint-pipeline.md` § "Configuration
//! in sb.yml".

use sbproxy_e2e::ProxyHarness;

// --- Test 1: JA3 capture for a TLS 1.2 ClientHello ---

#[test]
#[ignore = "TODO(wave5-day6+): day-5 landed the `type: cel` transform (Item 4) and the harness loopback trust-CIDR default (Item 5). Reactivation now blocks on (1) the day-5 CEL transform writes to the response BODY, not response HEADERS as this test expects (`resp.headers[...] = ...`); the test needs to be rewritten to assert against the body, and (2) a curl-impersonate-driven harness path that drives a real TLS 1.2 ClientHello (or sidecar-header injection from the harness via `get_with_headers` plus the `features.tls_fingerprint:` config block being threaded onto CompiledPipeline)."]
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
        on_response: |
          resp.headers["x-ja3"] = request.tls.ja3 != null ? request.tls.ja3 : "absent"
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
#[ignore = "TODO(wave5-day6+): day-5 landed the `type: cel` transform (Item 4) and the harness loopback trust-CIDR default (Item 5). Same blockers as `ja3_captured_for_tls12_client`: header-vs-body CEL surface mismatch, plus a TLS 1.3 client path (or sidecar-header injection)."]
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
        on_response: |
          resp.headers["x-ja4"] = request.tls.ja4 != null ? request.tls.ja4 : "absent"
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
#[ignore = "TODO(wave5-day6+): day-5 landed the loopback trust-CIDR default (Item 5) so sidecar `x-sbproxy-tls-ja4` headers are now honoured from 127.0.0.1, AND landed the `type: cel` transform (Item 4). Reactivation blocks on (1) the test must inject `x-sbproxy-tls-ja4` via `get_with_headers` (the test already uses get_with_headers but does not include the sidecar header), and (2) the day-5 CEL transform writes to the response BODY, not headers; the test must rewrite the assertion against the body."]
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
        on_response: |
          resp.headers["x-ja4h"] = request.tls.ja4h != null ? request.tls.ja4h : "absent"
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/",
            "tls-fp.localhost",
            &[
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

// The trustworthy assertion still depends on `features.tls_fingerprint`
// landing on CompiledPipeline (day-6 Item 3 - WATCH). The fixture and
// shape below pin the contract for the follow-up.
#[test]
#[ignore = "TODO(wave5-day6+): the day-6 Item 1 header-mutating CEL surface lands here. The remaining gap is day-6 Item 3: wire `features.tls_fingerprint:` onto CompiledPipeline so request.tls.trustworthy actually populates from the per-origin CIDR config (today the YAML block parses via the pre-process migration but is not threaded to the pipeline)."]
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
            value_expr: 'string(request.tls.trustworthy)'
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness.get("/", "tls-fp.localhost").expect("GET");
    assert_eq!(
        resp.headers.get("x-tls-trust").map(String::as_str),
        Some("true"),
        "127.0.0.1 must match trustworthy_client_cidrs and surface trustworthy=true"
    );
}

// --- Test 5: trustworthy = false when client IP is in a CDN range ---

#[test]
#[ignore = "TODO(wave5-day6+): day-5 landed the `type: cel` transform (Item 4). Reactivation blocks on the `features.tls_fingerprint:` config block being parsed and threaded onto CompiledPipeline (today the YAML field is silently ignored) plus the header-vs-body CEL surface mismatch."]
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
        on_response: |
          resp.headers["x-tls-trust"] = string(request.tls.trustworthy)
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness.get("/", "tls-fp.localhost").expect("GET");
    assert_eq!(
        resp.headers.get("x-tls-trust").map(String::as_str),
        Some("false"),
        "loopback listed under untrusted_client_cidrs must surface trustworthy=false"
    );
}

// --- Test 6: trustworthy defaults to false when no CIDR matches ---

#[test]
#[ignore = "TODO(wave5-day6+): day-5 landed the `type: cel` transform (Item 4). Same blockers as the other CIDR tests: `features.tls_fingerprint:` config plumbing onto CompiledPipeline plus the header-vs-body CEL surface mismatch."]
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
        on_response: |
          resp.headers["x-tls-trust"] = string(request.tls.trustworthy)
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness.get("/", "tls-fp.localhost").expect("GET");
    assert_eq!(
        resp.headers.get("x-tls-trust").map(String::as_str),
        Some("false"),
        "no CIDR match must default to trustworthy=false (conservative default per A5.1)"
    );
}

// --- Test 7: capture is a no-op when the cargo feature is off ---

#[test]
#[ignore = "TODO(wave5-day6+): day-5 landed the `type: cel` transform (Item 4). The harness binary is compiled with the `tls-fingerprint` feature on by default; reactivation blocks on a `--no-default-features` harness build path so this test can observe the noop branch. The header-vs-body CEL surface mismatch also applies."]
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
        on_response: |
          resp.headers["x-ja4"] = request.tls.ja4 != null ? request.tls.ja4 : "absent"
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness.get("/", "tls-fp.localhost").expect("GET");
    assert_eq!(
        resp.headers.get("x-ja4").map(String::as_str),
        Some("absent"),
        "with the tls-fingerprint feature off, request.tls.ja4 must stay null"
    );
}
