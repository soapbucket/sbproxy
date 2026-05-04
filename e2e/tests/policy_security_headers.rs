//! End-to-end coverage for the `security_headers` policy.
//!
//! Exercises the documented behaviour from
//! `examples/33-security-headers/sb.yml`:
//!
//! - Configured headers (HSTS, X-Frame-Options, ...) appear on every
//!   response.
//! - When the CSP block sets `enable_nonce: true`, every response
//!   carries a fresh `'nonce-...'` token in the policy and an
//!   `X-CSP-Nonce` header. Two consecutive requests must observe
//!   distinct nonces.
//! - When the CSP block sets `report_only: true`, the response
//!   carries `Content-Security-Policy-Report-Only` and NOT
//!   `Content-Security-Policy`.
//!
//! The headers are appended in `response_filter`, which only runs on
//! the proxy flow (static actions short-circuit before that), so we
//! pair every test with a `MockUpstream`.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn yaml_with_static_headers(upstream_base: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "sec.localhost":
    action:
      type: proxy
      url: "{base}"
    policies:
      - type: security_headers
        headers:
          - name: Strict-Transport-Security
            value: "max-age=31536000; includeSubDomains; preload"
          - name: X-Frame-Options
            value: DENY
          - name: X-Content-Type-Options
            value: nosniff
          - name: Referrer-Policy
            value: strict-origin-when-cross-origin
          - name: Permissions-Policy
            value: "camera=(), microphone=(), geolocation=()"
"#,
        base = upstream_base,
    )
}

fn yaml_with_csp_nonce(upstream_base: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "sec.localhost":
    action:
      type: proxy
      url: "{base}"
    policies:
      - type: security_headers
        content_security_policy:
          policy: "default-src 'self'; script-src 'self'; style-src 'self'"
          enable_nonce: true
          report_only: false
"#,
        base = upstream_base,
    )
}

fn yaml_with_csp_report_only(upstream_base: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "sec.localhost":
    action:
      type: proxy
      url: "{base}"
    policies:
      - type: security_headers
        content_security_policy:
          policy: "default-src 'self'"
          enable_nonce: true
          report_only: true
"#,
        base = upstream_base,
    )
}

#[test]
fn static_security_headers_are_emitted_on_every_response() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&yaml_with_static_headers(&upstream.base_url()))
        .expect("start proxy");

    let resp = harness.get("/", "sec.localhost").expect("GET");
    assert_eq!(resp.status, 200);

    let hsts = resp
        .headers
        .get("strict-transport-security")
        .expect("HSTS must appear");
    assert!(
        hsts.contains("max-age=31536000"),
        "HSTS must carry configured max-age; got: {hsts}"
    );

    assert_eq!(
        resp.headers.get("x-frame-options").map(String::as_str),
        Some("DENY"),
        "X-Frame-Options must equal configured DENY"
    );
    assert_eq!(
        resp.headers
            .get("x-content-type-options")
            .map(String::as_str),
        Some("nosniff")
    );
    assert_eq!(
        resp.headers.get("referrer-policy").map(String::as_str),
        Some("strict-origin-when-cross-origin")
    );
}

#[test]
fn csp_nonce_changes_per_request() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&yaml_with_csp_nonce(&upstream.base_url()))
        .expect("start proxy");

    let r1 = harness.get("/", "sec.localhost").expect("first request");
    let r2 = harness.get("/", "sec.localhost").expect("second request");
    assert_eq!(r1.status, 200);
    assert_eq!(r2.status, 200);

    let csp1 = r1
        .headers
        .get("content-security-policy")
        .expect("CSP header on first response");
    let csp2 = r2
        .headers
        .get("content-security-policy")
        .expect("CSP header on second response");
    assert!(
        csp1.contains("'nonce-"),
        "CSP must carry a 'nonce-...' token; got: {csp1}"
    );
    assert!(
        csp2.contains("'nonce-"),
        "CSP must carry a 'nonce-...' token; got: {csp2}"
    );
    assert_ne!(
        csp1, csp2,
        "CSP nonce must change per request; both responses returned identical headers"
    );

    // The proxy also exposes the raw nonce as `X-CSP-Nonce`.
    let n1 = r1.headers.get("x-csp-nonce").expect("X-CSP-Nonce on r1");
    let n2 = r2.headers.get("x-csp-nonce").expect("X-CSP-Nonce on r2");
    assert_ne!(n1, n2, "X-CSP-Nonce must change per request");
}

#[test]
fn csp_report_only_emits_report_only_header_only() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&yaml_with_csp_report_only(&upstream.base_url()))
        .expect("start proxy");

    let resp = harness.get("/", "sec.localhost").expect("GET");
    assert_eq!(resp.status, 200);

    assert!(
        resp.headers
            .contains_key("content-security-policy-report-only"),
        "report_only=true must emit Content-Security-Policy-Report-Only"
    );
    assert!(
        !resp.headers.contains_key("content-security-policy"),
        "report_only=true must NOT also emit the enforcing Content-Security-Policy header"
    );
}
