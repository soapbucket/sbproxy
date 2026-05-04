//! End-to-end coverage for the `sri` (Subresource Integrity) policy.
//!
//! SRI is observation-only: the policy scans `text/html` responses
//! from the upstream and logs / increments metrics for any external
//! `<script src>` or `<link rel="stylesheet" href>` tag that is
//! missing an `integrity` attribute (or uses a disallowed algorithm).
//! The response body and headers are not modified.
//!
//! These tests confirm three things end-to-end:
//!
//! 1. When SRI is enforced and the upstream HTML is missing
//!    integrity attributes, the response still flows through
//!    intact (no body mutation, no blocking).
//! 2. When SRI is enforced and the upstream HTML has valid
//!    integrity attributes, the response flows through and the
//!    body is unchanged.
//! 3. When the upstream is not HTML, the policy is a no-op even
//!    when enforced.

use sbproxy_e2e::ProxyHarness;

fn config_with_html_body(body: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "sri.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: {body:?}
    policies:
      - type: sri
        enforce: true
        algorithms: [sha256, sha384, sha512]
"#
    )
}

const JSON_CONFIG: &str = r#"
proxy:
  http_bind_port: 0
origins:
  "sri.localhost":
    action:
      type: static
      status_code: 200
      content_type: application/json
      body: '{"hello":"world"}'
    policies:
      - type: sri
        enforce: true
"#;

#[test]
fn html_with_missing_integrity_passes_through_unchanged() {
    let body = r#"<html><body>
<script src="https://cdn.example.com/lib.js"></script>
<link rel="stylesheet" href="https://cdn.example.com/theme.css">
</body></html>"#;
    let harness = ProxyHarness::start_with_yaml(&config_with_html_body(body)).expect("start proxy");

    let resp = harness.get("/", "sri.localhost").expect("send");
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.text().expect("decode body"),
        body,
        "SRI is observation-only and must not mutate the response body"
    );
}

#[test]
fn html_with_valid_integrity_passes_through_unchanged() {
    let body = r#"<html>
<script src="https://cdn.example.com/lib.js"
        integrity="sha384-abcdef"
        crossorigin="anonymous"></script>
</html>"#;
    let harness = ProxyHarness::start_with_yaml(&config_with_html_body(body)).expect("start proxy");

    let resp = harness.get("/", "sri.localhost").expect("send");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.text().expect("decode body"), body);
}

#[test]
fn non_html_response_is_unaffected_by_sri_policy() {
    let harness = ProxyHarness::start_with_yaml(JSON_CONFIG).expect("start proxy");
    let resp = harness.get("/", "sri.localhost").expect("send");
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or(""),
        "application/json"
    );
    assert_eq!(resp.text().expect("decode body"), r#"{"hello":"world"}"#);
}
