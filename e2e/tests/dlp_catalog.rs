//! Data Loss Prevention catalog (F2.14).
//!
//! Block mode rejects requests carrying secrets in the URI or headers
//! with 403; tag mode forwards and stamps `dlp-detection: <names>`
//! on the upstream request via the existing trust-headers path.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

#[test]
fn block_mode_rejects_aws_key_in_query_string() {
    let upstream = MockUpstream::start(json!({"ok": true})).unwrap();
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "api.localhost":
    action:
      type: proxy
      url: "{base}"
    policies:
      - type: dlp
        action: block
        detectors: [aws_access]
"#,
        base = upstream.base_url()
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let resp = harness
        .get("/build?key=AKIAIOSFODNN7EXAMPLE", "api.localhost")
        .expect("send");
    assert_eq!(resp.status, 403);
    assert!(
        upstream.captured().is_empty(),
        "block mode must not forward to upstream",
    );
}

#[test]
fn tag_mode_stamps_detection_header_on_upstream() {
    let upstream = MockUpstream::start(json!({"ok": true})).unwrap();
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "api.localhost":
    action:
      type: proxy
      url: "{base}"
    policies:
      - type: dlp
        action: tag
        detectors: [slack_token]
"#,
        base = upstream.base_url()
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/anything",
            "api.localhost",
            &[("x-notes", "saw xoxb-1234567890-secret-payload")],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
    let captured = upstream.captured();
    assert!(
        !captured.is_empty(),
        "upstream should have seen the request"
    );
    let stamped = captured[0].headers.get("dlp-detection").map(|s| s.as_str());
    assert_eq!(
        stamped,
        Some("slack_token"),
        "expected dlp-detection: slack_token, got headers: {:?}",
        captured[0].headers
    );
}

#[test]
fn clean_request_passes_without_tag() {
    let upstream = MockUpstream::start(json!({"ok": true})).unwrap();
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "api.localhost":
    action:
      type: proxy
      url: "{base}"
    policies:
      - type: dlp
        action: tag
        detectors: [aws_access, slack_token, github_token]
"#,
        base = upstream.base_url()
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let resp = harness.get("/api/users", "api.localhost").expect("send");
    assert_eq!(resp.status, 200);
    let captured = upstream.captured();
    assert!(
        !captured[0].headers.contains_key("dlp-detection"),
        "clean request must not see the tag header"
    );
}
