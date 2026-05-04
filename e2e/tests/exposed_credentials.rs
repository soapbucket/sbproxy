//! Exposed Credentials Check (F2.13).
//!
//! The static-list provider hashes the request's Basic-auth
//! password and looks it up in the configured set. Tag mode stamps
//! `exposed-credential-check: leaked-password` on the upstream
//! request; block mode returns 403.

use base64::Engine;
use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn basic_auth(user: &str, password: &str) -> String {
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
    format!("Basic {token}")
}

#[test]
fn known_password_tags_upstream_request() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
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
      - type: exposed_credentials
        action: tag
        passwords:
          - hunter2
"#,
        base = upstream.base_url()
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/anything",
            "api.localhost",
            &[("authorization", &basic_auth("alice", "hunter2"))],
        )
        .expect("send");
    assert_eq!(resp.status, 200);

    let captured = upstream.captured();
    assert!(
        !captured.is_empty(),
        "upstream should have seen the request"
    );
    let stamped = captured[0]
        .headers
        .get("exposed-credential-check")
        .map(|s| s.as_str());
    assert_eq!(
        stamped,
        Some("leaked-password"),
        "upstream should see the tag header, got headers: {:?}",
        captured[0].headers
    );
}

#[test]
fn unknown_password_does_not_tag() {
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
      - type: exposed_credentials
        action: tag
        passwords:
          - hunter2
"#,
        base = upstream.base_url()
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/anything",
            "api.localhost",
            &[("authorization", &basic_auth("alice", "this-is-fine"))],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
    let captured = upstream.captured();
    assert!(
        !captured[0].headers.contains_key("exposed-credential-check"),
        "upstream must not see the tag header for a clean password"
    );
}

#[test]
fn block_action_rejects_with_403() {
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
      - type: exposed_credentials
        action: block
        passwords:
          - hunter2
"#,
        base = upstream.base_url()
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/anything",
            "api.localhost",
            &[("authorization", &basic_auth("alice", "hunter2"))],
        )
        .expect("send");
    assert_eq!(resp.status, 403);
    assert!(
        upstream.captured().is_empty(),
        "block action must not forward the request to the upstream"
    );
}
