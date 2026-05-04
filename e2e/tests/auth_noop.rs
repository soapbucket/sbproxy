//! No-op authentication.
//!
//! `type: noop` is a documented escape hatch for callers who want to
//! attach a placeholder auth block (often inserted by config tooling)
//! without actually gating traffic. Every request must pass straight
//! through to the upstream regardless of credentials.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn config_yaml(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "open.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    authentication:
      type: noop
"#
    )
}

#[test]
fn request_without_auth_headers_passes_through() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness.get("/anything", "open.localhost").expect("send");
    assert_eq!(
        resp.status, 200,
        "noop must accept unauthenticated traffic, got {}",
        resp.status
    );
    assert!(
        !upstream.captured().is_empty(),
        "request should reach the upstream"
    );
}

#[test]
fn request_with_arbitrary_auth_headers_also_passes() {
    // noop must not "validate" anything; even a deliberately bogus
    // Authorization header does not cause the request to be rejected.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/anything",
            "open.localhost",
            &[("authorization", "Bearer junk-token")],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
}
