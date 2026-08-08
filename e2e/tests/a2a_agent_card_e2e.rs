//! Configured A2A agent-card serving (WOR-2315).
//!
//! Verifies the proxy serves an operator-configured `agent_card` at
//! the A2A discovery paths (`/.well-known/agent-card.json` per
//! ratified A2A 1.0, plus the pre-1.0 `/.well-known/agent.json` and
//! `/agent-card.json` aliases) without touching the upstream, that
//! the served card advertises the proxy's own hostname rather than
//! the upstream URL the operator pasted, and that an `a2a` origin
//! without a configured card still proxies the discovery paths
//! through to the upstream unchanged.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

/// Two `a2a` origins in front of the same mock upstream: one with a
/// configured card (whose `url` deliberately points at the upstream
/// placeholder host), one without.
fn config(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "card.localhost":
    action:
      type: a2a
      url: "{upstream_url}"
      agent_card:
        name: "Reservation assistant"
        description: "Books and modifies restaurant reservations."
        version: "0.3.0"
        url: "https://test.sbproxy.dev/"
        capabilities:
          streaming: true
        defaultInputModes:
          - "application/json"
        defaultOutputModes:
          - "application/json"
  "bare.localhost":
    action:
      type: a2a
      url: "{upstream_url}"
"#
    )
}

/// The three discovery paths the gateway serves a configured card at.
const CARD_PATHS: [&str; 3] = [
    "/.well-known/agent-card.json",
    "/.well-known/agent.json",
    "/agent-card.json",
];

#[test]
fn configured_card_is_served_at_the_spec_path() {
    let upstream = MockUpstream::start(json!({"upstream": true})).expect("start upstream");
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.base_url())).expect("start");

    let resp = harness
        .get("/.well-known/agent-card.json", "card.localhost")
        .expect("send");
    assert_eq!(resp.status, 200);
    let ct = resp
        .headers
        .get("content-type")
        .cloned()
        .unwrap_or_default();
    assert!(ct.contains("application/json"), "unexpected ct: {ct}");
    let len = resp
        .headers
        .get("content-length")
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        len.parse::<usize>().expect("numeric content-length"),
        resp.body.len(),
        "content-length must match the served body"
    );

    let card: serde_json::Value = serde_json::from_slice(&resp.body).expect("valid JSON");
    assert_eq!(card["name"], "Reservation assistant");
    assert_eq!(card["capabilities"]["streaming"], true);
    // URL self-consistency: the configured card's url pointed at the
    // upstream placeholder host; the served card must advertise the
    // hostname the client called the proxy on.
    assert_eq!(card["url"], "https://card.localhost/");

    // Gateway-served means served: the upstream saw nothing.
    assert!(
        upstream.captured().is_empty(),
        "the discovery request must not reach the upstream"
    );
}

#[test]
fn alias_paths_serve_the_same_card() {
    let upstream = MockUpstream::start(json!({"upstream": true})).expect("start upstream");
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.base_url())).expect("start");

    for path in CARD_PATHS {
        let resp = harness.get(path, "card.localhost").expect("send");
        assert_eq!(resp.status, 200, "path {path} must serve the card");
        let card: serde_json::Value = serde_json::from_slice(&resp.body).expect("valid JSON");
        assert_eq!(card["name"], "Reservation assistant", "path {path}");
        assert_eq!(card["url"], "https://card.localhost/", "path {path}");
    }
    assert!(upstream.captured().is_empty());
}

#[test]
fn origin_without_card_proxies_through() {
    let upstream = MockUpstream::start(json!({"upstream": true})).expect("start upstream");
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.base_url())).expect("start");

    let resp = harness
        .get("/.well-known/agent-card.json", "bare.localhost")
        .expect("send");
    // No configured card: the path proxies to the upstream like any
    // other request (no behavior change for unconfigured origins).
    assert_eq!(resp.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&resp.body).expect("valid JSON");
    assert_eq!(body["upstream"], true, "expected the upstream's reply");
    let captured = upstream.captured();
    assert_eq!(captured.len(), 1, "the upstream must see the request");
    assert_eq!(captured[0].path, "/.well-known/agent-card.json");
}

#[test]
fn non_get_falls_through_to_the_upstream() {
    let upstream = MockUpstream::start(json!({"upstream": true})).expect("start upstream");
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.base_url())).expect("start");

    let resp = harness
        .post_json(
            "/.well-known/agent-card.json",
            "card.localhost",
            &json!({}),
            &[],
        )
        .expect("send");
    // Card serving is GET-only; other methods keep pre-existing
    // proxy behavior even on an origin with a configured card.
    assert_eq!(resp.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&resp.body).expect("valid JSON");
    assert_eq!(body["upstream"], true, "expected the upstream's reply");
    assert_eq!(upstream.captured().len(), 1);
}
