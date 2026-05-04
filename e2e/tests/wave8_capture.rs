// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Soap Bucket LLC

//! Wave 8 P0 envelope-capture round-trip tests.
//!
//! Validates the contract documented in `docs/adr-event-envelope.md`,
//! `docs/adr-custom-properties.md`, `docs/adr-session-id.md`, and
//! `docs/adr-user-id.md` against a live proxy spawned by
//! [`sbproxy_e2e::ProxyHarness`].
//!
//! Observable behavior covered today:
//!
//! * `X-Sb-Session-Id` response echo (always when captured or
//!   auto-generated for anonymous traffic).
//! * Anonymous default policy: no caller-supplied session and no
//!   resolved user mints a fresh ULID.
//! * Authenticated traffic (caller-supplied `X-Sb-User-Id`) does NOT
//!   trigger session auto-generation when the policy is `anonymous`.
//! * Caller-supplied valid session IDs survive the round trip.
//! * Caller-supplied custom-property and parent-session headers do not
//!   break the request path.
//!
//! Auto-publishing of `X-Sb-User-Id` echo, properties echo, and the
//! enterprise ingest pipeline transport are explicit follow-up slices
//! and are not covered here.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn config_yaml(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "api.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
"#
    )
}

fn is_valid_ulid(s: &str) -> bool {
    s.len() == 26 && ulid::Ulid::from_string(s).is_ok()
}

#[test]
fn anonymous_request_gets_auto_generated_session_id() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness.get("/anything", "api.localhost").expect("send");
    assert_eq!(resp.status, 200);

    // Anonymous default policy auto-generates a session ID and echoes
    // it on the response so stateless SDK callers can adopt it.
    let echoed = resp
        .headers
        .get("x-sb-session-id")
        .expect("response must echo X-Sb-Session-Id for anonymous traffic");
    assert!(
        is_valid_ulid(echoed),
        "auto-generated session must be a 26-char ULID, got {echoed:?}"
    );
}

#[test]
fn caller_supplied_session_id_survives_round_trip() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let supplied = ulid::Ulid::new().to_string();
    let resp = harness
        .get_with_headers(
            "/anything",
            "api.localhost",
            &[("X-Sb-Session-Id", supplied.as_str())],
        )
        .expect("send");
    assert_eq!(resp.status, 200);

    let echoed = resp
        .headers
        .get("x-sb-session-id")
        .expect("response must echo the caller-supplied session id");
    assert_eq!(
        echoed, &supplied,
        "auto-generation must never overwrite a valid caller-supplied ULID"
    );
}

#[test]
fn invalid_session_id_drops_then_auto_generates_fresh() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/anything",
            "api.localhost",
            &[("X-Sb-Session-Id", "not-a-valid-ulid")],
        )
        .expect("send");
    assert_eq!(resp.status, 200);

    let echoed = resp
        .headers
        .get("x-sb-session-id")
        .expect("anonymous default must auto-generate after dropping the bad header");
    assert!(
        is_valid_ulid(echoed),
        "fallback must be a fresh ULID, got {echoed:?}"
    );
    assert_ne!(
        echoed, "not-a-valid-ulid",
        "the proxy must not echo the invalid input"
    );
}

#[test]
fn authenticated_request_does_not_auto_generate_session() {
    // The default sessions.auto_generate policy is `anonymous`: the
    // proxy mints a session only when no end-user identity has been
    // resolved. Supplying X-Sb-User-Id flips that signal and the
    // response should NOT carry an X-Sb-Session-Id echo.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers("/anything", "api.localhost", &[("X-Sb-User-Id", "user_42")])
        .expect("send");
    assert_eq!(resp.status, 200);
    assert!(
        !resp.headers.contains_key("x-sb-session-id"),
        "authenticated traffic must not auto-generate sessions, got {:?}",
        resp.headers.get("x-sb-session-id")
    );
}

#[test]
fn parent_session_header_does_not_break_request() {
    // Parent linkage is captured but not echoed today (the portal
    // reconstructs trees client-side). This test pins regression
    // coverage that the header is at least accepted.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let parent = ulid::Ulid::new().to_string();
    let resp = harness
        .get_with_headers(
            "/anything",
            "api.localhost",
            &[("X-Sb-Parent-Session-Id", parent.as_str())],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
}

#[test]
fn custom_property_headers_do_not_break_request() {
    // Properties capture is internal; today there is no opt-in echo
    // (T1.3 lands once PropertiesConfig is plumbed through sb.yml).
    // This test just pins regression coverage that the proxy accepts
    // the headers and continues serving 200s.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/anything",
            "api.localhost",
            &[
                ("X-Sb-Property-Environment", "prod"),
                ("X-Sb-Property-Customer-Tier", "enterprise"),
                ("X-Sb-Property-Feature-Flag", "agent-v2"),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
    assert!(
        !upstream.captured().is_empty(),
        "request must reach the upstream; properties capture must not short-circuit"
    );
}

#[test]
fn many_property_headers_stay_under_caps() {
    // The per-request property cap is 20 (MAX_PROPERTIES_PER_REQUEST).
    // Sending more than that must drop the extras silently rather than
    // 4xx the request.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let mut headers: Vec<(String, String)> = Vec::new();
    for i in 0..30u32 {
        headers.push((format!("X-Sb-Property-K{i}"), "v".to_string()));
    }
    let header_refs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let resp = harness
        .get_with_headers("/anything", "api.localhost", &header_refs)
        .expect("send");
    assert_eq!(
        resp.status, 200,
        "property cap overflow must drop silently, not error"
    );
}
