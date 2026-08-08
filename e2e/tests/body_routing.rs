//! End-to-end coverage for JSON-body-field `forward_rules` routing.
//!
//! `examples/body-routing/sb.yml` documents the contract: a forward
//! rule matcher entry may carry a `body` matcher that addresses a
//! field of a JSON request body with an RFC 6901 JSON Pointer and
//! compares the resolved value exactly (`value`) or by prefix
//! (`prefix`). The body is buffered (up to a 64 KiB cap) before the
//! route is chosen and replayed upstream byte for byte. A body the
//! matcher cannot read (not JSON, pointer resolves to nothing, over
//! the cap) is a miss, not a failure: the request falls through to
//! the parent origin's own action rather than being rejected.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

#[test]
fn model_field_routes_to_matching_upstream() {
    let gpt = MockUpstream::start(json!({"pool": "gpt"})).expect("gpt upstream");
    let fallback = MockUpstream::start(json!({"pool": "fallback"})).expect("fallback upstream");

    // The parent origin proxies to the fallback upstream; one forward
    // rule dispatches bodies naming gpt-4o to the dedicated pool.
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "llm.localhost":
    action:
      type: proxy
      url: "{}"

    forward_rules:
      - rules:
          - body:
              pointer: /model
              value: gpt-4o
        origin:
          id: gpt-pool
          action:
            type: proxy
            url: "{}"
"#,
        fallback.base_url(),
        gpt.base_url()
    );

    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let matched = proxy
        .post_json("/v1/chat/completions", "llm.localhost", &body, &[])
        .expect("matching request");
    assert_eq!(matched.status, 200);
    assert_eq!(matched.json().expect("matched json")["pool"], "gpt");

    // Route selection buffered the body; the upstream must still
    // receive it intact.
    let captured = gpt.captured();
    assert_eq!(captured.len(), 1, "matching model must hit the gpt pool");
    let forwarded: serde_json::Value =
        serde_json::from_slice(&captured[0].body).expect("forwarded body is intact JSON");
    assert_eq!(forwarded, body, "buffered body must be replayed unchanged");

    // A different model misses the rule and lands on the parent
    // origin's action.
    let other = json!({
        "model": "claude-sonnet-4",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let unmatched = proxy
        .post_json("/v1/chat/completions", "llm.localhost", &other, &[])
        .expect("non-matching request");
    assert_eq!(unmatched.status, 200);
    assert_eq!(
        unmatched.json().expect("unmatched json")["pool"],
        "fallback"
    );

    assert_eq!(
        gpt.captured().len(),
        1,
        "non-matching model must not hit the gpt pool"
    );
    assert_eq!(
        fallback.captured().len(),
        1,
        "non-matching model must fall through to the parent action"
    );
}

#[test]
fn a_body_the_matcher_cannot_read_falls_through_to_the_default() {
    let gpt = MockUpstream::start(json!({"pool": "gpt"})).expect("gpt upstream");

    // Parent origin uses a static action so fall-through returns a
    // deterministic body without a second upstream. The rule matches
    // the gpt- model family by prefix.
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "llm.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "default-action"

    forward_rules:
      - rules:
          - body:
              pointer: /model
              prefix: gpt-
        origin:
          id: gpt-pool
          action:
            type: proxy
            url: "{}"
"#,
        gpt.base_url()
    );

    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    // A prefix hit dispatches to the pool.
    let hit = proxy
        .post_json(
            "/v1/chat/completions",
            "llm.localhost",
            &json!({"model": "gpt-4o-mini"}),
            &[],
        )
        .expect("prefix hit");
    assert_eq!(hit.status, 200);
    assert_eq!(hit.json().expect("hit json")["pool"], "gpt");
    assert_eq!(gpt.captured().len(), 1, "gpt- prefix must dispatch");

    // A body that is not JSON misses without failing the request.
    let not_json = proxy
        .post_bytes(
            "/v1/chat/completions",
            "llm.localhost",
            "text/plain",
            b"model=gpt-4o".to_vec(),
            &[],
        )
        .expect("non-JSON body");
    assert_eq!(not_json.status, 200);
    assert_eq!(not_json.text().unwrap(), "default-action");

    // JSON without the field: the pointer resolves to nothing, same
    // fall-through.
    let missing = proxy
        .post_json(
            "/v1/chat/completions",
            "llm.localhost",
            &json!({"prompt": "hi"}),
            &[],
        )
        .expect("missing field");
    assert_eq!(missing.status, 200);
    assert_eq!(missing.text().unwrap(), "default-action");

    assert_eq!(
        gpt.captured().len(),
        1,
        "only the prefix hit may reach the pool"
    );
}
