//! Regression coverage for GitHub issue #240: `/v1/responses` against a
//! non-OpenAI (Anthropic) upstream.
//!
//! The bug (reported on v1.0.1): a client POST to `/v1/responses` with an
//! Anthropic provider configured was forwarded verbatim to
//! `api.anthropic.com/v1/responses`, which does not exist, returning 404.
//! `/v1/chat/completions` and `/v1/messages` against the same provider
//! worked, so the gap was specific to the Responses surface not being
//! translated for the Anthropic wire format.
//!
//! The contract this pins: a `/v1/responses` request to an Anthropic
//! provider must reach the upstream as Anthropic Messages JSON at
//! `/v1/messages` (never `/v1/responses`, never `/v1/chat/completions`),
//! and the client must get a Responses-shaped reply. The inbound shim
//! translates Responses -> OpenAI Chat, and the Anthropic provider
//! translator then rewrites Chat -> Messages on egress.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

// Single Anthropic-format provider. `name: anthropic` resolves the
// catalog wire format to Anthropic, so the egress translator applies.
fn anthropic_config(upstream_base: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0  # overridden by the harness
origins:
  "claude.localhost":
    action:
      type: ai_proxy
      providers:
        - name: anthropic
          api_key: "stub-key"
          base_url: "{upstream_base}"
          allow_private_base_url: true
      routing:
        strategy: round_robin
"#
    )
}

#[test]
fn responses_endpoint_translates_to_anthropic_messages_not_404() {
    // The upstream is Anthropic-shaped: because the provider speaks the
    // Anthropic wire format, the gateway sends Anthropic Messages JSON and
    // expects an Anthropic Messages reply, which it then maps back to the
    // Responses shape for the client.
    let upstream = MockUpstream::start(json!({
        "id": "msg_abc",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": "hello from anthropic"}],
        "model": "claude-haiku-4-5",
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 9, "output_tokens": 4}
    }))
    .expect("start mock");

    let yaml = anthropic_config(&upstream.base_url());
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    // OpenAI Responses-shaped request (string input, the shape the issue
    // reporter used).
    let body = json!({
        "model": "claude-haiku-4-5",
        "input": "hi",
        "max_output_tokens": 64
    });
    let resp = harness
        .post_json("/v1/responses", "claude.localhost", &body, &[])
        .expect("post /v1/responses");

    // The headline assertion: not a 404. Pre-fix this was Anthropic's
    // not_found_error for /v1/responses.
    assert_eq!(
        resp.status, 200,
        "/v1/responses against an Anthropic provider must be translated, not 404'd; got {}",
        resp.status
    );

    // The upstream must have seen Anthropic Messages at /v1/messages, not
    // the verbatim /v1/responses path that caused the 404.
    let captured = upstream.captured();
    assert!(
        !captured.is_empty(),
        "upstream must have seen the translated request"
    );
    let cap = &captured[0];
    assert_eq!(
        cap.path, "/v1/messages",
        "Anthropic upstream must be hit at /v1/messages, got {}",
        cap.path
    );
    let fwd: serde_json::Value = serde_json::from_slice(&cap.body).expect("forwarded JSON");
    // Anthropic Messages shape: `messages` array + `max_tokens`, and no
    // Responses-only `input` field.
    assert!(
        fwd.get("messages").is_some(),
        "forwarded body must be Anthropic Messages shape (messages array)"
    );
    assert!(
        fwd.get("input").is_none(),
        "forwarded body must not carry the Responses `input` field"
    );

    // The client must get a Responses-shaped reply.
    let text = resp.text().unwrap_or_default();
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("client JSON");
    assert_eq!(
        parsed["object"], "response",
        "client reply must be Responses-shaped"
    );
    assert_eq!(parsed["output"][0]["type"], "message");
    assert_eq!(
        parsed["output"][0]["content"][0]["text"], "hello from anthropic",
        "translated assistant text must round-trip to the Responses output"
    );
}
