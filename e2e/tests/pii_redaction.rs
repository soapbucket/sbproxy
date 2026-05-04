//! Pattern-aware PII redaction at the AI request boundary.
//!
//! Mirrors `examples/97-pii-redaction/sb.yml`: with `pii.enabled:
//! true` on an `ai_proxy` origin, well-known PII shapes (email,
//! credit card, SSN, OpenAI/Anthropic key prefixes) are stripped
//! from the JSON request body before the proxy forwards it to the
//! upstream provider.
//!
//! We assert the contract directly by spinning up a `MockUpstream`
//! that captures the forwarded body and grepping for the
//! sentinels.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn build_config(upstream_base: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0  # overridden by the harness
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: "stub-key"
          base_url: "{upstream_base}"
      routing:
        strategy: round_robin
      pii:
        enabled: true
        defaults: true
        redact_request: true
        redact_response: false
"#
    )
}

#[test]
fn email_and_card_are_redacted_before_forwarding() {
    let upstream = MockUpstream::start(json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop"
        }]
    }))
    .expect("start mock");

    let yaml = build_config(&upstream.base_url());
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let body = json!({
        "model": "gpt-4o",
        "messages": [{
            "role": "user",
            "content": "Email me at alice@example.com about card 4111-1111-1111-1111"
        }]
    });
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .expect("post");
    assert_eq!(resp.status, 200, "proxy should forward and 200 back");

    let captured = upstream.captured();
    assert!(
        !captured.is_empty(),
        "upstream should have seen the request"
    );
    let forwarded =
        String::from_utf8(captured[0].body.clone()).expect("forwarded body should be utf8");

    assert!(
        !forwarded.contains("alice@example.com"),
        "raw email leaked to upstream: {}",
        forwarded
    );
    assert!(
        !forwarded.contains("4111-1111-1111-1111"),
        "raw card leaked to upstream: {}",
        forwarded
    );
    assert!(
        forwarded.contains("[REDACTED:EMAIL]"),
        "expected EMAIL sentinel in: {}",
        forwarded
    );
    assert!(
        forwarded.contains("[REDACTED:CARD]"),
        "expected CARD sentinel in: {}",
        forwarded
    );
}

#[test]
fn anthropic_key_shape_is_redacted() {
    let upstream = MockUpstream::start(json!({"id": "x", "choices": []})).unwrap();
    let yaml = build_config(&upstream.base_url());
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let body = json!({
        "model": "gpt-4o",
        "messages": [{
            "role": "user",
            "content": "my key is sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-foo"
        }]
    });
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .expect("post");
    assert_eq!(resp.status, 200);

    let captured = upstream.captured();
    let forwarded = String::from_utf8(captured[0].body.clone()).unwrap();
    assert!(
        !forwarded.contains("sk-ant-api03-AAAAAAA"),
        "anthropic key shape leaked: {}",
        forwarded
    );
}
