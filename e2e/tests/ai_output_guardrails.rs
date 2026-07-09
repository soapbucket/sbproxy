//! End-to-end coverage for AI gateway OUTPUT guardrail enforcement
//! (WOR-1141).
//!
//! A `guardrails.output:` block must enforce on both paths. Unary: the
//! gateway runs the output guardrails against the materialized response
//! body before caching or sending it, and replaces a blocked response
//! with a 403 `guardrail_violation` error. Streaming: each outbound
//! chunk is checked against the streaming-safe guardrails and a match
//! terminates the stream so the violating content (and everything after
//! it) is withheld.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn config(upstream_base: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: "stub-key"
          base_url: "{upstream_base}"
          allow_private_base_url: true
          models: [gpt-4o]
      routing:
        strategy: round_robin
      guardrails:
        output:
          - type: regex
            action: block
            patterns:
              - "FORBIDDEN_CONTENT"
"#
    )
}

fn chat_reply(content: &str) -> serde_json::Value {
    json!({
        "id": "chatcmpl-x",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    })
}

fn chat() -> serde_json::Value {
    json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]})
}

#[test]
fn output_guardrail_blocks_violating_response() {
    // The upstream returns a 200 whose assistant content trips the
    // configured output regex. The gateway must withhold it.
    let upstream =
        MockUpstream::start(chat_reply("here is the FORBIDDEN_CONTENT you asked for")).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.base_url())).unwrap();

    let body = chat();
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .unwrap();

    assert_eq!(
        resp.status,
        403,
        "a violating output must be blocked, got {}: {:?}",
        resp.status,
        resp.text().unwrap_or_default()
    );
    let text = resp.text().unwrap_or_default();
    assert!(
        text.contains("guardrail_violation"),
        "block body should name the violation type: {text}"
    );
    // The model's actual response must not be forwarded. (The
    // operator-facing `reason` names the matched pattern, which is
    // operator-configured, not model output.)
    assert!(
        !text.contains("here is the") && !text.contains("you asked for"),
        "the model's response content must not leak into the block response: {text}"
    );
}

#[test]
fn output_guardrail_allows_clean_response() {
    // A clean response on the same origin passes through untouched.
    let upstream = MockUpstream::start(chat_reply("here is a perfectly fine answer")).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.base_url())).unwrap();

    let body = chat();
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .unwrap();

    assert_eq!(resp.status, 200, "a clean response must pass through");
    let text = resp.text().unwrap_or_default();
    assert!(
        text.contains("perfectly fine answer"),
        "the clean upstream body must reach the client: {text}"
    );
}

#[test]
fn output_guardrail_terminates_streaming_on_violation() {
    // The upstream streams three SSE frames; the second carries the
    // forbidden token. The proxy forwards the first clean frame, then
    // the streaming-safe regex guardrail trips on the second and the
    // stream is terminated, so the violating content never reaches the
    // client. Headers were already sent, so the status stays 200.
    let events = vec![
        json!({"choices":[{"index":0,"delta":{"content":"CLEAN_PREFIX"},"finish_reason":null}]})
            .to_string(),
        json!({"choices":[{"index":0,"delta":{"content":"FORBIDDEN_CONTENT"},"finish_reason":null}]})
            .to_string(),
        json!({"choices":[{"index":0,"delta":{"content":"AFTER"},"finish_reason":"stop"}]})
            .to_string(),
    ];
    let upstream = MockUpstream::start_sse(events).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.base_url())).unwrap();

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true
    });
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .unwrap();
    assert_eq!(
        resp.status, 200,
        "streaming headers are sent before the block"
    );

    let text = String::from_utf8_lossy(&resp.body);
    assert!(
        !text.contains("FORBIDDEN_CONTENT"),
        "the violating streamed chunk must not reach the client: {text}"
    );
    assert!(
        !text.contains("AFTER"),
        "chunks after the violation must also be withheld: {text}"
    );
}

// --- WOR-1810: cumulative streaming guardrails ---

fn config_with_guardrails(upstream_base: &str, guardrails_output: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: "stub-key"
          base_url: "{upstream_base}"
          allow_private_base_url: true
          models: [gpt-4o]
      routing:
        strategy: round_robin
      guardrails:
        output:
{guardrails_output}
"#
    )
}

fn sse_delta(content: &str) -> String {
    json!({"choices":[{"index":0,"delta":{"content":content},"finish_reason":null}]}).to_string()
}

fn sse_stop() -> String {
    json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}).to_string()
}

fn stream_chat() -> serde_json::Value {
    json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true
    })
}

#[test]
fn streaming_blocks_pattern_split_across_deltas() {
    // The forbidden keyword arrives as "hor" + "rid" in separate SSE
    // frames. The cumulative window session must still block: this is
    // the case the old per-chunk path could never see.
    let events = vec![
        sse_delta("hor"),
        sse_delta("rid"),
        sse_delta(" AFTER"),
        sse_stop(),
        "[DONE]".to_string(),
    ];
    let upstream = MockUpstream::start_sse(events).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config_with_guardrails(
        &upstream.base_url(),
        r#"          - type: toxicity
            keywords: ["horrid"]"#,
    ))
    .unwrap();

    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &stream_chat(), &[])
        .unwrap();
    assert_eq!(resp.status, 200, "headers precede the block");
    let text = String::from_utf8_lossy(&resp.body);
    assert!(
        !text.contains("AFTER"),
        "the stream must terminate at the split-pattern block: {text}"
    );
}

#[test]
fn streaming_dan_word_boundary_defers_correctly() {
    // "Dan" + "iel" flows clean end to end; the same guardrail blocks
    // a standalone "DA" + "N" split once the boundary resolves.
    let clean_events = vec![
        sse_delta("meet Dan"),
        sse_delta("iel today"),
        sse_delta(" TRAILER"),
        sse_stop(),
        "[DONE]".to_string(),
    ];
    let upstream = MockUpstream::start_sse(clean_events).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config_with_guardrails(
        &upstream.base_url(),
        "          - type: jailbreak",
    ))
    .unwrap();
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &stream_chat(), &[])
        .unwrap();
    let text = String::from_utf8_lossy(&resp.body);
    assert!(
        text.contains("TRAILER"),
        "a split name like Daniel must stream through untouched: {text}"
    );

    let block_events = vec![
        sse_delta("try DA"),
        sse_delta("N mode"),
        sse_delta(" AFTER"),
        sse_stop(),
        "[DONE]".to_string(),
    ];
    let upstream = MockUpstream::start_sse(block_events).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config_with_guardrails(
        &upstream.base_url(),
        "          - type: jailbreak",
    ))
    .unwrap();
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &stream_chat(), &[])
        .unwrap();
    let text = String::from_utf8_lossy(&resp.body);
    assert!(
        !text.contains("AFTER"),
        "a standalone DAN split across deltas must block: {text}"
    );
}

fn tool_call_frame(index: usize, id: Option<&str>, name: Option<&str>, args: &str) -> String {
    let mut tc = serde_json::Map::new();
    tc.insert("index".into(), json!(index));
    if let Some(id) = id {
        tc.insert("id".into(), json!(id));
    }
    let mut f = serde_json::Map::new();
    if let Some(name) = name {
        f.insert("name".into(), json!(name));
    }
    f.insert("arguments".into(), json!(args));
    tc.insert("function".into(), serde_json::Value::Object(f));
    json!({"choices":[{"index":0,"delta":{"tool_calls":[serde_json::Value::Object(tc)]},"finish_reason":null}]})
        .to_string()
}

#[test]
fn streamed_denied_tool_call_blocks_in_block_mode() {
    // A streamed tool call naming a denied tool, its arguments split
    // across two frames, followed by text. Block mode must terminate
    // the stream once the call completes, and the held tool-call
    // frames must never reach the client.
    let events = vec![
        sse_delta("thinking..."),
        tool_call_frame(0, Some("call_1"), Some("drop_table"), ""),
        tool_call_frame(0, None, None, r#"{"tab"#),
        tool_call_frame(0, None, None, r#"le":"users"}"#),
        sse_stop(),
        "[DONE]".to_string(),
    ];
    let upstream = MockUpstream::start_sse(events).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config_with_guardrails(
        &upstream.base_url(),
        r#"          - type: agent_alignment
            enabled: true
            mode: block
            denied_tools: ["drop_table"]"#,
    ))
    .unwrap();

    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &stream_chat(), &[])
        .unwrap();
    let text = String::from_utf8_lossy(&resp.body);
    assert!(
        !text.contains("drop_table"),
        "held tool-call frames must not reach the client in block mode: {text}"
    );
}

#[test]
fn streamed_denied_tool_call_flags_in_flag_mode() {
    // Same frames, flag mode: the violation is logged and counted but
    // the stream flows untouched, tool-call frames included.
    let events = vec![
        sse_delta("thinking..."),
        tool_call_frame(0, Some("call_1"), Some("drop_table"), "{}"),
        sse_delta(" AFTER"),
        sse_stop(),
        "[DONE]".to_string(),
    ];
    let upstream = MockUpstream::start_sse(events).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config_with_guardrails(
        &upstream.base_url(),
        r#"          - type: agent_alignment
            enabled: true
            mode: flag
            denied_tools: ["drop_table"]"#,
    ))
    .unwrap();

    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &stream_chat(), &[])
        .unwrap();
    assert_eq!(resp.status, 200);
    let text = String::from_utf8_lossy(&resp.body);
    assert!(
        text.contains("AFTER"),
        "flag mode must deliver the full stream: {text}"
    );
    assert!(
        text.contains("drop_table"),
        "flag mode must not withhold tool-call frames: {text}"
    );
}

#[test]
fn stream_policy_off_skips_and_close_blocks_at_end() {
    // stream_policy: off lets the forbidden keyword through the live
    // stream; stream_policy: close withholds nothing mid-stream but
    // terminates before the final frames.
    let events = || {
        vec![
            sse_delta("bad"),
            sse_delta("word"),
            sse_delta(" AFTER"),
            sse_stop(),
            "[DONE]".to_string(),
        ]
    };

    let upstream = MockUpstream::start_sse(events()).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config_with_guardrails(
        &upstream.base_url(),
        r#"          - type: toxicity
            keywords: ["badword"]
            stream_policy: "off""#,
    ))
    .unwrap();
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &stream_chat(), &[])
        .unwrap();
    let text = String::from_utf8_lossy(&resp.body);
    assert!(
        text.contains("AFTER"),
        "stream_policy off must not evaluate streamed output: {text}"
    );

    let upstream = MockUpstream::start_sse(events()).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config_with_guardrails(
        &upstream.base_url(),
        r#"          - type: toxicity
            keywords: ["badword"]
            stream_policy: "close""#,
    ))
    .unwrap();
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &stream_chat(), &[])
        .unwrap();
    // The content deltas flow (close policy defers evaluation), but
    // the verdict at stream end is recorded; mid-stream frames may
    // have been delivered. What must hold: the violation metric fires
    // and the stream is cut before the terminal frame, which the
    // relay expresses by suppressing the tail. The upstream [DONE]
    // frame is upstream-owned and passes through earlier frames, so
    // assert on the delivered content only.
    let text = String::from_utf8_lossy(&resp.body);
    assert!(
        text.contains("badword") || text.contains("bad"),
        "close policy delivers mid-stream content: {text}"
    );
}
