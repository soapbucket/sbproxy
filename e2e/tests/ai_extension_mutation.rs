//! End-to-end coverage for AI extension hook mutation (WOR-2368).
//!
//! A bundle hook that declares `mutates: true` may return a `mutate`
//! decision carrying a replacement payload. The host applies it in
//! place and the rewritten content is what actually ships: an output
//! rewrite reaches the client body, an input rewrite reaches the
//! upstream request. A hook that returns `mutate` without declaring it
//! is an engine fault handled under the bundle's failure posture, so
//! under the closed default the response is a refusal, never the
//! original bytes shipped as if the rewrite had happened.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn config(upstream_base: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
extensions:
  bundles_dir: bundles
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

fn chat(content: &str) -> serde_json::Value {
    json!({"model": "gpt-4o", "messages": [{"role": "user", "content": content}]})
}

const OUTPUT_REDACTOR_MANIFEST: &str = "\
apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: output-redactor
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: ai_guardrail_output
    type: redact_output
    export: redact
    execution:
      mutates: true
";

// The hook sees the canonical assistant text and replaces it wholesale.
// btoa is not assumed in the sandbox; the replacement is precomputed:
// base64("the answer is [REDACTED-SSN]") =
// "dGhlIGFuc3dlciBpcyBbUkVEQUNURUQtU1NOXQ==".
const OUTPUT_REDACTOR_JS: &str = r#"export function redact(input) {
  if (input.event.content.indexOf("123-45-6789") === -1) {
    return {version:"sbproxy-envelope/v1",decision:"release"};
  }
  return {version:"sbproxy-envelope/v1",decision:"mutate",code:"ssn_redacted",body_base64:"dGhlIGFuc3dlciBpcyBbUkVEQUNURUQtU1NOXQ=="};
}"#;

#[test]
fn output_mutation_reaches_the_client_body() {
    let upstream = MockUpstream::start(chat_reply("the answer is 123-45-6789")).unwrap();
    let files = [
        (
            "bundles/output-redactor/bundle.yaml",
            OUTPUT_REDACTOR_MANIFEST,
        ),
        ("bundles/output-redactor/entry.js", OUTPUT_REDACTOR_JS),
    ];
    let harness =
        ProxyHarness::start_with_workspace(&config(&upstream.base_url()), &files).unwrap();

    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &chat("hi"), &[])
        .unwrap();

    assert_eq!(resp.status, 200, "{:?}", resp.text().unwrap_or_default());
    let text = resp.text().unwrap_or_default();
    assert!(
        text.contains("[REDACTED-SSN]"),
        "the rewritten text must reach the client: {text}"
    );
    assert!(
        !text.contains("123-45-6789"),
        "the original content must not ship once a hook rewrote it: {text}"
    );
    // The splice touched exactly the assistant text slot.
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["usage"]["total_tokens"], 2);
    assert_eq!(value["choices"][0]["finish_reason"], "stop");
}

const INPUT_REDACTOR_MANIFEST: &str = "\
apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: input-redactor
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: ai_guardrail_input
    type: redact_input
    export: redact
    execution:
      mutates: true
";

// base64 of [{"role":"user","content":"my card is [REDACTED-CARD]"}]
const INPUT_REDACTOR_JS: &str = r#"export function redact(input) {
  var flagged = false;
  for (var i = 0; i < input.event.messages.length; i++) {
    if (input.event.messages[i].content.indexOf("4111") !== -1) { flagged = true; }
  }
  if (!flagged) { return {version:"sbproxy-envelope/v1",decision:"release"}; }
  return {version:"sbproxy-envelope/v1",decision:"mutate",code:"card_redacted",body_base64:"W3sicm9sZSI6InVzZXIiLCJjb250ZW50IjoibXkgY2FyZCBpcyBbUkVEQUNURUQtQ0FSRF0ifV0="};
}"#;

#[test]
fn input_mutation_reaches_the_upstream_request() {
    let upstream = MockUpstream::start(chat_reply("done")).unwrap();
    let files = [
        (
            "bundles/input-redactor/bundle.yaml",
            INPUT_REDACTOR_MANIFEST,
        ),
        ("bundles/input-redactor/entry.js", INPUT_REDACTOR_JS),
    ];
    let harness =
        ProxyHarness::start_with_workspace(&config(&upstream.base_url()), &files).unwrap();

    let resp = harness
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &chat("my card is 4111 1111 1111 1111"),
            &[],
        )
        .unwrap();

    assert_eq!(resp.status, 200, "{:?}", resp.text().unwrap_or_default());
    let captured = upstream.captured();
    assert_eq!(captured.len(), 1, "exactly one upstream call");
    let sent = String::from_utf8(captured[0].body.clone()).unwrap();
    assert!(
        sent.contains("[REDACTED-CARD]"),
        "the rewritten input must reach the upstream: {sent}"
    );
    assert!(
        !sent.contains("4111"),
        "the original card number must not reach the upstream: {sent}"
    );
}

const UNDECLARED_MANIFEST: &str = "\
apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: sneaky-redactor
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: ai_guardrail_output
    type: sneak_output
    export: sneak
";

const UNDECLARED_JS: &str = r#"export function sneak(input) {
  return {version:"sbproxy-envelope/v1",decision:"mutate",code:"sneaky",body_base64:"c25lYWt5"};
}"#;

#[test]
fn undeclared_mutation_refuses_under_the_closed_default() {
    // The manifest says inspect-only; the engine mutates anyway. Under
    // the closed default posture that is an engine fault and the
    // request refuses. Shipping the original as if nothing happened
    // would leave the operator believing the hook ran clean.
    let upstream = MockUpstream::start(chat_reply("the original answer")).unwrap();
    let files = [
        ("bundles/sneaky-redactor/bundle.yaml", UNDECLARED_MANIFEST),
        ("bundles/sneaky-redactor/entry.js", UNDECLARED_JS),
    ];
    let harness =
        ProxyHarness::start_with_workspace(&config(&upstream.base_url()), &files).unwrap();

    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &chat("hi"), &[])
        .unwrap();

    assert_ne!(
        resp.status,
        200,
        "an undeclared mutation must not release: {:?}",
        resp.text().unwrap_or_default()
    );
    let text = resp.text().unwrap_or_default();
    assert!(
        !text.contains("the original answer"),
        "the model output must not leak through the refusal: {text}"
    );
}

// --- Tool-call mutation (WOR-2419) ---

fn sse_frames(events: &[String]) -> Vec<String> {
    events.to_vec()
}

fn tool_frame(index: usize, id: Option<&str>, name: Option<&str>, args: &str) -> String {
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

const TOOL_REWRITER_MANIFEST: &str = "\
apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: tool-rewriter
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: ai_tool_call
    type: rewrite_tool
    export: rewrite
    execution:
      mutates: true
";

// base64 of {"index":0,"id":"call_1","name":"lookup_user","arguments_json":"{\"table\":\"[MASKED]\"}"}
const TOOL_REWRITER_JS: &str = r#"export function rewrite(input) {
  const call = input.event.call;
  if (call.arguments_json.indexOf("secret_users") === -1) {
    return {version:"sbproxy-envelope/v1",decision:"release"};
  }
  return {version:"sbproxy-envelope/v1",decision:"mutate",code:"table_masked",body_base64:"eyJpbmRleCI6MCwiaWQiOiJjYWxsXzEiLCJuYW1lIjoibG9va3VwX3VzZXIiLCJhcmd1bWVudHNfanNvbiI6IntcInRhYmxlXCI6XCJbTUFTS0VEXVwifSJ9"};
}"#;

#[test]
fn tool_call_mutation_reaches_the_client_stream() {
    // The upstream fragments the call's arguments across two frames;
    // the hook sees the assembled call and rewrites it; the client
    // stream carries the rewrite as one canonical frame and never the
    // original fragments.
    let events = sse_frames(&[
        tool_frame(0, Some("call_1"), Some("lookup_user"), ""),
        tool_frame(0, None, None, r#"{"table":"secret"#),
        tool_frame(0, None, None, r#"_users"}"#),
        json!({"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}).to_string(),
        "[DONE]".to_string(),
    ]);
    let upstream = MockUpstream::start_sse(events).unwrap();
    let files = [
        ("bundles/tool-rewriter/bundle.yaml", TOOL_REWRITER_MANIFEST),
        ("bundles/tool-rewriter/entry.js", TOOL_REWRITER_JS),
    ];
    let harness =
        ProxyHarness::start_with_workspace(&config(&upstream.base_url()), &files).unwrap();

    let body = json!({
        "model": "gpt-4o",
        "stream": true,
        "messages": [{"role": "user", "content": "look them up"}]
    });
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .unwrap();
    assert_eq!(resp.status, 200, "{:?}", resp.text().unwrap_or_default());
    let text = String::from_utf8_lossy(&resp.body);
    assert!(
        text.contains("[MASKED]"),
        "the rewritten arguments must reach the client stream: {text}"
    );
    assert!(
        !text.contains("secret_users"),
        "the original arguments must not reach the client: {text}"
    );
    assert!(
        text.contains("lookup_user"),
        "the call itself still ships: {text}"
    );
}
