//! Live request-path acceptance for the Phase 1 retrieval compression pipeline.

use sbproxy_ai::compression::{decode_sbproxy_table_v1, inspect_marked_context};
use sbproxy_e2e::{CapturedRequest, MockUpstream, ProxyHarness};
use serde_json::{json, Value};

const HOST: &str = "phase1.localhost";
const QUERY: &str = "Which deployment fact explains the checkout outage?";
const REQUIRED_EVIDENCE: &str =
    "Required evidence: checkout failed because catalog-v42 was missing in us-west-2.";
const DISTRACTOR_A: &str = "Unrelated payroll archive from 2019. ";
const DISTRACTOR_B: &str = "Unrelated office lunch menu and room booking notes.";
const USEFUL_A: &str = "The catalog service reported ImagePullBackOff.";
const USEFUL_B: &str = "The checkout deployment began at 12:01 UTC.";
const UNMARKED_PREFIX: &str = "Caller note before retrieval.\n";
const UNMARKED_SUFFIX: &str = "\nCaller note after retrieval.";

fn config(upstream_base: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "{HOST}":
    action:
      type: ai_proxy
      providers:
        - name: openai
          provider_type: openai
          api_key: stub-key
          base_url: "{upstream_base}"
          allow_private_base_url: true
          default_model: gpt-4o
          models: [gpt-4o]
      compression:
        levers:
          - type: rag_select
            min_tokens: 1
            ranking: supplied
            max_chunks: 3
            min_relevance_percent: 20
            drop_empty: true
          - type: compact_serialization
            min_tokens: 1
            tabular:
              enabled: true
              min_rows: 200
          - type: position_reorder
            ranking: supplied
          - type: window_fit
            completion_reserve_tokens: 0
            input_budget_tokens: 32768
"#
    )
}

fn reply() -> Value {
    json!({
        "id": "chatcmpl-phase1",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    })
}

fn marked_chunk(id: &str, score: &str, format: &str, body: &str) -> String {
    format!(
        "<sbproxy-chunk id=\"{id}\" score=\"{score}\" format=\"{format}\">\n{body}\n</sbproxy-chunk>"
    )
}

fn marked_block(query: &str, chunks: &[String]) -> String {
    format!(
        "<sbproxy-retrieval>\n<sbproxy-query>\n{query}\n</sbproxy-query>\n{}\n</sbproxy-retrieval>",
        chunks.join("\n")
    )
}

fn source_rows() -> Value {
    Value::Array(
        (0..200)
            .map(|row| {
                json!({
                    "attempt": row,
                    "region": "us-west-2",
                    "service": "checkout",
                    "status": if row % 2 == 0 { "retrying" } else { "waiting" }
                })
            })
            .collect(),
    )
}

fn valid_body(rows: &Value) -> Value {
    let assistant_marker = marked_block(
        "Protected assistant marker-like query",
        &[marked_chunk(
            "protected",
            "1",
            "text",
            "Protected assistant marker-like evidence",
        )],
    );
    let user_block = marked_block(
        QUERY,
        &[
            marked_chunk("distractor-a", "0.05", "text", DISTRACTOR_A),
            marked_chunk("useful-b", "0.60", "text", USEFUL_B),
            marked_chunk("required", "0.99", "text", REQUIRED_EVIDENCE),
            marked_chunk("distractor-b", "0.10", "text", DISTRACTOR_B),
            marked_chunk("useful-a", "0.80", "text", USEFUL_A),
        ],
    );
    let pretty_rows = serde_json::to_string_pretty(rows).expect("serialize source rows");
    let tool_block = marked_block(
        QUERY,
        &[marked_chunk("tool-rows", "1", "json", &pretty_rows)],
    );

    json!({
        "model": "gpt-4o",
        "messages": [
            {
                "role": "system",
                "content": "Protected system text: <sbproxy-retrieval> is documentation, not input."
            },
            {
                "role": "developer",
                "content": "Protected developer text: </sbproxy-query> and <sbproxy-chunk id=\"x\" format=\"text\"> stay literal."
            },
            {"role": "assistant", "content": assistant_marker},
            {"role": "user", "content": "Unmarked user text must remain byte-for-byte identical."},
            {
                "role": "user",
                "content": format!("{UNMARKED_PREFIX}{user_block}{UNMARKED_SUFFIX}")
            },
            {"role": "tool", "tool_call_id": "call_phase1", "content": tool_block},
            {"role": "user", "content": "Final unmarked user instruction stays exact."}
        ]
    })
}

fn malformed_body() -> Value {
    json!({
        "model": "gpt-4o",
        "messages": [{
            "role": "user",
            "content": concat!(
                "<sbproxy-retrieval>\n",
                "<sbproxy-query>\nsmall malformed request\n</sbproxy-query>\n",
                "<sbproxy-chunk id=\"broken\" score=\"1\" format=\"text\">\n",
                "short body\n",
                "</sbproxy-retrieval>"
            )
        }]
    })
}

fn post(harness: &ProxyHarness, body: &Value, selector: &str) {
    let response = harness
        .post_json(
            "/v1/chat/completions",
            HOST,
            body,
            &[("x-compression", selector)],
        )
        .expect("send request through proxy");
    assert_eq!(
        response.status,
        200,
        "request failed: {}",
        String::from_utf8_lossy(&response.body)
    );
}

fn only_new_capture(upstream: &MockUpstream, before: usize) -> CapturedRequest {
    let captures = upstream.captured();
    assert_eq!(
        captures.len(),
        before + 1,
        "one request must reach upstream"
    );
    captures[before].clone()
}

fn captured_json(capture: &CapturedRequest) -> Value {
    serde_json::from_slice(&capture.body).expect("captured provider request JSON")
}

fn assert_internal_header_removed(capture: &CapturedRequest) {
    assert!(
        !capture.headers.contains_key("x-compression"),
        "the internal compression selector must not reach the provider"
    );
}

#[test]
fn phase1_pipeline_changes_only_valid_explicit_marked_context() {
    let upstream = MockUpstream::start(reply()).expect("start mock upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config(&upstream.base_url())).expect("start Phase 1 proxy");
    let rows = source_rows();
    let valid = valid_body(&rows);

    let before = upstream.captured().len();
    post(&harness, &valid, "on");
    let compressed_capture = only_new_capture(&upstream, before);
    assert_internal_header_removed(&compressed_capture);
    let compressed = captured_json(&compressed_capture);
    let source_messages = valid["messages"].as_array().expect("source messages");
    let compressed_messages = compressed["messages"]
        .as_array()
        .expect("compressed messages");
    assert_eq!(compressed_messages.len(), source_messages.len());
    for index in [0, 1, 2, 3, 6] {
        assert_eq!(
            compressed_messages[index], source_messages[index],
            "unmarked or protected message {index} changed"
        );
    }
    let compressed_user = compressed_messages[4]["content"]
        .as_str()
        .expect("compressed marked user content");
    assert_ne!(compressed_messages[4], source_messages[4]);
    assert_ne!(compressed_messages[5], source_messages[5]);

    let snapshot = inspect_marked_context(compressed_messages)
        .expect("compressed markers remain valid")
        .expect("compressed markers remain present");
    assert_eq!(snapshot.blocks.len(), 2);
    assert_eq!(snapshot.blocks[0].query, QUERY);
    assert_eq!(snapshot.blocks[1].query, QUERY);
    let user_chunks = &snapshot.blocks[0].chunks;
    assert_eq!(
        user_chunks
            .iter()
            .map(|chunk| chunk.id.as_str())
            .collect::<Vec<_>>(),
        ["required", "useful-b", "useful-a"]
    );
    assert!(
        user_chunks
            .first()
            .is_some_and(|chunk| chunk.body == REQUIRED_EVIDENCE)
            || user_chunks
                .last()
                .is_some_and(|chunk| chunk.body == REQUIRED_EVIDENCE),
        "required evidence must be placed at a retrieval edge"
    );
    assert!(
        !compressed_user.contains("distractor-a")
            && !compressed_user.contains("distractor-b")
            && !compressed_user.contains(DISTRACTOR_A)
            && !compressed_user.contains(DISTRACTOR_B),
        "RAG selection must remove distractor IDs and bodies"
    );
    let expected_user_block = marked_block(
        QUERY,
        &[
            marked_chunk("required", "0.99", "text", REQUIRED_EVIDENCE),
            marked_chunk("useful-b", "0.60", "text", USEFUL_B),
            marked_chunk("useful-a", "0.80", "text", USEFUL_A),
        ],
    );
    assert_eq!(
        compressed_user,
        format!("{UNMARKED_PREFIX}{expected_user_block}{UNMARKED_SUFFIX}"),
        "the complete transformed user string must match exactly"
    );
    let compacted = &snapshot.blocks[1].chunks[0];
    assert_eq!(compacted.id, "tool-rows");
    assert_eq!(compacted.format, "sbproxy_table_v1");
    let expected_tool = marked_block(
        QUERY,
        &[marked_chunk(
            "tool-rows",
            "1",
            "sbproxy_table_v1",
            &compacted.body,
        )],
    );
    assert_eq!(
        compressed_messages[5]["content"], expected_tool,
        "the complete transformed tool string must match exactly"
    );
    assert_eq!(
        decode_sbproxy_table_v1(&compacted.body).expect("decode public Table v1"),
        rows
    );

    let malformed = malformed_body();
    let before = upstream.captured().len();
    post(&harness, &malformed, "on");
    let malformed_capture = only_new_capture(&upstream, before);
    assert_internal_header_removed(&malformed_capture);
    assert_eq!(captured_json(&malformed_capture), malformed);
    assert_eq!(
        malformed_capture.body,
        serde_json::to_vec(&malformed).expect("encode malformed fixture"),
        "the small malformed request must be forwarded byte-for-byte"
    );

    let before = upstream.captured().len();
    post(&harness, &valid, "off");
    let disabled_capture = only_new_capture(&upstream, before);
    assert_internal_header_removed(&disabled_capture);
    assert_eq!(captured_json(&disabled_capture), valid);
    assert_eq!(
        disabled_capture.body,
        serde_json::to_vec(&valid).expect("encode valid fixture"),
        "x-compression: off must preserve the full valid request"
    );
}
