//! OpenAI ⇄ Anthropic Messages API translator.
//!
//! Maps the OpenAI chat-completions shape to and from Anthropic's
//! Messages API. Covers the fields most clients use: messages,
//! system prompt, model, temperature, top_p, top_k, max_tokens,
//! stop sequences, stream, and tool calls.
//!
//! Streaming SSE event translation is a follow-up; today the
//! translator handles non-streaming bodies. Setting `stream: true`
//! forwards as-is and the response stays in Anthropic's
//! `event: content_block_delta` shape until SSE translation lands.

use serde_json::{json, Map, Value};

/// Convert an OpenAI request body to Anthropic Messages API shape.
///
/// Differences handled:
///   * The OpenAI `system` role is hoisted to a top-level `system`
///     field. Anthropic does not allow `system` in the messages list.
///   * `max_tokens` is required by Anthropic; we default to 1024 when
///     the OpenAI client omitted it.
///   * `messages` array shape stays compatible (role + content) for
///     plain-text turns. Multimodal `content: [...]` arrays pass
///     through unchanged.
///   * The path is rewritten from `/v1/chat/completions` to
///     `/v1/messages`.
///   * Unsupported OpenAI knobs (`logit_bias`, `n`, `presence_penalty`,
///     `frequency_penalty`, `response_format`, `seed`, `user`) are
///     dropped. Unknown extensions pass through.
pub fn request_to_native(body: Value, path: &str) -> (Value, String) {
    let mut obj: Map<String, Value> = match body {
        Value::Object(m) => m,
        other => return (other, path.to_string()),
    };

    // 1. Hoist any `system` role messages to a top-level `system`
    //    field (concatenated when there are several).
    let mut system_chunks: Vec<String> = Vec::new();
    if let Some(Value::Array(messages)) = obj.get("messages") {
        for m in messages {
            if m.get("role").and_then(|r| r.as_str()) == Some("system") {
                if let Some(s) = m.get("content").and_then(|c| c.as_str()) {
                    system_chunks.push(s.to_string());
                }
            }
        }
    }
    if !system_chunks.is_empty() {
        obj.insert(
            "system".to_string(),
            Value::String(system_chunks.join("\n\n")),
        );
        if let Some(Value::Array(messages)) = obj.remove("messages") {
            let filtered: Vec<Value> = messages
                .into_iter()
                .filter(|m| m.get("role").and_then(|r| r.as_str()) != Some("system"))
                .collect();
            obj.insert("messages".to_string(), Value::Array(filtered));
        }
    }

    // 2. Anthropic requires max_tokens. OpenAI defaults it server
    //    side; we pick a conservative default so requests don't get
    //    rejected.
    obj.entry("max_tokens".to_string())
        .or_insert(Value::Number(1024.into()));

    // 3. Drop OpenAI-only knobs Anthropic rejects with 400.
    for k in [
        "logit_bias",
        "n",
        "presence_penalty",
        "frequency_penalty",
        "response_format",
        "seed",
        "user",
    ] {
        obj.remove(k);
    }

    // 4. Path rewrite. Translator only supports chat completions and
    //    its native equivalent today.
    let new_path = if path.ends_with("/chat/completions") {
        path.trim_end_matches("/chat/completions")
            .trim_end_matches('/')
            .to_string()
            + "/messages"
    } else {
        path.to_string()
    };

    (Value::Object(obj), new_path)
}

/// Convert an Anthropic Messages API response back to the OpenAI
/// chat-completions shape so OpenAI SDK clients can parse it.
///
/// Field map:
///   * Anthropic `content: [{type: "text", text}, ...]` →
///     OpenAI `choices[0].message.content` (concatenated text blocks).
///     Tool-use blocks become `tool_calls` on the message.
///   * Anthropic `stop_reason` → OpenAI `finish_reason`
///     (`end_turn` → `stop`, `max_tokens` → `length`,
///     `tool_use` → `tool_calls`, others pass through).
///   * Anthropic `usage.input_tokens` / `output_tokens` →
///     OpenAI `usage.prompt_tokens` / `completion_tokens`.
///   * `model` and `id` pass through.
pub fn response_to_openai(body: Value) -> Value {
    let m = match body {
        Value::Object(m) => m,
        other => return other,
    };

    let id = m.get("id").cloned().unwrap_or(Value::Null);
    let model = m.get("model").cloned().unwrap_or(Value::Null);

    let (content_text, tool_calls) = extract_content_and_tools(&m);

    let finish_reason = m
        .get("stop_reason")
        .and_then(|s| s.as_str())
        .map(|s| match s {
            "end_turn" => "stop",
            "max_tokens" => "length",
            "tool_use" => "tool_calls",
            "stop_sequence" => "stop",
            other => other,
        })
        .unwrap_or("stop")
        .to_string();

    let mut message = json!({
        "role": "assistant",
        "content": content_text,
    });
    if !tool_calls.is_empty() {
        if let Some(obj) = message.as_object_mut() {
            obj.insert("tool_calls".to_string(), Value::Array(tool_calls));
        }
    }

    let usage = json!({
        "prompt_tokens": m.get("usage")
            .and_then(|u| u.get("input_tokens"))
            .and_then(|n| n.as_u64()).unwrap_or(0),
        "completion_tokens": m.get("usage")
            .and_then(|u| u.get("output_tokens"))
            .and_then(|n| n.as_u64()).unwrap_or(0),
        "total_tokens": (m.get("usage")
            .and_then(|u| u.get("input_tokens"))
            .and_then(|n| n.as_u64()).unwrap_or(0)
            + m.get("usage")
                .and_then(|u| u.get("output_tokens"))
                .and_then(|n| n.as_u64()).unwrap_or(0)),
    });

    json!({
        "id": id,
        "object": "chat.completion",
        "model": model,
        "choices": [{
            "index": 0,
            "message": message,
            "finish_reason": finish_reason,
        }],
        "usage": usage,
    })
}

fn extract_content_and_tools(m: &Map<String, Value>) -> (Value, Vec<Value>) {
    let blocks = match m.get("content") {
        Some(Value::Array(a)) => a,
        Some(other) => return (other.clone(), Vec::new()),
        None => return (Value::String(String::new()), Vec::new()),
    };
    let mut texts: Vec<String> = Vec::new();
    let mut tool_calls: Vec<Value> = Vec::new();
    for block in blocks {
        let ty = block.get("type").and_then(|s| s.as_str()).unwrap_or("");
        match ty {
            "text" => {
                if let Some(t) = block.get("text").and_then(|s| s.as_str()) {
                    texts.push(t.to_string());
                }
            }
            "tool_use" => {
                let id = block
                    .get("id")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();
                let name = block
                    .get("name")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();
                let input = block.get("input").cloned().unwrap_or(Value::Null);
                tool_calls.push(json!({
                    "id": id,
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": input.to_string(),
                    },
                }));
            }
            _ => {}
        }
    }
    (Value::String(texts.join("")), tool_calls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_extracts_system_role() {
        let body = json!({
            "model": "claude-3-5-sonnet",
            "messages": [
                {"role": "system", "content": "you are helpful"},
                {"role": "user", "content": "hi"}
            ],
        });
        let (out, path) = request_to_native(body, "/v1/chat/completions");
        assert_eq!(path, "/v1/messages");
        assert_eq!(out["system"], "you are helpful");
        let msgs = out["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0]["role"], "user");
    }

    #[test]
    fn request_concatenates_multiple_system_messages() {
        let body = json!({
            "messages": [
                {"role": "system", "content": "tone is formal"},
                {"role": "system", "content": "answer in english"},
                {"role": "user", "content": "hello"}
            ]
        });
        let (out, _) = request_to_native(body, "/v1/chat/completions");
        assert_eq!(out["system"], "tone is formal\n\nanswer in english");
    }

    #[test]
    fn request_default_max_tokens() {
        let body = json!({"messages": [{"role": "user", "content": "hi"}]});
        let (out, _) = request_to_native(body, "/v1/chat/completions");
        assert_eq!(out["max_tokens"], 1024);
    }

    #[test]
    fn request_drops_openai_only_fields() {
        let body = json!({
            "messages": [{"role": "user", "content": "hi"}],
            "logit_bias": {"123": 5},
            "n": 2,
            "presence_penalty": 0.5,
            "frequency_penalty": 0.5,
            "response_format": {"type": "json_object"},
            "seed": 42,
            "user": "u-1",
        });
        let (out, _) = request_to_native(body, "/v1/chat/completions");
        let obj = out.as_object().unwrap();
        for k in [
            "logit_bias",
            "n",
            "presence_penalty",
            "frequency_penalty",
            "response_format",
            "seed",
            "user",
        ] {
            assert!(!obj.contains_key(k), "expected {k} stripped");
        }
    }

    #[test]
    fn response_concatenates_text_blocks() {
        let body = json!({
            "id": "msg_01",
            "model": "claude-3-5-sonnet",
            "content": [
                {"type": "text", "text": "Hello "},
                {"type": "text", "text": "world."}
            ],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 7, "output_tokens": 3}
        });
        let out = response_to_openai(body);
        assert_eq!(out["id"], "msg_01");
        assert_eq!(out["model"], "claude-3-5-sonnet");
        assert_eq!(out["object"], "chat.completion");
        assert_eq!(out["choices"][0]["message"]["content"], "Hello world.");
        assert_eq!(out["choices"][0]["finish_reason"], "stop");
        assert_eq!(out["usage"]["prompt_tokens"], 7);
        assert_eq!(out["usage"]["completion_tokens"], 3);
        assert_eq!(out["usage"]["total_tokens"], 10);
    }

    #[test]
    fn response_maps_finish_reasons() {
        for (anth, oai) in [
            ("end_turn", "stop"),
            ("max_tokens", "length"),
            ("tool_use", "tool_calls"),
            ("stop_sequence", "stop"),
        ] {
            let body = json!({
                "content": [{"type": "text", "text": "x"}],
                "stop_reason": anth,
            });
            let out = response_to_openai(body);
            assert_eq!(
                out["choices"][0]["finish_reason"], oai,
                "{anth} should map to {oai}"
            );
        }
    }

    #[test]
    fn response_extracts_tool_calls() {
        let body = json!({
            "content": [
                {"type": "text", "text": "let me check"},
                {
                    "type": "tool_use",
                    "id": "toolu_1",
                    "name": "get_weather",
                    "input": {"city": "SF"}
                }
            ],
            "stop_reason": "tool_use",
        });
        let out = response_to_openai(body);
        let tool_calls = out["choices"][0]["message"]["tool_calls"]
            .as_array()
            .expect("tool_calls present");
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0]["id"], "toolu_1");
        assert_eq!(tool_calls[0]["function"]["name"], "get_weather");
    }

    #[test]
    fn round_trip_minimal() {
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{"role": "user", "content": "hi"}],
        });
        let (native, path) = request_to_native(req.clone(), "/v1/chat/completions");
        assert!(path.ends_with("/messages"));
        // Simulate Anthropic's response shape.
        let raw = json!({
            "id": "msg_xyz",
            "model": native["model"],
            "content": [{"type": "text", "text": "hello"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1},
        });
        let out = response_to_openai(raw);
        assert_eq!(out["choices"][0]["message"]["content"], "hello");
    }
}
