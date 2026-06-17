//! OpenAI ⇄ AWS Bedrock Converse API translator.
//!
//! Maps the OpenAI chat-completions shape to and from Bedrock's
//! model-agnostic `Converse` API. The Converse shape is the
//! recommended way to call Bedrock for chat workloads because it
//! abstracts the per-model body schemas (Claude, Llama, Mistral,
//! Titan, Nova) behind a single set of request and response types.
//!
//! For workloads that need to hit the legacy `InvokeModel` endpoint
//! against a model-specific shape (e.g. raw Anthropic Messages on
//! Bedrock-hosted Claude), callers should select the corresponding
//! provider format directly; this translator targets the Converse
//! shape so a single OpenAI client can fan out across Bedrock
//! model families without per-model branching.
//!
//! This module owns non-streaming request/response JSON translation.
//! Streaming responses are handled by the native stream translator in
//! `format::native_streams`, which parses Bedrock stream events into
//! the shared hub stream before the inbound route re-emits them.
//! SigV4 request signing is handled at the HTTP transport layer (the
//! `Authorization` header set by operator config or a future signing
//! middleware); it is not part of the JSON body translation contract
//! this module owns.

use serde_json::{json, Map, Value};

/// Convert an OpenAI request body to Bedrock Converse shape.
///
/// Differences handled:
///   * The OpenAI `system` role is hoisted into Bedrock's top-level
///     `system: [{text}]` array. Multiple system messages are
///     emitted as separate entries (Converse preserves order).
///   * `messages` array shape: `role` stays as `user`/`assistant`;
///     plain-text content becomes `[{text}]`, multimodal arrays are
///     translated part by part.
///   * Sampling knobs (`temperature`, `top_p`, `max_tokens`, `stop`)
///     move under `inferenceConfig` with camelCase keys.
///   * `tools` become `toolConfig.tools` with the
///     `{toolSpec: {name, description, inputSchema: {json}}}`
///     wrapper. `tool_calls` on assistant messages become content
///     blocks with `toolUse`. `role: "tool"` messages become user
///     turns with `toolResult` content blocks.
///   * The path is rewritten from `/v1/chat/completions` to
///     `/model/{modelId}/converse`.
///   * Unsupported OpenAI knobs (`logit_bias`, `n`,
///     `presence_penalty`, `frequency_penalty`, `response_format`,
///     `seed`, `user`, `top_k`) are dropped.
pub fn request_to_native(body: Value, path: &str) -> (Value, String) {
    let obj: Map<String, Value> = match body {
        Value::Object(m) => m,
        other => return (other, path.to_string()),
    };

    let model = obj
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let mut out: Map<String, Value> = Map::new();

    // 1. Split system messages from the rest, translate each.
    let raw_messages = obj
        .get("messages")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut system_blocks: Vec<Value> = Vec::new();
    let mut messages: Vec<Value> = Vec::new();
    for m in raw_messages {
        let role = m.get("role").and_then(|r| r.as_str()).unwrap_or("");
        if role == "system" {
            if let Some(s) = m.get("content").and_then(|c| c.as_str()) {
                system_blocks.push(json!({"text": s}));
            } else if let Some(arr) = m.get("content").and_then(|c| c.as_array()) {
                for p in arr {
                    if let Some(t) = p.get("text").and_then(|t| t.as_str()) {
                        system_blocks.push(json!({"text": t}));
                    }
                }
            }
            continue;
        }
        messages.push(message_to_converse(&m));
    }
    if !system_blocks.is_empty() {
        out.insert("system".to_string(), Value::Array(system_blocks));
    }
    out.insert("messages".to_string(), Value::Array(messages));

    // 2. Inference config.
    let mut inference: Map<String, Value> = Map::new();
    if let Some(v) = obj.get("max_tokens") {
        inference.insert("maxTokens".to_string(), v.clone());
    }
    if let Some(v) = obj.get("temperature") {
        inference.insert("temperature".to_string(), v.clone());
    }
    if let Some(v) = obj.get("top_p") {
        inference.insert("topP".to_string(), v.clone());
    }
    if let Some(v) = obj.get("stop") {
        let seqs = match v {
            Value::String(s) => Value::Array(vec![Value::String(s.clone())]),
            arr @ Value::Array(_) => arr.clone(),
            other => other.clone(),
        };
        inference.insert("stopSequences".to_string(), seqs);
    }
    if !inference.is_empty() {
        out.insert("inferenceConfig".to_string(), Value::Object(inference));
    }

    // 3. Tool config.
    if let Some(Value::Array(tools)) = obj.get("tools").cloned() {
        let mut specs: Vec<Value> = Vec::new();
        for t in tools {
            if let Some(func) = t.get("function") {
                let name = func.get("name").cloned().unwrap_or(Value::Null);
                let mut spec = Map::new();
                spec.insert("name".to_string(), name);
                if let Some(desc) = func.get("description") {
                    spec.insert("description".to_string(), desc.clone());
                }
                if let Some(params) = func.get("parameters") {
                    spec.insert("inputSchema".to_string(), json!({"json": params}));
                }
                specs.push(json!({"toolSpec": Value::Object(spec)}));
            }
        }
        if !specs.is_empty() {
            let mut tool_config = Map::new();
            tool_config.insert("tools".to_string(), Value::Array(specs));
            if let Some(choice) = obj.get("tool_choice") {
                tool_config.insert("toolChoice".to_string(), translate_tool_choice(choice));
            }
            out.insert("toolConfig".to_string(), Value::Object(tool_config));
        }
    }

    // 4. Path rewrite. Converse uses /model/{modelId}/converse.
    let new_path = if path.ends_with("/chat/completions") && !model.is_empty() {
        format!("/model/{}/converse", urlencode_model(&model))
    } else {
        path.to_string()
    };

    (Value::Object(out), new_path)
}

/// URL-encode the slashes inside a Bedrock model identifier
/// (`anthropic.claude-3-5-sonnet-20240620-v1:0` is fine bare, but
/// inference profile ARNs include `/` and `:` which must be
/// percent-encoded). We keep the set of escapes minimal because
/// Bedrock model IDs are otherwise alphanumeric with `.`, `-`, `:`.
fn urlencode_model(model: &str) -> String {
    model.replace('/', "%2F").replace(' ', "%20")
}

fn translate_tool_choice(choice: &Value) -> Value {
    if let Some(s) = choice.as_str() {
        return match s {
            "required" => json!({"any": {}}),
            // "auto", "none", and anything else map to Converse's
            // `auto` toolChoice. Bedrock does not have a "none"
            // analogue; clients that pass it get default behaviour.
            _ => json!({"auto": {}}),
        };
    }
    if let Some(obj) = choice.as_object() {
        if obj.get("type").and_then(|t| t.as_str()) == Some("function") {
            if let Some(name) = obj
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
            {
                return json!({"tool": {"name": name}});
            }
        }
    }
    json!({"auto": {}})
}

fn message_to_converse(m: &Value) -> Value {
    let role = m.get("role").and_then(|r| r.as_str()).unwrap_or("user");
    let conv_role = if role == "tool" { "user" } else { role };

    let mut content_blocks: Vec<Value> = Vec::new();

    // Tool result turn: a single toolResult content block.
    if role == "tool" {
        let tool_use_id = m
            .get("tool_call_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let content = match m.get("content") {
            Some(Value::String(s)) => vec![json!({"text": s})],
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|p| {
                    p.get("text")
                        .and_then(|t| t.as_str())
                        .map(|t| json!({"text": t}))
                })
                .collect(),
            _ => Vec::new(),
        };
        content_blocks.push(json!({
            "toolResult": {
                "toolUseId": tool_use_id,
                "content": content,
            }
        }));
        return json!({"role": conv_role, "content": content_blocks});
    }

    match m.get("content") {
        Some(Value::String(s)) if !s.is_empty() => {
            content_blocks.push(json!({"text": s}));
        }
        Some(Value::Array(arr)) => {
            for p in arr {
                let ty = p.get("type").and_then(|t| t.as_str()).unwrap_or("");
                match ty {
                    "text" => {
                        if let Some(t) = p.get("text").and_then(|s| s.as_str()) {
                            content_blocks.push(json!({"text": t}));
                        }
                    }
                    "image_url" => {
                        // Converse expects raw base64 source; the
                        // OpenAI shape's data: URL is decoded by a
                        // future enrichment step. Pass through the
                        // URL form so operators can spot the gap.
                        if let Some(url) = p
                            .get("image_url")
                            .and_then(|i| i.get("url"))
                            .and_then(|u| u.as_str())
                        {
                            content_blocks.push(json!({
                                "image": {"source": {"url": url}}
                            }));
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }

    if let Some(Value::Array(tool_calls)) = m.get("tool_calls") {
        for tc in tool_calls {
            let id = tc
                .get("id")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let name = tc
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            let args_str = tc
                .get("function")
                .and_then(|f| f.get("arguments"))
                .and_then(|a| a.as_str())
                .unwrap_or("{}");
            let input: Value = serde_json::from_str(args_str).unwrap_or(Value::Object(Map::new()));
            content_blocks.push(json!({
                "toolUse": {
                    "toolUseId": id,
                    "name": name,
                    "input": input,
                }
            }));
        }
    }

    json!({"role": conv_role, "content": content_blocks})
}

/// Convert a Bedrock Converse response back to the OpenAI
/// chat-completions shape so OpenAI SDK clients can parse it.
///
/// Field map:
///   * Converse `output.message.content[]` ->
///     OpenAI `choices[0].message.content` (text blocks concatenated).
///     `toolUse` blocks become `tool_calls` on the message.
///   * Converse `stopReason` -> OpenAI `finish_reason`
///     (`end_turn` -> `stop`, `max_tokens` -> `length`, `tool_use` ->
///     `tool_calls`, `content_filtered`/`guardrail_intervened` ->
///     `content_filter`, others pass through).
///   * Converse `usage.inputTokens` / `outputTokens` ->
///     OpenAI `usage.prompt_tokens` / `completion_tokens`.
pub fn response_to_openai(body: Value) -> Value {
    let m = match body {
        Value::Object(m) => m,
        other => return other,
    };

    let message = m
        .get("output")
        .and_then(|o| o.get("message"))
        .cloned()
        .unwrap_or(Value::Null);

    let (content_text, tool_calls) = extract_content_and_tools(&message);

    let finish_reason = m
        .get("stopReason")
        .and_then(|s| s.as_str())
        .map(|s| match s {
            "end_turn" => "stop".to_string(),
            "max_tokens" => "length".to_string(),
            "tool_use" => "tool_calls".to_string(),
            "stop_sequence" => "stop".to_string(),
            "content_filtered" | "guardrail_intervened" => "content_filter".to_string(),
            other => other.to_string(),
        })
        .unwrap_or_else(|| "stop".to_string());

    let mut out_message = json!({
        "role": "assistant",
        "content": content_text,
    });
    if !tool_calls.is_empty() {
        if let Some(obj) = out_message.as_object_mut() {
            obj.insert("tool_calls".to_string(), Value::Array(tool_calls));
        }
    }

    let usage = m.get("usage");
    let prompt_tokens = usage
        .and_then(|u| u.get("inputTokens"))
        .and_then(|n| n.as_u64())
        .unwrap_or(0);
    let completion_tokens = usage
        .and_then(|u| u.get("outputTokens"))
        .and_then(|n| n.as_u64())
        .unwrap_or(0);
    let total_tokens = usage
        .and_then(|u| u.get("totalTokens"))
        .and_then(|n| n.as_u64())
        .unwrap_or(prompt_tokens + completion_tokens);

    json!({
        "id": "",
        "object": "chat.completion",
        "model": Value::Null,
        "choices": [{
            "index": 0,
            "message": out_message,
            "finish_reason": finish_reason,
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
        },
    })
}

fn extract_content_and_tools(message: &Value) -> (Value, Vec<Value>) {
    let blocks = message
        .get("content")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();

    let mut texts: Vec<String> = Vec::new();
    let mut tool_calls: Vec<Value> = Vec::new();
    for block in blocks {
        if let Some(t) = block.get("text").and_then(|t| t.as_str()) {
            texts.push(t.to_string());
            continue;
        }
        if let Some(tu) = block.get("toolUse") {
            let id = tu
                .get("toolUseId")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let name = tu
                .get("name")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let input = tu
                .get("input")
                .cloned()
                .unwrap_or(Value::Object(Map::new()));
            tool_calls.push(json!({
                "id": id,
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": input.to_string(),
                },
            }));
        }
    }
    (Value::String(texts.join("")), tool_calls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_simple_chat_translation() {
        let body = json!({
            "model": "anthropic.claude-3-5-sonnet-20240620-v1:0",
            "messages": [
                {"role": "user", "content": "hello"}
            ],
            "temperature": 0.7,
            "max_tokens": 512,
        });
        let (out, path) = request_to_native(body, "/v1/chat/completions");
        assert_eq!(
            path,
            "/model/anthropic.claude-3-5-sonnet-20240620-v1:0/converse"
        );
        let messages = out["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], "user");
        assert_eq!(messages[0]["content"][0]["text"], "hello");
        assert_eq!(out["inferenceConfig"]["maxTokens"], 512);
        assert_eq!(out["inferenceConfig"]["temperature"], 0.7);
        // Top-level model is consumed into the path.
        assert!(out.get("model").is_none());
    }

    #[test]
    fn request_system_message_hoisted() {
        let body = json!({
            "model": "anthropic.claude-3-haiku-20240307-v1:0",
            "messages": [
                {"role": "system", "content": "be terse"},
                {"role": "system", "content": "english only"},
                {"role": "user", "content": "hi"}
            ],
        });
        let (out, _) = request_to_native(body, "/v1/chat/completions");
        let system = out["system"].as_array().unwrap();
        assert_eq!(system.len(), 2);
        assert_eq!(system[0]["text"], "be terse");
        assert_eq!(system[1]["text"], "english only");
        let messages = out["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], "user");
    }

    #[test]
    fn request_tool_definitions_translated() {
        let body = json!({
            "model": "anthropic.claude-3-5-sonnet-20240620-v1:0",
            "messages": [{"role": "user", "content": "what's the weather"}],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "look up the weather",
                    "parameters": {
                        "type": "object",
                        "properties": {"city": {"type": "string"}}
                    }
                }
            }],
        });
        let (out, _) = request_to_native(body, "/v1/chat/completions");
        let tools = out["toolConfig"]["tools"].as_array().unwrap();
        assert_eq!(tools[0]["toolSpec"]["name"], "get_weather");
        assert_eq!(tools[0]["toolSpec"]["description"], "look up the weather");
        assert_eq!(
            tools[0]["toolSpec"]["inputSchema"]["json"]["type"],
            "object"
        );
    }

    #[test]
    fn request_tool_choice_translated() {
        let body = json!({
            "model": "anthropic.claude-3-5-sonnet-20240620-v1:0",
            "messages": [{"role": "user", "content": "x"}],
            "tools": [{
                "type": "function",
                "function": {"name": "f", "parameters": {}}
            }],
            "tool_choice": {"type": "function", "function": {"name": "f"}},
        });
        let (out, _) = request_to_native(body, "/v1/chat/completions");
        assert_eq!(out["toolConfig"]["toolChoice"]["tool"]["name"], "f");
    }

    #[test]
    fn request_drops_openai_only_fields() {
        let body = json!({
            "model": "anthropic.claude-3-5-sonnet-20240620-v1:0",
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
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {"text": "Hello "},
                        {"text": "world."}
                    ]
                }
            },
            "stopReason": "end_turn",
            "usage": {
                "inputTokens": 7,
                "outputTokens": 3,
                "totalTokens": 10
            }
        });
        let out = response_to_openai(body);
        assert_eq!(out["object"], "chat.completion");
        assert_eq!(out["choices"][0]["message"]["content"], "Hello world.");
        assert_eq!(out["choices"][0]["finish_reason"], "stop");
        assert_eq!(out["usage"]["prompt_tokens"], 7);
        assert_eq!(out["usage"]["completion_tokens"], 3);
        assert_eq!(out["usage"]["total_tokens"], 10);
    }

    #[test]
    fn response_maps_finish_reasons() {
        for (br, oai) in [
            ("end_turn", "stop"),
            ("max_tokens", "length"),
            ("tool_use", "tool_calls"),
            ("stop_sequence", "stop"),
            ("content_filtered", "content_filter"),
            ("guardrail_intervened", "content_filter"),
        ] {
            let body = json!({
                "output": {"message": {"content": [{"text": "x"}]}},
                "stopReason": br,
            });
            let out = response_to_openai(body);
            assert_eq!(
                out["choices"][0]["finish_reason"], oai,
                "{br} should map to {oai}"
            );
        }
    }

    #[test]
    fn response_extracts_tool_use() {
        let body = json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {"text": "let me check"},
                        {"toolUse": {
                            "toolUseId": "tu_1",
                            "name": "get_weather",
                            "input": {"city": "SF"}
                        }}
                    ]
                }
            },
            "stopReason": "tool_use"
        });
        let out = response_to_openai(body);
        let tool_calls = out["choices"][0]["message"]["tool_calls"]
            .as_array()
            .expect("tool_calls present");
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0]["id"], "tu_1");
        assert_eq!(tool_calls[0]["function"]["name"], "get_weather");
        let parsed: Value =
            serde_json::from_str(tool_calls[0]["function"]["arguments"].as_str().unwrap()).unwrap();
        assert_eq!(parsed["city"], "SF");
    }

    #[test]
    fn round_trip_minimal() {
        let req = json!({
            "model": "anthropic.claude-3-haiku-20240307-v1:0",
            "messages": [{"role": "user", "content": "hi"}],
        });
        let (native, path) = request_to_native(req, "/v1/chat/completions");
        assert!(path.ends_with("/converse"));
        assert_eq!(native["messages"][0]["content"][0]["text"], "hi");

        let raw = json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": "hello"}]
                }
            },
            "stopReason": "end_turn",
            "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2}
        });
        let out = response_to_openai(raw);
        assert_eq!(out["choices"][0]["message"]["content"], "hello");
        assert_eq!(out["usage"]["total_tokens"], 2);
    }
}
