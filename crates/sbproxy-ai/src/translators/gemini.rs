//! OpenAI ⇄ Google Gemini translator.
//!
//! Maps the OpenAI chat-completions shape to and from Google's
//! Generative Language `generateContent` API (used by both Gemini
//! direct and Vertex AI's OpenAI-incompatible surface). Covers the
//! fields most clients use: messages, system prompt, model,
//! temperature, top_p, top_k, max_tokens, stop sequences, and tool
//! calls.
//!
//! Streaming SSE event translation is out of scope here; setting
//! `stream: true` forwards as-is and the response stays in Gemini's
//! native SSE shape until the sibling streaming-translation ticket
//! lands.

use serde_json::{json, Map, Value};

/// Convert an OpenAI request body to Gemini `generateContent` shape.
///
/// Differences handled:
///   * The OpenAI `messages` array becomes Gemini `contents`. Each
///     message's `role` maps as `user` -> `user`, `assistant` ->
///     `model`. The `system` role is hoisted to a top-level
///     `systemInstruction` field (Gemini does not allow `system` in
///     `contents`).
///   * Plain-text `content: "..."` becomes a single `{text: "..."}`
///     part. Multimodal `content: [{type:"text", text}, ...]` arrays
///     are translated part by part.
///   * Sampling knobs (`temperature`, `top_p`, `top_k`, `max_tokens`,
///     `stop`) move under `generationConfig`.
///   * `tools: [{type:"function", function:{name, parameters,
///     description}}]` becomes `tools: [{functionDeclarations: [...]}]`.
///   * `tool_calls` on assistant messages become content parts with
///     `functionCall`. `role: "tool"` messages become user-role
///     `functionResponse` parts.
///   * The path is rewritten from `/v1/chat/completions` to
///     `/v1beta/models/{model}:generateContent`.
///   * Unsupported OpenAI knobs (`logit_bias`, `n`,
///     `presence_penalty`, `frequency_penalty`, `response_format`,
///     `seed`, `user`) are dropped. Unknown extensions pass through
///     untouched at the top level.
pub fn request_to_native(body: Value, path: &str) -> (Value, String) {
    // WOR-824 item 2: surface dispatch. Embedding requests reach the
    // gateway at /v1/embeddings; route them to the embeddings
    // sub-translator instead of pretending they are chat.
    if super::gemini_embeddings::is_embeddings_path(path) {
        return super::gemini_embeddings::request_to_native(body, path);
    }

    let mut obj: Map<String, Value> = match body {
        Value::Object(m) => m,
        other => return (other, path.to_string()),
    };

    let model = obj
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // 1. Hoist system role messages to systemInstruction.
    let mut system_chunks: Vec<String> = Vec::new();
    let raw_messages = obj.remove("messages").unwrap_or(Value::Null);
    let messages = match raw_messages {
        Value::Array(a) => a,
        _ => Vec::new(),
    };
    let mut contents: Vec<Value> = Vec::new();
    for m in messages {
        let role = m.get("role").and_then(|r| r.as_str()).unwrap_or("");
        if role == "system" {
            if let Some(s) = m.get("content").and_then(|c| c.as_str()) {
                system_chunks.push(s.to_string());
            } else if let Some(arr) = m.get("content").and_then(|c| c.as_array()) {
                for p in arr {
                    if let Some(t) = p.get("text").and_then(|t| t.as_str()) {
                        system_chunks.push(t.to_string());
                    }
                }
            }
            continue;
        }
        contents.push(message_to_content(&m));
    }
    if !system_chunks.is_empty() {
        obj.insert(
            "systemInstruction".to_string(),
            json!({
                "parts": [{"text": system_chunks.join("\n\n")}],
            }),
        );
    }
    obj.insert("contents".to_string(), Value::Array(contents));

    // 2. Move sampling knobs under generationConfig.
    let mut gen_cfg: Map<String, Value> = Map::new();
    if let Some(v) = obj.remove("temperature") {
        gen_cfg.insert("temperature".to_string(), v);
    }
    if let Some(v) = obj.remove("top_p") {
        gen_cfg.insert("topP".to_string(), v);
    }
    if let Some(v) = obj.remove("top_k") {
        gen_cfg.insert("topK".to_string(), v);
    }
    if let Some(v) = obj.remove("max_tokens") {
        gen_cfg.insert("maxOutputTokens".to_string(), v);
    }
    if let Some(v) = obj.remove("stop") {
        let seqs = match v {
            Value::String(s) => Value::Array(vec![Value::String(s)]),
            arr @ Value::Array(_) => arr,
            other => other,
        };
        gen_cfg.insert("stopSequences".to_string(), seqs);
    }
    if !gen_cfg.is_empty() {
        obj.insert("generationConfig".to_string(), Value::Object(gen_cfg));
    }

    // 3. Translate tools.
    if let Some(Value::Array(tools)) = obj.remove("tools") {
        let mut decls: Vec<Value> = Vec::new();
        for t in tools {
            if let Some(func) = t.get("function") {
                let mut decl = Map::new();
                if let Some(name) = func.get("name") {
                    decl.insert("name".to_string(), name.clone());
                }
                if let Some(desc) = func.get("description") {
                    decl.insert("description".to_string(), desc.clone());
                }
                if let Some(params) = func.get("parameters") {
                    decl.insert("parameters".to_string(), params.clone());
                }
                decls.push(Value::Object(decl));
            }
        }
        if !decls.is_empty() {
            obj.insert(
                "tools".to_string(),
                Value::Array(vec![json!({"functionDeclarations": decls})]),
            );
        }
    }

    // 4. Drop OpenAI-only knobs Gemini rejects.
    for k in [
        "logit_bias",
        "n",
        "presence_penalty",
        "frequency_penalty",
        "response_format",
        "seed",
        "user",
        "model",
    ] {
        obj.remove(k);
    }

    // 5. Path rewrite. Translator only supports chat completions today.
    let new_path = if path.ends_with("/chat/completions") && !model.is_empty() {
        format!("/v1beta/models/{}:generateContent", model)
    } else {
        path.to_string()
    };

    (Value::Object(obj), new_path)
}

/// Convert an OpenAI chat-completions message into a Gemini content
/// entry. Handles plain-text strings, multimodal content arrays, and
/// `tool_calls` (assistant turn) / `role: "tool"` (tool result turn)
/// shapes.
fn message_to_content(m: &Value) -> Value {
    let role = m.get("role").and_then(|r| r.as_str()).unwrap_or("user");
    let gem_role = match role {
        "assistant" => "model",
        "tool" => "user",
        _ => "user",
    };

    let mut parts: Vec<Value> = Vec::new();

    // Tool result: `role: "tool"`, `tool_call_id`, `content`.
    if role == "tool" {
        let name = m
            .get("name")
            .and_then(|v| v.as_str())
            .or_else(|| m.get("tool_call_id").and_then(|v| v.as_str()))
            .unwrap_or("")
            .to_string();
        let response = match m.get("content") {
            Some(Value::String(s)) => json!({"content": s}),
            Some(other) => other.clone(),
            None => Value::Null,
        };
        parts.push(json!({
            "functionResponse": {
                "name": name,
                "response": response,
            }
        }));
        return json!({"role": gem_role, "parts": parts});
    }

    // Plain-text or multimodal content.
    match m.get("content") {
        Some(Value::String(s)) if !s.is_empty() => {
            parts.push(json!({"text": s}));
        }
        Some(Value::Array(arr)) => {
            for p in arr {
                let ty = p.get("type").and_then(|t| t.as_str()).unwrap_or("");
                match ty {
                    "text" => {
                        if let Some(t) = p.get("text").and_then(|s| s.as_str()) {
                            parts.push(json!({"text": t}));
                        }
                    }
                    "image_url" => {
                        if let Some(url) = p
                            .get("image_url")
                            .and_then(|i| i.get("url"))
                            .and_then(|u| u.as_str())
                        {
                            parts.push(json!({"fileData": {"fileUri": url}}));
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }

    // Tool calls on an assistant message become functionCall parts.
    if let Some(Value::Array(tool_calls)) = m.get("tool_calls") {
        for tc in tool_calls {
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
            let args: Value = serde_json::from_str(args_str).unwrap_or(Value::Null);
            parts.push(json!({
                "functionCall": {
                    "name": name,
                    "args": args,
                }
            }));
        }
    }

    json!({"role": gem_role, "parts": parts})
}

/// Convert a Gemini `generateContent` response back to the OpenAI
/// chat-completions shape so OpenAI SDK clients can parse it.
///
/// Field map:
///   * Gemini `candidates[0].content.parts[]` ->
///     OpenAI `choices[0].message.content` (text parts concatenated).
///     `functionCall` parts become `tool_calls` on the message.
///   * Gemini `candidates[0].finishReason` -> OpenAI `finish_reason`
///     (`STOP` -> `stop`, `MAX_TOKENS` -> `length`, `SAFETY` ->
///     `content_filter`, `RECITATION` -> `content_filter`, others
///     pass through lowercased).
///   * Gemini `usageMetadata.promptTokenCount` /
///     `candidatesTokenCount` -> OpenAI `usage.prompt_tokens` /
///     `completion_tokens`.
///   * `modelVersion` (when present) -> OpenAI `model`.
pub fn response_to_openai(body: Value) -> Value {
    // WOR-824 item 2: shape-based dispatch. A Gemini embeddings
    // response carries `embedding` or `embeddings` at the top
    // level (no `candidates`); send it to the embeddings sub-
    // translator. Detecting by shape rather than threading the
    // path through the existing signature keeps the dispatcher
    // API unchanged.
    if super::gemini_embeddings::looks_like_embeddings_response(&body) {
        return super::gemini_embeddings::response_to_openai(body);
    }

    let m = match body {
        Value::Object(m) => m,
        other => return other,
    };

    let model = m
        .get("modelVersion")
        .cloned()
        .or_else(|| m.get("model").cloned())
        .unwrap_or(Value::Null);

    let candidates = m
        .get("candidates")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();
    let first = candidates.first().cloned().unwrap_or(Value::Null);

    let (content_text, tool_calls) = extract_content_and_tools(&first);

    let finish_reason = first
        .get("finishReason")
        .and_then(|s| s.as_str())
        .map(|s| match s {
            "STOP" => "stop".to_string(),
            "MAX_TOKENS" => "length".to_string(),
            "SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" => {
                "content_filter".to_string()
            }
            other => other.to_lowercase(),
        })
        .unwrap_or_else(|| "stop".to_string());

    let mut message = json!({
        "role": "assistant",
        "content": content_text,
    });
    if !tool_calls.is_empty() {
        if let Some(obj) = message.as_object_mut() {
            obj.insert("tool_calls".to_string(), Value::Array(tool_calls));
        }
    }

    let usage_meta = m.get("usageMetadata");
    let prompt_tokens = usage_meta
        .and_then(|u| u.get("promptTokenCount"))
        .and_then(|n| n.as_u64())
        .unwrap_or(0);
    let completion_tokens = usage_meta
        .and_then(|u| u.get("candidatesTokenCount"))
        .and_then(|n| n.as_u64())
        .unwrap_or(0);
    let total_tokens = usage_meta
        .and_then(|u| u.get("totalTokenCount"))
        .and_then(|n| n.as_u64())
        .unwrap_or(prompt_tokens + completion_tokens);

    let id = m
        .get("responseId")
        .cloned()
        .unwrap_or_else(|| Value::String(String::new()));

    json!({
        "id": id,
        "object": "chat.completion",
        "model": model,
        "choices": [{
            "index": 0,
            "message": message,
            "finish_reason": finish_reason,
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
        },
    })
}

fn extract_content_and_tools(candidate: &Value) -> (Value, Vec<Value>) {
    let parts = candidate
        .get("content")
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();

    let mut texts: Vec<String> = Vec::new();
    let mut tool_calls: Vec<Value> = Vec::new();
    for (idx, part) in parts.iter().enumerate() {
        if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
            texts.push(t.to_string());
            continue;
        }
        if let Some(fc) = part.get("functionCall") {
            let name = fc
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            let args = fc.get("args").cloned().unwrap_or(Value::Object(Map::new()));
            tool_calls.push(json!({
                "id": format!("call_{}", idx),
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": args.to_string(),
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
            "model": "gemini-1.5-pro",
            "messages": [
                {"role": "user", "content": "hello"}
            ],
            "temperature": 0.5,
            "max_tokens": 256,
        });
        let (out, path) = request_to_native(body, "/v1/chat/completions");
        assert_eq!(path, "/v1beta/models/gemini-1.5-pro:generateContent");
        let contents = out["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["role"], "user");
        assert_eq!(contents[0]["parts"][0]["text"], "hello");
        assert_eq!(out["generationConfig"]["temperature"], 0.5);
        assert_eq!(out["generationConfig"]["maxOutputTokens"], 256);
        // `model` is consumed into the path.
        assert!(out.get("model").is_none());
    }

    #[test]
    fn request_system_message_hoisted() {
        let body = json!({
            "model": "gemini-1.5-pro",
            "messages": [
                {"role": "system", "content": "be terse"},
                {"role": "system", "content": "answer in english"},
                {"role": "user", "content": "hi"}
            ],
        });
        let (out, _) = request_to_native(body, "/v1/chat/completions");
        assert_eq!(
            out["systemInstruction"]["parts"][0]["text"],
            "be terse\n\nanswer in english"
        );
        let contents = out["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["role"], "user");
    }

    #[test]
    fn request_assistant_role_renamed_to_model() {
        let body = json!({
            "model": "gemini-1.5-flash",
            "messages": [
                {"role": "user", "content": "hi"},
                {"role": "assistant", "content": "hello back"},
                {"role": "user", "content": "more"}
            ],
        });
        let (out, _) = request_to_native(body, "/v1/chat/completions");
        let contents = out["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 3);
        assert_eq!(contents[0]["role"], "user");
        assert_eq!(contents[1]["role"], "model");
        assert_eq!(contents[2]["role"], "user");
    }

    #[test]
    fn request_tool_definitions_translated() {
        let body = json!({
            "model": "gemini-1.5-pro",
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
        let decls = &out["tools"][0]["functionDeclarations"];
        assert_eq!(decls[0]["name"], "get_weather");
        assert_eq!(decls[0]["description"], "look up the weather");
        assert_eq!(decls[0]["parameters"]["type"], "object");
    }

    #[test]
    fn request_drops_openai_only_fields() {
        let body = json!({
            "model": "gemini-1.5-pro",
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
    fn response_concatenates_text_parts() {
        let body = json!({
            "responseId": "gen_01",
            "modelVersion": "gemini-1.5-pro",
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [
                        {"text": "Hello "},
                        {"text": "world."}
                    ]
                },
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 7,
                "candidatesTokenCount": 3,
                "totalTokenCount": 10
            }
        });
        let out = response_to_openai(body);
        assert_eq!(out["id"], "gen_01");
        assert_eq!(out["model"], "gemini-1.5-pro");
        assert_eq!(out["object"], "chat.completion");
        assert_eq!(out["choices"][0]["message"]["content"], "Hello world.");
        assert_eq!(out["choices"][0]["finish_reason"], "stop");
        assert_eq!(out["usage"]["prompt_tokens"], 7);
        assert_eq!(out["usage"]["completion_tokens"], 3);
        assert_eq!(out["usage"]["total_tokens"], 10);
    }

    #[test]
    fn response_maps_finish_reasons() {
        for (gem, oai) in [
            ("STOP", "stop"),
            ("MAX_TOKENS", "length"),
            ("SAFETY", "content_filter"),
            ("RECITATION", "content_filter"),
        ] {
            let body = json!({
                "candidates": [{
                    "content": {"parts": [{"text": "x"}]},
                    "finishReason": gem,
                }]
            });
            let out = response_to_openai(body);
            assert_eq!(
                out["choices"][0]["finish_reason"], oai,
                "{gem} should map to {oai}"
            );
        }
    }

    #[test]
    fn response_extracts_function_call() {
        let body = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"text": "let me check"},
                        {"functionCall": {
                            "name": "get_weather",
                            "args": {"city": "SF"}
                        }}
                    ]
                },
                "finishReason": "STOP"
            }]
        });
        let out = response_to_openai(body);
        let tool_calls = out["choices"][0]["message"]["tool_calls"]
            .as_array()
            .expect("tool_calls present");
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0]["function"]["name"], "get_weather");
        // Arguments are JSON-stringified so OpenAI SDKs can parse them.
        let parsed: Value =
            serde_json::from_str(tool_calls[0]["function"]["arguments"].as_str().unwrap()).unwrap();
        assert_eq!(parsed["city"], "SF");
    }

    #[test]
    fn round_trip_minimal() {
        let req = json!({
            "model": "gemini-1.5-flash",
            "messages": [{"role": "user", "content": "hi"}],
        });
        let (native, path) = request_to_native(req, "/v1/chat/completions");
        assert!(path.contains(":generateContent"));
        assert_eq!(native["contents"][0]["parts"][0]["text"], "hi");
        let raw = json!({
            "responseId": "g_xyz",
            "modelVersion": "gemini-1.5-flash",
            "candidates": [{
                "content": {"parts": [{"text": "hello"}]},
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 1,
                "candidatesTokenCount": 1,
                "totalTokenCount": 2
            }
        });
        let out = response_to_openai(raw);
        assert_eq!(out["choices"][0]["message"]["content"], "hello");
        assert_eq!(out["usage"]["total_tokens"], 2);
    }
}
