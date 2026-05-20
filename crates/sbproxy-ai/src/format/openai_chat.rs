//! OpenAI Chat Completions `ChatFormat` implementation.
//!
//! The hub format mirrors the OpenAI Chat Completions wire shape, so
//! this implementation is the closest thing to an identity translator
//! the trait has. It still has to:
//!
//!   * Hoist interleaved `system` turns into the hub's top-level
//!     `system` field so cross-format emitters that want a single
//!     system prompt (Anthropic) work.
//!   * Convert OpenAI's stringified `function.arguments` into typed
//!     JSON for tool calls so every other emitter sees structured
//!     arguments.
//!   * Re-stringify those arguments on the way out so OpenAI clients
//!     see the wire shape they expect.
//!
//! Streaming is wired end to end here because the OpenAI SSE format is
//! the hub's reference shape; other formats grow the same wiring under
//! WOR-226.

use serde_json::{json, Map, Value};

use super::{
    BridgeContext, ChatError, ChatFormat, ContentPart, ContentPartDelta, FinishReason, HubChunk,
    HubMessage, HubRequest, HubResponse, HubToolChoice, HubToolDefinition, Role,
};

/// Inbound path the format claims.
const INBOUND_PATHS: &[&str] = &["/v1/chat/completions"];

/// `ChatFormat` for OpenAI Chat Completions.
#[derive(Debug, Default, Clone, Copy)]
pub struct OpenAiChatFormat;

impl ChatFormat for OpenAiChatFormat {
    fn id(&self) -> &'static str {
        "openai"
    }

    fn inbound_paths(&self) -> &'static [&'static str] {
        INBOUND_PATHS
    }

    fn to_hub(&self, bytes: &[u8]) -> Result<(HubRequest, BridgeContext), ChatError> {
        let raw: Value = serde_json::from_slice(bytes)
            .map_err(|e| ChatError::bad_request(format!("invalid JSON body: {e}")))?;
        let obj = raw
            .as_object()
            .ok_or_else(|| ChatError::bad_request("request body must be a JSON object"))?;

        let mut hub = HubRequest {
            model: obj
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            temperature: obj
                .get("temperature")
                .and_then(|v| v.as_f64())
                .map(|f| f as f32),
            top_p: obj.get("top_p").and_then(|v| v.as_f64()).map(|f| f as f32),
            top_k: obj.get("top_k").and_then(|v| v.as_u64()).map(|n| n as u32),
            max_tokens: obj
                .get("max_tokens")
                .and_then(|v| v.as_u64())
                .map(|n| n as u32),
            stream: obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false),
            ..Default::default()
        };

        // Stop sequences accept a string or a list of strings.
        if let Some(stop) = obj.get("stop") {
            if let Some(s) = stop.as_str() {
                hub.stop.push(s.to_string());
            } else if let Some(arr) = stop.as_array() {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        hub.stop.push(s.to_string());
                    }
                }
            }
        }

        // Messages: hoist system turns, parse tool calls and content parts.
        let mut system_chunks: Vec<String> = Vec::new();
        if let Some(arr) = obj.get("messages").and_then(|v| v.as_array()) {
            for m in arr {
                if let Some(msg_obj) = m.as_object() {
                    let role = msg_obj.get("role").and_then(|r| r.as_str()).unwrap_or("");
                    if role == "system" {
                        if let Some(s) = msg_obj.get("content").and_then(|c| c.as_str()) {
                            system_chunks.push(s.to_string());
                        }
                        continue;
                    }
                    let hub_msg = parse_openai_message(msg_obj)?;
                    hub.messages.push(hub_msg);
                }
            }
        }
        if !system_chunks.is_empty() {
            hub.system = Some(system_chunks.join("\n\n"));
        }

        // Tools.
        if let Some(arr) = obj.get("tools").and_then(|v| v.as_array()) {
            for t in arr {
                if let Some(fobj) = t.get("function").and_then(|f| f.as_object()) {
                    hub.tools.push(HubToolDefinition {
                        name: fobj
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string(),
                        description: fobj
                            .get("description")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string(),
                        parameters: fobj.get("parameters").cloned().unwrap_or(Value::Null),
                    });
                }
            }
        }

        // Tool choice. OpenAI's wire form is `"auto"`, `"none"`, or
        // `{"type":"function","function":{"name":"..."}}`.
        if let Some(tc) = obj.get("tool_choice") {
            hub.tool_choice = match tc {
                Value::String(s) if s == "none" => HubToolChoice::None,
                Value::String(s) if s == "auto" => HubToolChoice::Auto,
                Value::Object(o) => {
                    if let Some(name) = o
                        .get("function")
                        .and_then(|f| f.get("name"))
                        .and_then(|n| n.as_str())
                    {
                        HubToolChoice::Required(name.to_string())
                    } else {
                        HubToolChoice::Auto
                    }
                }
                _ => HubToolChoice::Auto,
            };
        }

        // `response_format` rides on the extensions map; only the
        // OpenAI emitter knows what to do with it.
        if let Some(rf) = obj.get("response_format").cloned() {
            hub.extensions.insert("openai.response_format".into(), rf);
        }

        let ctx = BridgeContext {
            inbound_format: self.id().into(),
            inbound_path: "/v1/chat/completions".into(),
            stream: hub.stream,
            ..Default::default()
        };
        Ok((hub, ctx))
    }

    fn from_hub(&self, resp: &HubResponse, _ctx: &BridgeContext) -> Result<Vec<u8>, ChatError> {
        let value = hub_response_to_openai_value(resp);
        serde_json::to_vec(&value)
            .map_err(|e| ChatError::bad_request(format!("failed to serialise response: {e}")))
    }

    fn from_hub_stream(
        &self,
        chunk: &HubChunk,
        _ctx: &BridgeContext,
    ) -> Result<Vec<String>, ChatError> {
        Ok(hub_chunk_to_openai_sse(chunk))
    }
}

/// Parse one OpenAI message object into a `HubMessage`. Pulled out so
/// both the live request path and the test fixtures can call it.
pub(crate) fn parse_openai_message(obj: &Map<String, Value>) -> Result<HubMessage, ChatError> {
    // WOR-599: missing or unknown role is an error, not a silent default to
    // user. Shared helper lives in the format module.
    let role = super::parse_role(obj)?;

    let mut content: Vec<ContentPart> = Vec::new();

    // OpenAI allows `content` to be a string or an array of content
    // parts. Some assistant turns omit `content` entirely when they
    // only carry `tool_calls`.
    if let Some(c) = obj.get("content") {
        match c {
            Value::String(s) if !s.is_empty() => {
                content.push(ContentPart::Text { text: s.clone() });
            }
            Value::String(_) => {}
            Value::Array(arr) => {
                for part in arr {
                    if let Some(p) = part.as_object() {
                        let ty = p.get("type").and_then(|t| t.as_str()).unwrap_or("");
                        match ty {
                            "text" => {
                                if let Some(t) = p.get("text").and_then(|t| t.as_str()) {
                                    content.push(ContentPart::Text { text: t.into() });
                                }
                            }
                            "image_url" => {
                                let url = p
                                    .get("image_url")
                                    .and_then(|i| i.get("url"))
                                    .and_then(|u| u.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                content.push(ContentPart::Image {
                                    source: url,
                                    media_type: "image/*".into(),
                                });
                            }
                            _ => {}
                        }
                    }
                }
            }
            Value::Null => {}
            _ => {}
        }
    }

    // Assistant turns can carry tool_calls.
    if let Some(arr) = obj.get("tool_calls").and_then(|v| v.as_array()) {
        for tc in arr {
            let id = tc
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let function = tc.get("function").and_then(|f| f.as_object());
            let name = function
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            // arguments comes in as a JSON string; parse it back into
            // structured JSON for the hub. Fall back to a string-wrapped
            // value when the upstream sent something we can't parse.
            let raw_args = function
                .and_then(|f| f.get("arguments"))
                .cloned()
                .unwrap_or(Value::Null);
            let input = match &raw_args {
                // OpenAI encodes tool-call arguments as a JSON string. An empty
                // string means "no arguments". Anything non-empty must be valid
                // JSON: surfacing it as a raw string would hand the hub a
                // string-shaped value where structured arguments are expected.
                Value::String(s) if s.trim().is_empty() => Value::Object(Map::new()),
                Value::String(s) => serde_json::from_str(s).map_err(|_| {
                    ChatError::bad_request("tool call arguments are not valid JSON")
                })?,
                other => other.clone(),
            };
            content.push(ContentPart::ToolUse {
                id: id.clone(),
                name: name.clone(),
                input,
            });
        }
    }

    // Tool role messages carry a `tool_call_id` and a single text body.
    let tool_call_id = obj
        .get("tool_call_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if role == Role::Tool {
        let mut body = String::new();
        if let Some(c) = obj.get("content").and_then(|c| c.as_str()) {
            body = c.to_string();
        }
        let id = tool_call_id.clone().unwrap_or_default();
        content.clear();
        content.push(ContentPart::ToolResult {
            tool_call_id: id,
            content: body,
            is_error: false,
        });
    }

    Ok(HubMessage {
        role,
        content,
        name: obj
            .get("name")
            .and_then(|n| n.as_str())
            .map(|s| s.to_string()),
        tool_call_id,
    })
}

/// Serialise a `HubResponse` into the OpenAI Chat Completions wire shape.
pub(crate) fn hub_response_to_openai_value(resp: &HubResponse) -> Value {
    let mut content_text = String::new();
    let mut tool_calls: Vec<Value> = Vec::new();

    let blocks_iter = resp
        .content
        .iter()
        .chain(resp.tool_calls.iter().map(|_| unreachable!()).take(0));

    for part in blocks_iter {
        match part {
            ContentPart::Text { text } => content_text.push_str(text),
            ContentPart::ToolUse { id, name, input } => {
                tool_calls.push(json!({
                    "id": id,
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": input.to_string(),
                    },
                }));
            }
            ContentPart::Image { .. } | ContentPart::ToolResult { .. } => {
                // Assistant turns do not produce image or tool-result
                // content blocks in the OpenAI wire shape.
            }
        }
    }

    // Tool calls surfaced through the dedicated `tool_calls` slot
    // (separate from content parts).
    for tc in &resp.tool_calls {
        tool_calls.push(json!({
            "id": tc.id,
            "type": "function",
            "function": {
                "name": tc.name,
                "arguments": tc.arguments.to_string(),
            },
        }));
    }

    let mut message = json!({
        "role": "assistant",
        "content": content_text,
    });
    if !tool_calls.is_empty() {
        if let Some(obj) = message.as_object_mut() {
            obj.insert("tool_calls".into(), Value::Array(tool_calls));
        }
    }

    json!({
        "id": resp.id,
        "object": "chat.completion",
        "model": resp.model,
        "choices": [{
            "index": 0,
            "message": message,
            "finish_reason": finish_reason_to_openai(&resp.finish_reason),
        }],
        "usage": {
            "prompt_tokens": resp.usage.prompt_tokens,
            "completion_tokens": resp.usage.completion_tokens,
            "total_tokens": resp.usage.total_tokens,
        },
    })
}

pub(crate) fn finish_reason_to_openai(r: &FinishReason) -> &str {
    match r {
        FinishReason::Stop => "stop",
        FinishReason::Length => "length",
        FinishReason::ToolCalls => "tool_calls",
        FinishReason::ContentFilter => "content_filter",
        FinishReason::Other(s) => s.as_str(),
    }
}

fn hub_chunk_to_openai_sse(chunk: &HubChunk) -> Vec<String> {
    match chunk {
        HubChunk::MessageStart { id, model } => {
            // OpenAI's first SSE chunk carries an empty delta with the
            // role set on the choice.
            let body = json!({
                "id": id,
                "object": "chat.completion.chunk",
                "model": model,
                "choices": [{
                    "index": 0,
                    "delta": {"role": "assistant"},
                    "finish_reason": null,
                }],
            });
            vec![format!("data: {body}\n\n")]
        }
        HubChunk::ContentDelta { index, delta } => match delta {
            ContentPartDelta::Text(t) => {
                let body = json!({
                    "object": "chat.completion.chunk",
                    "choices": [{
                        "index": index,
                        "delta": {"content": t},
                        "finish_reason": null,
                    }],
                });
                vec![format!("data: {body}\n\n")]
            }
        },
        HubChunk::ToolCallDelta { index, delta } => {
            let mut tc = Map::new();
            tc.insert("index".into(), json!(index));
            if let Some(id) = &delta.id {
                tc.insert("id".into(), Value::String(id.clone()));
            }
            tc.insert("type".into(), Value::String("function".into()));
            let mut function = Map::new();
            if let Some(name) = &delta.name {
                function.insert("name".into(), Value::String(name.clone()));
            }
            if let Some(args) = &delta.arguments_chunk {
                function.insert("arguments".into(), Value::String(args.clone()));
            }
            tc.insert("function".into(), Value::Object(function));
            let body = json!({
                "object": "chat.completion.chunk",
                "choices": [{
                    "index": 0,
                    "delta": {"tool_calls": [Value::Object(tc)]},
                    "finish_reason": null,
                }],
            });
            vec![format!("data: {body}\n\n")]
        }
        HubChunk::Usage(u) => {
            let body = json!({
                "object": "chat.completion.chunk",
                "choices": [],
                "usage": {
                    "prompt_tokens": u.prompt_tokens,
                    "completion_tokens": u.completion_tokens,
                    "total_tokens": u.total_tokens,
                },
            });
            vec![format!("data: {body}\n\n")]
        }
        HubChunk::MessageStop { finish_reason } => {
            let fr = finish_reason_to_openai(finish_reason);
            let body = json!({
                "object": "chat.completion.chunk",
                "choices": [{
                    "index": 0,
                    "delta": {},
                    "finish_reason": fr,
                }],
            });
            vec![format!("data: {body}\n\n"), "data: [DONE]\n\n".to_string()]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::HubToolCall;
    use super::*;
    use serde_json::json;

    fn fmt() -> OpenAiChatFormat {
        OpenAiChatFormat
    }

    #[test]
    fn simple_chat_round_trip_text_only() {
        let req = json!({
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hi"}],
        });
        let (hub, ctx) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.model, "gpt-4o-mini");
        assert_eq!(hub.messages.len(), 1);
        assert_eq!(hub.messages[0].role, Role::User);
        match &hub.messages[0].content[0] {
            ContentPart::Text { text } => assert_eq!(text, "hi"),
            other => panic!("expected text part, got {other:?}"),
        }
        assert_eq!(ctx.inbound_format, "openai");
    }

    #[test]
    fn system_messages_are_hoisted() {
        let req = json!({
            "messages": [
                {"role": "system", "content": "tone is formal"},
                {"role": "system", "content": "answer in english"},
                {"role": "user", "content": "hello"}
            ]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(
            hub.system.as_deref(),
            Some("tone is formal\n\nanswer in english")
        );
        assert_eq!(hub.messages.len(), 1);
        assert_eq!(hub.messages[0].role, Role::User);
    }

    #[test]
    fn tool_calls_round_trip_typed_arguments() {
        let req = json!({
            "messages": [{
                "role": "assistant",
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "get_weather", "arguments": "{\"city\":\"SF\"}"}
                }]
            }]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        let parts = &hub.messages[0].content;
        let tool_use = parts.iter().find_map(|p| match p {
            ContentPart::ToolUse { id, name, input } => Some((id, name, input)),
            _ => None,
        });
        let (id, name, input) = tool_use.expect("tool_use part present");
        assert_eq!(id, "call_1");
        assert_eq!(name, "get_weather");
        assert_eq!(input["city"], "SF");

        // Now go back the other way.
        let resp = HubResponse {
            id: "resp_1".into(),
            model: "gpt-4o-mini".into(),
            tool_calls: vec![HubToolCall {
                id: id.clone(),
                name: name.clone(),
                arguments: input.clone(),
            }],
            finish_reason: FinishReason::ToolCalls,
            ..Default::default()
        };
        let bytes = fmt().from_hub(&resp, &BridgeContext::default()).unwrap();
        let out: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            out["choices"][0]["message"]["tool_calls"][0]["id"],
            "call_1"
        );
        assert_eq!(
            out["choices"][0]["message"]["tool_calls"][0]["function"]["name"],
            "get_weather"
        );
        // arguments come back as a string per OpenAI's wire shape.
        let args_str = out["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        let args_val: Value = serde_json::from_str(args_str).unwrap();
        assert_eq!(args_val["city"], "SF");
    }

    #[test]
    fn invalid_json_is_400() {
        let err = fmt().to_hub(b"not json").unwrap_err();
        assert_eq!(err.status(), 400);
    }

    #[test]
    fn stream_chunks_terminate_with_done() {
        let mut frames: Vec<String> = Vec::new();
        frames.extend(
            fmt()
                .from_hub_stream(
                    &HubChunk::MessageStart {
                        id: "resp_1".into(),
                        model: "gpt-4o-mini".into(),
                    },
                    &BridgeContext::default(),
                )
                .unwrap(),
        );
        frames.extend(
            fmt()
                .from_hub_stream(
                    &HubChunk::MessageStop {
                        finish_reason: FinishReason::Stop,
                    },
                    &BridgeContext::default(),
                )
                .unwrap(),
        );
        assert!(frames.iter().any(|f| f.contains("[DONE]")));
    }
}
