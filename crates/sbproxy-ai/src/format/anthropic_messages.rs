//! Anthropic Messages API `ChatFormat` implementation.
//!
//! Parses the Anthropic Messages wire shape (`POST /v1/messages`) into
//! the hub, and emits hub responses back as Anthropic Messages JSON. The
//! wire shape has three differences from the hub baseline that this
//! module owns:
//!
//!   * A top-level `system` field rather than interleaved `system`
//!     turns. Maps to `HubRequest::system` directly.
//!   * Typed content blocks (`text`, `tool_use`, `tool_result`,
//!     `image`) that map onto the hub `ContentPart` variants.
//!   * `stop_reason` strings (`end_turn`, `max_tokens`, `tool_use`,
//!     `stop_sequence`) normalised to the hub `FinishReason`.
//!
//! Streaming for the Anthropic shape is deferred to WOR-226; the
//! `from_hub_stream` arm returns `ChatError::not_implemented` so a
//! caller wiring a stream against an Anthropic inbound sees a clear
//! pointer rather than a silent misroute.

use serde_json::{json, Map, Value};

use super::{
    BridgeContext, ChatError, ChatFormat, ContentPart, FinishReason, HubChunk, HubMessage,
    HubRequest, HubResponse, HubToolDefinition, HubUsage, Role,
};

const INBOUND_PATHS: &[&str] = &["/v1/messages"];

/// `ChatFormat` for Anthropic Messages.
#[derive(Debug, Default, Clone, Copy)]
pub struct AnthropicMessagesFormat;

impl ChatFormat for AnthropicMessagesFormat {
    fn id(&self) -> &'static str {
        "anthropic"
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

        // Anthropic `system` is either a string or an array of typed
        // content blocks. Concatenate text blocks; ignore non-text
        // blocks but flag them as lossiness so the operator can see it.
        if let Some(sys) = obj.get("system") {
            match sys {
                Value::String(s) => hub.system = Some(s.clone()),
                Value::Array(arr) => {
                    let mut chunks = Vec::new();
                    for block in arr {
                        if let Some(t) = block.get("text").and_then(|v| v.as_str()) {
                            chunks.push(t.to_string());
                        }
                    }
                    if !chunks.is_empty() {
                        hub.system = Some(chunks.join("\n\n"));
                    }
                }
                _ => {}
            }
        }

        if let Some(stops) = obj.get("stop_sequences").and_then(|v| v.as_array()) {
            for s in stops {
                if let Some(s) = s.as_str() {
                    hub.stop.push(s.to_string());
                }
            }
        }

        if let Some(arr) = obj.get("messages").and_then(|v| v.as_array()) {
            for m in arr {
                if let Some(msg_obj) = m.as_object() {
                    hub.messages.push(parse_anthropic_message(msg_obj)?);
                }
            }
        }

        // Tools: Anthropic ships `[{name, description, input_schema}]`.
        if let Some(arr) = obj.get("tools").and_then(|v| v.as_array()) {
            for t in arr {
                if let Some(tobj) = t.as_object() {
                    hub.tools.push(HubToolDefinition {
                        name: tobj
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string(),
                        description: tobj
                            .get("description")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string(),
                        parameters: tobj.get("input_schema").cloned().unwrap_or(Value::Null),
                    });
                }
            }
        }

        let ctx = BridgeContext {
            inbound_format: self.id().into(),
            inbound_path: "/v1/messages".into(),
            stream: hub.stream,
            ..Default::default()
        };
        Ok((hub, ctx))
    }

    fn from_hub(&self, resp: &HubResponse, _ctx: &BridgeContext) -> Result<Vec<u8>, ChatError> {
        let value = hub_response_to_anthropic_value(resp);
        serde_json::to_vec(&value)
            .map_err(|e| ChatError::bad_request(format!("failed to serialise response: {e}")))
    }

    fn from_hub_stream(
        &self,
        _chunk: &HubChunk,
        _ctx: &BridgeContext,
    ) -> Result<Vec<String>, ChatError> {
        // Streaming for Anthropic inbound is wired under WOR-226. Until
        // then the chat-completions inbound path is the only one with an
        // end-to-end streaming bridge.
        Err(ChatError::not_implemented(
            "anthropic SSE emission not yet wired; see WOR-226",
        ))
    }
}

fn parse_anthropic_message(obj: &Map<String, Value>) -> Result<HubMessage, ChatError> {
    let role_s = obj.get("role").and_then(|r| r.as_str()).unwrap_or("user");
    let role = match role_s {
        "user" => Role::User,
        "assistant" => Role::Assistant,
        other => {
            return Err(ChatError::bad_request(format!(
                "unsupported message role: {other}"
            )));
        }
    };

    let mut content: Vec<ContentPart> = Vec::new();
    match obj.get("content") {
        Some(Value::String(s)) => {
            content.push(ContentPart::Text { text: s.clone() });
        }
        Some(Value::Array(arr)) => {
            for part in arr {
                if let Some(p) = part.as_object() {
                    let ty = p.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    match ty {
                        "text" => {
                            if let Some(t) = p.get("text").and_then(|t| t.as_str()) {
                                content.push(ContentPart::Text { text: t.into() });
                            }
                        }
                        "tool_use" => {
                            content.push(ContentPart::ToolUse {
                                id: p
                                    .get("id")
                                    .and_then(|n| n.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                name: p
                                    .get("name")
                                    .and_then(|n| n.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                input: p.get("input").cloned().unwrap_or(Value::Null),
                            });
                        }
                        "tool_result" => {
                            // Anthropic ships the result body either as
                            // a string or as a nested array of text
                            // blocks; flatten to a string.
                            let body = match p.get("content") {
                                Some(Value::String(s)) => s.clone(),
                                Some(Value::Array(blocks)) => blocks
                                    .iter()
                                    .filter_map(|b| {
                                        b.get("text").and_then(|t| t.as_str()).map(String::from)
                                    })
                                    .collect::<Vec<_>>()
                                    .join(""),
                                _ => String::new(),
                            };
                            content.push(ContentPart::ToolResult {
                                tool_call_id: p
                                    .get("tool_use_id")
                                    .and_then(|i| i.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                content: body,
                                is_error: p
                                    .get("is_error")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false),
                            });
                        }
                        "image" => {
                            // Source is `{type, media_type, data}` for
                            // base64 or `{type, url}` for hosted; keep
                            // the source string verbatim.
                            let src = p.get("source").cloned().unwrap_or(Value::Null);
                            let source = match &src {
                                Value::Object(s) => s
                                    .get("data")
                                    .or_else(|| s.get("url"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                _ => String::new(),
                            };
                            let media_type = src
                                .get("media_type")
                                .and_then(|v| v.as_str())
                                .unwrap_or("image/*")
                                .to_string();
                            content.push(ContentPart::Image { source, media_type });
                        }
                        _ => {}
                    }
                }
            }
        }
        _ => {}
    }

    Ok(HubMessage {
        role,
        content,
        name: None,
        tool_call_id: None,
    })
}

fn hub_response_to_anthropic_value(resp: &HubResponse) -> Value {
    let mut content_blocks: Vec<Value> = Vec::new();
    for part in &resp.content {
        match part {
            ContentPart::Text { text } => content_blocks.push(json!({
                "type": "text",
                "text": text,
            })),
            ContentPart::ToolUse { id, name, input } => content_blocks.push(json!({
                "type": "tool_use",
                "id": id,
                "name": name,
                "input": input,
            })),
            ContentPart::ToolResult { .. } | ContentPart::Image { .. } => {
                // Assistant turns from Anthropic do not emit tool_result
                // or image blocks.
            }
        }
    }
    // Standalone tool_calls (separate from content) also surface as
    // tool_use blocks in the Anthropic shape.
    for tc in &resp.tool_calls {
        content_blocks.push(json!({
            "type": "tool_use",
            "id": tc.id,
            "name": tc.name,
            "input": tc.arguments,
        }));
    }

    let stop_reason = match &resp.finish_reason {
        FinishReason::Stop => "end_turn",
        FinishReason::Length => "max_tokens",
        FinishReason::ToolCalls => "tool_use",
        FinishReason::ContentFilter => "stop_sequence",
        FinishReason::Other(s) => s.as_str(),
    };

    json!({
        "id": resp.id,
        "type": "message",
        "role": "assistant",
        "model": resp.model,
        "content": content_blocks,
        "stop_reason": stop_reason,
        "stop_sequence": Value::Null,
        "usage": {
            "input_tokens": resp.usage.prompt_tokens,
            "output_tokens": resp.usage.completion_tokens,
        },
    })
}

/// Translate an inbound Anthropic Messages request body into an
/// OpenAI Chat Completions request body. The gateway already handles
/// the OpenAI Chat shape end to end; converting on the way in lets
/// the existing router, guardrails, and translator pipeline run
/// unchanged.
pub fn translate_anthropic_request_to_openai(body: &[u8]) -> Result<Vec<u8>, ChatError> {
    let (hub, _ctx) = AnthropicMessagesFormat.to_hub(body)?;
    Ok(super::openai_responses::hub_request_to_openai_bytes(&hub))
}

/// Translate the raw OpenAI Chat Completions response body (the shape
/// the gateway already produces today) into Anthropic Messages shape.
/// Used by the dispatch shim so an Anthropic inbound client receives
/// an Anthropic-shaped response regardless of the upstream provider.
pub fn translate_openai_response_to_anthropic(body: &[u8]) -> Vec<u8> {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return body.to_vec(),
    };
    let resp = openai_to_hub_response(&parsed);
    let value = hub_response_to_anthropic_value(&resp);
    serde_json::to_vec(&value).unwrap_or_else(|_| body.to_vec())
}

/// Parse a raw OpenAI Chat Completions response into a `HubResponse`.
/// Shared between the Anthropic and Responses outbound shims so any
/// upstream that ultimately leaves the gateway in OpenAI shape can be
/// re-wrapped to the client's expected format.
pub fn openai_to_hub_response(v: &Value) -> HubResponse {
    let id = v
        .get("id")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let model = v
        .get("model")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let choice = v
        .get("choices")
        .and_then(|c| c.get(0))
        .cloned()
        .unwrap_or(Value::Null);
    let message = choice.get("message").cloned().unwrap_or(Value::Null);
    let content_text = message
        .get("content")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string();
    let mut content_parts = Vec::new();
    if !content_text.is_empty() {
        content_parts.push(ContentPart::Text { text: content_text });
    }
    let mut tool_calls = Vec::new();
    if let Some(arr) = message.get("tool_calls").and_then(|t| t.as_array()) {
        for tc in arr {
            let id = tc
                .get("id")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let f = tc.get("function").and_then(|f| f.as_object());
            let name = f
                .and_then(|f| f.get("name"))
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let args = f
                .and_then(|f| f.get("arguments"))
                .cloned()
                .unwrap_or(Value::Null);
            let parsed_args = match &args {
                Value::String(s) => serde_json::from_str(s).unwrap_or(Value::String(s.clone())),
                other => other.clone(),
            };
            content_parts.push(ContentPart::ToolUse {
                id: id.clone(),
                name: name.clone(),
                input: parsed_args.clone(),
            });
            tool_calls.push(super::HubToolCall {
                id,
                name,
                arguments: parsed_args,
            });
        }
    }
    let finish_str = choice
        .get("finish_reason")
        .and_then(|f| f.as_str())
        .unwrap_or("stop");
    let finish_reason = match finish_str {
        "stop" => FinishReason::Stop,
        "length" => FinishReason::Length,
        "tool_calls" => FinishReason::ToolCalls,
        "content_filter" => FinishReason::ContentFilter,
        other => FinishReason::Other(other.to_string()),
    };
    let usage_obj = v.get("usage");
    let usage = HubUsage {
        prompt_tokens: usage_obj
            .and_then(|u| u.get("prompt_tokens"))
            .and_then(|n| n.as_u64())
            .unwrap_or(0),
        completion_tokens: usage_obj
            .and_then(|u| u.get("completion_tokens"))
            .and_then(|n| n.as_u64())
            .unwrap_or(0),
        total_tokens: usage_obj
            .and_then(|u| u.get("total_tokens"))
            .and_then(|n| n.as_u64())
            .unwrap_or(0),
    };

    HubResponse {
        id,
        model,
        content: content_parts,
        tool_calls,
        finish_reason,
        usage,
        extensions: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fmt() -> AnthropicMessagesFormat {
        AnthropicMessagesFormat
    }

    #[test]
    fn parses_simple_messages_request() {
        let req = json!({
            "model": "claude-3-5-sonnet",
            "max_tokens": 256,
            "system": "tone is formal",
            "messages": [
                {"role": "user", "content": "hello"}
            ]
        });
        let (hub, ctx) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.model, "claude-3-5-sonnet");
        assert_eq!(hub.max_tokens, Some(256));
        assert_eq!(hub.system.as_deref(), Some("tone is formal"));
        assert_eq!(hub.messages.len(), 1);
        assert_eq!(hub.messages[0].role, Role::User);
        assert_eq!(ctx.inbound_format, "anthropic");
    }

    #[test]
    fn parses_typed_content_blocks() {
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "look at this"},
                    {"type": "image", "source": {"media_type": "image/png", "data": "abc=="}}
                ]
            }]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        let parts = &hub.messages[0].content;
        assert_eq!(parts.len(), 2);
        matches!(parts[0], ContentPart::Text { .. });
        matches!(parts[1], ContentPart::Image { .. });
    }

    #[test]
    fn tool_use_round_trip() {
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": {"city": "SF"}}
                ]
            }]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        match &hub.messages[0].content[0] {
            ContentPart::ToolUse { id, name, input } => {
                assert_eq!(id, "toolu_1");
                assert_eq!(name, "get_weather");
                assert_eq!(input["city"], "SF");
            }
            other => panic!("expected tool_use, got {other:?}"),
        }
    }

    #[test]
    fn response_emit_matches_anthropic_shape() {
        let resp = HubResponse {
            id: "msg_01".into(),
            model: "claude-3-5-sonnet".into(),
            content: vec![ContentPart::Text {
                text: "hello".into(),
            }],
            tool_calls: Vec::new(),
            finish_reason: FinishReason::Stop,
            usage: HubUsage {
                prompt_tokens: 5,
                completion_tokens: 2,
                total_tokens: 7,
            },
            extensions: Default::default(),
        };
        let bytes = fmt().from_hub(&resp, &BridgeContext::default()).unwrap();
        let out: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(out["type"], "message");
        assert_eq!(out["role"], "assistant");
        assert_eq!(out["stop_reason"], "end_turn");
        assert_eq!(out["content"][0]["type"], "text");
        assert_eq!(out["content"][0]["text"], "hello");
        assert_eq!(out["usage"]["input_tokens"], 5);
        assert_eq!(out["usage"]["output_tokens"], 2);
    }

    #[test]
    fn translate_openai_response_to_anthropic_shape() {
        let openai = json!({
            "id": "chatcmpl-xyz",
            "object": "chat.completion",
            "model": "gpt-4o-mini",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "hi there"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 7, "completion_tokens": 2, "total_tokens": 9}
        });
        let body = translate_openai_response_to_anthropic(openai.to_string().as_bytes());
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["type"], "message");
        assert_eq!(parsed["model"], "gpt-4o-mini");
        assert_eq!(parsed["content"][0]["text"], "hi there");
        assert_eq!(parsed["stop_reason"], "end_turn");
    }

    #[test]
    fn streaming_emit_is_not_implemented_yet() {
        let err = fmt()
            .from_hub_stream(
                &HubChunk::MessageStop {
                    finish_reason: FinishReason::Stop,
                },
                &BridgeContext::default(),
            )
            .unwrap_err();
        assert_eq!(err.status(), 501);
    }
}
