//! OpenAI Responses API `ChatFormat` implementation.
//!
//! The Responses API (`POST /v1/responses`) is OpenAI's stateful
//! conversation surface. It overlaps heavily with Chat Completions but
//! introduces three wrinkles the hub has to handle:
//!
//!   * `input` may be a plain string (single user turn), an array of
//!     content parts (single user turn with multimodal content), or an
//!     array of `{role, content}` items (a full conversation). All
//!     three shapes flatten to a `HubRequest::messages` list.
//!   * `instructions` is the Responses-flavoured `system` prompt.
//!   * `previous_response_id` points at a prior conversation. The
//!     stateful conversation handling is parked as an open question in
//!     the ADR; for v1 we surface the id on the bridge context so any
//!     stateful expansion can plug in later, but the hub itself remains
//!     stateless.
//!
//! Outbound shape is the Responses response object: `output` array of
//! typed items wrapping the assistant message; `usage.input_tokens`
//! and `usage.output_tokens`. Streaming is deferred to WOR-226.

use serde_json::{json, Map, Value};

use super::{
    BridgeContext, ChatError, ChatFormat, ContentPart, FinishReason, HubChunk, HubMessage,
    HubRequest, HubResponse, HubToolDefinition, Role,
};

const INBOUND_PATHS: &[&str] = &["/v1/responses"];

/// `ChatFormat` for OpenAI Responses.
#[derive(Debug, Default, Clone, Copy)]
pub struct OpenAiResponsesFormat;

impl ChatFormat for OpenAiResponsesFormat {
    fn id(&self) -> &'static str {
        "responses"
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
            max_tokens: obj
                .get("max_output_tokens")
                .and_then(|v| v.as_u64())
                .map(|n| n as u32),
            stream: obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false),
            ..Default::default()
        };

        // `instructions` is the Responses-flavoured system prompt.
        if let Some(instr) = obj.get("instructions").and_then(|v| v.as_str()) {
            hub.system = Some(instr.to_string());
        }

        // Input can be a string, a content-parts array, or a full
        // messages array. Normalise each shape to `HubMessage`s.
        if let Some(input) = obj.get("input") {
            match input {
                Value::String(s) => {
                    hub.messages.push(HubMessage {
                        role: Role::User,
                        content: vec![ContentPart::Text { text: s.clone() }],
                        name: None,
                        tool_call_id: None,
                    });
                }
                Value::Array(arr) => {
                    // Distinguish the two array shapes by the presence
                    // of `role` on the first element.
                    let is_message_list = arr
                        .iter()
                        .filter_map(|v| v.as_object())
                        .any(|o| o.contains_key("role"));
                    if is_message_list {
                        for item in arr {
                            if let Some(o) = item.as_object() {
                                hub.messages.push(parse_responses_message(o)?);
                            }
                        }
                    } else {
                        let mut content = Vec::new();
                        for part in arr {
                            if let Some(p) = part.as_object() {
                                if let Some(cp) = parse_responses_content_part(p) {
                                    content.push(cp);
                                }
                            }
                        }
                        hub.messages.push(HubMessage {
                            role: Role::User,
                            content,
                            name: None,
                            tool_call_id: None,
                        });
                    }
                }
                _ => {}
            }
        }

        // Tools share the OpenAI Chat shape.
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

        let mut ctx = BridgeContext {
            inbound_format: self.id().into(),
            inbound_path: "/v1/responses".into(),
            stream: hub.stream,
            ..Default::default()
        };
        if let Some(prev) = obj.get("previous_response_id").and_then(|v| v.as_str()) {
            ctx.extras.insert(
                "responses.previous_response_id".into(),
                Value::String(prev.to_string()),
            );
            hub.lossiness.push(super::LossinessNote {
                field: "responses.previous_response_id".into(),
                direction: super::LossinessDirection::Unsupported,
                note: "stateful conversation join is not yet implemented (WOR-226 follow-up)"
                    .into(),
            });
        }
        Ok((hub, ctx))
    }

    fn from_hub(&self, resp: &HubResponse, _ctx: &BridgeContext) -> Result<Vec<u8>, ChatError> {
        let value = hub_response_to_responses_value(resp);
        serde_json::to_vec(&value)
            .map_err(|e| ChatError::bad_request(format!("failed to serialise response: {e}")))
    }

    fn from_hub_stream(
        &self,
        _chunk: &HubChunk,
        _ctx: &BridgeContext,
    ) -> Result<Vec<String>, ChatError> {
        // Streaming for the Responses inbound branch lands with
        // WOR-226. Chat Completions is the only inbound branch with an
        // end-to-end streaming bridge today.
        Err(ChatError::not_implemented(
            "responses SSE emission not yet wired; see WOR-226",
        ))
    }
}

fn parse_responses_message(obj: &Map<String, Value>) -> Result<HubMessage, ChatError> {
    let role_s = obj.get("role").and_then(|r| r.as_str()).unwrap_or("user");
    let role = match role_s {
        "user" => Role::User,
        "assistant" => Role::Assistant,
        "system" => Role::System,
        "tool" => Role::Tool,
        other => {
            return Err(ChatError::bad_request(format!(
                "unsupported message role: {other}"
            )));
        }
    };
    let mut content = Vec::new();
    if let Some(c) = obj.get("content") {
        match c {
            Value::String(s) => content.push(ContentPart::Text { text: s.clone() }),
            Value::Array(arr) => {
                for part in arr {
                    if let Some(p) = part.as_object() {
                        if let Some(cp) = parse_responses_content_part(p) {
                            content.push(cp);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(HubMessage {
        role,
        content,
        name: None,
        tool_call_id: None,
    })
}

fn parse_responses_content_part(p: &Map<String, Value>) -> Option<ContentPart> {
    let ty = p.get("type").and_then(|t| t.as_str()).unwrap_or("");
    match ty {
        // Responses uses both `text` and `input_text` in its
        // documented shapes.
        "text" | "input_text" => {
            let text = p.get("text").and_then(|t| t.as_str()).unwrap_or("");
            if text.is_empty() {
                None
            } else {
                Some(ContentPart::Text {
                    text: text.to_string(),
                })
            }
        }
        "image_url" | "input_image" => {
            let url = p
                .get("image_url")
                .and_then(|v| v.get("url"))
                .and_then(|u| u.as_str())
                .or_else(|| p.get("image_url").and_then(|u| u.as_str()))
                .unwrap_or("")
                .to_string();
            Some(ContentPart::Image {
                source: url,
                media_type: "image/*".into(),
            })
        }
        _ => None,
    }
}

fn hub_response_to_responses_value(resp: &HubResponse) -> Value {
    // Concatenate text parts into the message; surface tool calls
    // alongside as `function_call` output items.
    let mut text_chunks = String::new();
    let mut function_call_items: Vec<Value> = Vec::new();
    for part in &resp.content {
        match part {
            ContentPart::Text { text } => text_chunks.push_str(text),
            ContentPart::ToolUse { id, name, input } => {
                function_call_items.push(json!({
                    "type": "function_call",
                    "id": id,
                    "name": name,
                    "arguments": input.to_string(),
                }));
            }
            ContentPart::ToolResult { .. } | ContentPart::Image { .. } => {}
        }
    }
    for tc in &resp.tool_calls {
        function_call_items.push(json!({
            "type": "function_call",
            "id": tc.id,
            "name": tc.name,
            "arguments": tc.arguments.to_string(),
        }));
    }

    let message_item = json!({
        "type": "message",
        "id": format!("{}__msg", resp.id),
        "role": "assistant",
        "content": [
            {"type": "output_text", "text": text_chunks, "annotations": []}
        ],
    });

    let mut output: Vec<Value> = Vec::new();
    output.push(message_item);
    output.extend(function_call_items);

    let status = match &resp.finish_reason {
        FinishReason::Stop | FinishReason::ToolCalls => "completed",
        FinishReason::Length => "incomplete",
        FinishReason::ContentFilter => "incomplete",
        FinishReason::Other(_) => "completed",
    };

    json!({
        "id": resp.id,
        "object": "response",
        "model": resp.model,
        "status": status,
        "output": output,
        "usage": {
            "input_tokens": resp.usage.prompt_tokens,
            "output_tokens": resp.usage.completion_tokens,
            "total_tokens": resp.usage.total_tokens,
        },
    })
}

/// Translate the raw OpenAI Chat Completions response body into
/// OpenAI Responses shape. Used by the dispatch shim so a
/// Responses-shaped client sees a Responses-shaped reply.
pub fn translate_openai_response_to_responses(body: &[u8]) -> Vec<u8> {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return body.to_vec(),
    };
    let hub = super::anthropic_messages::openai_to_hub_response(&parsed);
    let value = hub_response_to_responses_value(&hub);
    serde_json::to_vec(&value).unwrap_or_else(|_| body.to_vec())
}

/// Translate an inbound Responses request body into an OpenAI Chat
/// Completions request body. The gateway already handles the OpenAI
/// Chat shape end to end; converting on the way in lets the existing
/// router, guardrails, and translator pipeline run unchanged.
pub fn translate_responses_request_to_openai(body: &[u8]) -> Result<Vec<u8>, ChatError> {
    let (hub, _ctx) = OpenAiResponsesFormat.to_hub(body)?;
    Ok(hub_request_to_openai_bytes(&hub))
}

/// Build an OpenAI Chat Completions request body from a `HubRequest`.
/// Pulled out so both the Responses and Anthropic inbound shims call
/// the same flattener.
pub fn hub_request_to_openai_bytes(hub: &HubRequest) -> Vec<u8> {
    let mut messages: Vec<Value> = Vec::new();
    if let Some(sys) = &hub.system {
        if !sys.is_empty() {
            messages.push(json!({"role": "system", "content": sys}));
        }
    }
    for m in &hub.messages {
        let role = match m.role {
            Role::System => "system",
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::Tool => "tool",
        };
        // Plain text turns serialise as a flat string; multimodal
        // turns serialise as an array of content parts. Tool calls on
        // assistant turns surface alongside the content as
        // `tool_calls`.
        let mut text_only = String::new();
        let mut parts: Vec<Value> = Vec::new();
        let mut tool_calls: Vec<Value> = Vec::new();
        let mut tool_result_for: Option<(String, String)> = None;
        for part in &m.content {
            match part {
                ContentPart::Text { text } => {
                    text_only.push_str(text);
                    parts.push(json!({"type": "text", "text": text}));
                }
                ContentPart::Image { source, media_type } => {
                    parts.push(json!({
                        "type": "image_url",
                        "image_url": {"url": source, "media_type": media_type},
                    }));
                }
                ContentPart::ToolUse { id, name, input } => {
                    tool_calls.push(json!({
                        "id": id,
                        "type": "function",
                        "function": {
                            "name": name,
                            "arguments": input.to_string(),
                        }
                    }));
                }
                ContentPart::ToolResult {
                    tool_call_id,
                    content,
                    ..
                } => {
                    tool_result_for = Some((tool_call_id.clone(), content.clone()));
                }
            }
        }
        let content_value =
            if parts.len() == 1 && tool_calls.is_empty() && tool_result_for.is_none() {
                Value::String(text_only)
            } else if parts.is_empty() && (tool_result_for.is_some() || !tool_calls.is_empty()) {
                // Pure tool-call or tool-result turn.
                if let Some((_, body)) = &tool_result_for {
                    Value::String(body.clone())
                } else {
                    Value::String(String::new())
                }
            } else if parts.is_empty() {
                Value::String(String::new())
            } else {
                Value::Array(parts)
            };

        let mut obj = Map::new();
        obj.insert("role".into(), Value::String(role.into()));
        obj.insert("content".into(), content_value);
        if !tool_calls.is_empty() {
            obj.insert("tool_calls".into(), Value::Array(tool_calls));
        }
        if let Some((id, _)) = &tool_result_for {
            obj.insert("tool_call_id".into(), Value::String(id.clone()));
        }
        if let Some(name) = &m.name {
            obj.insert("name".into(), Value::String(name.clone()));
        }
        messages.push(Value::Object(obj));
    }

    let mut out = Map::new();
    out.insert("model".into(), Value::String(hub.model.clone()));
    out.insert("messages".into(), Value::Array(messages));
    if let Some(mt) = hub.max_tokens {
        out.insert("max_tokens".into(), Value::Number(mt.into()));
    }
    if let Some(t) = hub.temperature {
        if let Some(n) = serde_json::Number::from_f64(t as f64) {
            out.insert("temperature".into(), Value::Number(n));
        }
    }
    if let Some(t) = hub.top_p {
        if let Some(n) = serde_json::Number::from_f64(t as f64) {
            out.insert("top_p".into(), Value::Number(n));
        }
    }
    if hub.stream {
        out.insert("stream".into(), Value::Bool(true));
    }
    if !hub.stop.is_empty() {
        out.insert(
            "stop".into(),
            Value::Array(hub.stop.iter().cloned().map(Value::String).collect()),
        );
    }
    // Tools flatten back to OpenAI's `tools` array.
    if !hub.tools.is_empty() {
        let tools = hub
            .tools
            .iter()
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    }
                })
            })
            .collect();
        out.insert("tools".into(), Value::Array(tools));
    }

    serde_json::to_vec(&Value::Object(out)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fmt() -> OpenAiResponsesFormat {
        OpenAiResponsesFormat
    }

    #[test]
    fn parses_string_input() {
        let req = json!({"model": "gpt-4o", "input": "hello"});
        let (hub, ctx) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.model, "gpt-4o");
        assert_eq!(hub.messages.len(), 1);
        assert_eq!(hub.messages[0].role, Role::User);
        assert_eq!(ctx.inbound_format, "responses");
    }

    #[test]
    fn parses_instructions_as_system() {
        let req = json!({
            "model": "gpt-4o",
            "instructions": "you are helpful",
            "input": "hi"
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.system.as_deref(), Some("you are helpful"));
    }

    #[test]
    fn parses_message_list_input() {
        let req = json!({
            "model": "gpt-4o",
            "input": [
                {"role": "user", "content": "hi"},
                {"role": "assistant", "content": "hello"}
            ]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.messages.len(), 2);
        assert_eq!(hub.messages[1].role, Role::Assistant);
    }

    #[test]
    fn previous_response_id_records_lossiness_note() {
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "previous_response_id": "resp_old"
        });
        let (hub, ctx) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert!(ctx.extras.contains_key("responses.previous_response_id"));
        assert!(!hub.lossiness.is_empty());
    }

    #[test]
    fn response_emit_matches_responses_shape() {
        let resp = HubResponse {
            id: "resp_1".into(),
            model: "gpt-4o-mini".into(),
            content: vec![ContentPart::Text {
                text: "hello".into(),
            }],
            tool_calls: Vec::new(),
            finish_reason: FinishReason::Stop,
            usage: super::super::HubUsage {
                prompt_tokens: 4,
                completion_tokens: 2,
                total_tokens: 6,
            },
            extensions: Default::default(),
        };
        let bytes = fmt().from_hub(&resp, &BridgeContext::default()).unwrap();
        let out: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(out["object"], "response");
        assert_eq!(out["status"], "completed");
        assert_eq!(out["output"][0]["type"], "message");
        assert_eq!(out["output"][0]["content"][0]["text"], "hello");
        assert_eq!(out["usage"]["input_tokens"], 4);
    }

    #[test]
    fn translate_request_to_openai_chat_completions() {
        let req = json!({
            "model": "gpt-4o",
            "instructions": "you are helpful",
            "input": "what time is it"
        });
        let bytes = translate_responses_request_to_openai(req.to_string().as_bytes()).unwrap();
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["model"], "gpt-4o");
        let msgs = parsed["messages"].as_array().unwrap();
        assert_eq!(msgs[0]["role"], "system");
        assert_eq!(msgs[0]["content"], "you are helpful");
        assert_eq!(msgs[1]["role"], "user");
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
