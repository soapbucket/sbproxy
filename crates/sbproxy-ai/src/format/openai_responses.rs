//! OpenAI Responses API `ChatFormat` implementation.
//!
//! The Responses API (`POST /v1/responses`) is OpenAI's stateful
//! conversation surface. It overlaps heavily with Chat Completions but
//! introduces wrinkles the hub has to handle:
//!
//!   * `input` may be a plain string (single user turn), an array of
//!     content parts (single user turn with multimodal content), or an
//!     array of `{role, content}` items (a full conversation). All
//!     three shapes flatten to a `HubRequest::messages` list.
//!   * `instructions` is the Responses-flavored `system` prompt.
//!   * `previous_response_id` and `conversation` reference server-side
//!     state this gateway does not hold, and `store: true` asks it to
//!     create such state. All three are refused with a 400 rather than
//!     silently served without the state they name (WOR-2511 ruling;
//!     a real conversation store is WOR-2514's evaluation). `store:
//!     false` is honored as-is: the stateless translation persists
//!     nothing, which is exactly what it asks for.
//!   * `prompt` references a server-side prompt template the gateway
//!     does not resolve yet; it is dropped with a `LossinessNote`
//!     because a bridge onto the gateway prompt store is planned
//!     (WOR-2514) rather than ruled out.
//!   * `tools`: `function` tools are forwarded, in both the
//!     Responses-native flat shape and the Chat-style nested shape.
//!     Any other tool block records a `LossinessNote` naming the
//!     dropped type (WOR-2512), except `mcp`, which is refused with a
//!     400 because it asks the provider to dial an MCP server the
//!     gateway never sees (WOR-2513 ruling).
//!
//! Outbound shape is the Responses response object: `output` array of
//! typed items wrapping the assistant message; `usage.input_tokens`
//! and `usage.output_tokens`. Streaming is implemented:
//! `from_hub_stream` re-emits hub chunks as typed `response.*` SSE
//! frames via `hub_chunk_to_responses_sse`.

use serde_json::{json, Map, Value};

use super::{
    BridgeContext, ChatError, ChatFormat, ContentPart, ContentPartDelta, FinishReason, HubChunk,
    HubMessage, HubRequest, HubResponse, HubToolDefinition, Role,
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

        // WOR-2511 ruling: the gateway keeps no response state, so a
        // stateful-join request would silently run without the turns it
        // references. Refuse instead; silent context loss is the worse
        // failure. A JSON null is an SDK serializing an unset optional,
        // not a join request.
        if obj
            .get("previous_response_id")
            .is_some_and(|v| !v.is_null())
        {
            return Err(ChatError::bad_request(
                "previous_response_id is not supported: this gateway does not \
                 store response state, so the turns it references would be \
                 silently missing; resend the full conversation history in \
                 'input' instead",
            ));
        }

        // Same ruling for a conversation reference (string id or
        // {"id": ...} object): it names upstream conversation state the
        // translation to Chat Completions destroys.
        if obj.get("conversation").is_some_and(|v| !v.is_null()) {
            return Err(ChatError::bad_request(
                "conversation is not supported: this gateway does not store \
                 conversation state, so the conversation it references would \
                 be silently missing; resend the full conversation history in \
                 'input' instead",
            ));
        }

        // store: true asks for a retrievable server-side response that
        // will never exist once the request is translated; the returned
        // id would be a dangling reference. store: false asks for
        // nothing to be persisted, which the stateless translation
        // delivers exactly, so it passes.
        match obj.get("store") {
            None | Some(Value::Null) | Some(Value::Bool(false)) => {}
            Some(_) => {
                return Err(ChatError::bad_request(
                    "store is not supported: this gateway keeps no response \
                     state, so a stored response could never be retrieved; \
                     omit store or send store: false and keep conversation \
                     history client-side",
                ));
            }
        }

        // A prompt template reference is dropped with a note rather than
        // refused: bridging it onto the gateway prompt store is planned
        // (WOR-2514), and the request still carries its own input.
        if obj.get("prompt").is_some_and(|v| !v.is_null()) {
            hub.lossiness.push(super::LossinessNote {
                field: "responses.prompt".into(),
                direction: super::LossinessDirection::Unsupported,
                note: "prompt template reference dropped: the gateway does \
                       not resolve server-side prompt objects, so the request \
                       runs without the referenced template"
                    .into(),
            });
        }

        // `instructions` is the Responses-flavored system prompt.
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

        // Tools: `function` tools are forwarded, whether they arrive in
        // the Responses-native flat shape ({"type": "function", "name":
        // ...}) or the Chat-style nested shape ({"function": {...}}).
        // Everything else is unsupported: `mcp` is refused (WOR-2513),
        // and every other type records a lossiness note naming what was
        // dropped (WOR-2512). Nothing falls through silently.
        if let Some(arr) = obj.get("tools").and_then(|v| v.as_array()) {
            for t in arr {
                let ty = t.get("type").and_then(|v| v.as_str()).unwrap_or("");
                if let Some(fobj) = t
                    .get("function")
                    .and_then(|f| f.as_object())
                    .or_else(|| (ty == "function").then_some(t.as_object()).flatten())
                {
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
                } else if ty == "mcp" {
                    // WOR-2513 ruling: an embedded mcp tool block asks
                    // the model provider to contact an MCP server
                    // directly, bypassing the gateway's governed MCP
                    // surface (RBAC, sessions, audit, egress inventory).
                    // Fail closed. The message deliberately does not
                    // echo server_url or server_label: the URL can carry
                    // credentials.
                    return Err(ChatError::bad_request(
                        "tools: type 'mcp' is not supported: it asks the model \
                         provider to contact an MCP server directly, bypassing \
                         this gateway's MCP governance; front the server with \
                         an origin whose action is 'type: mcp' and point the \
                         client at that origin instead",
                    ));
                } else {
                    // WOR-2512: every unsupported tool block leaves a
                    // trace naming what was dropped.
                    let label = tool_type_label(ty);
                    hub.lossiness.push(super::LossinessNote {
                        field: format!("responses.tools.{label}"),
                        direction: super::LossinessDirection::Unsupported,
                        note: format!(
                            "unsupported Responses tool type '{label}' dropped: \
                             only function tools are forwarded upstream"
                        ),
                    });
                }
            }
        }

        let ctx = BridgeContext {
            inbound_format: self.id().into(),
            inbound_path: "/v1/responses".into(),
            stream: hub.stream,
            ..Default::default()
        };
        Ok((hub, ctx))
    }

    fn from_hub(&self, resp: &HubResponse, _ctx: &BridgeContext) -> Result<Vec<u8>, ChatError> {
        let value = hub_response_to_responses_value(resp);
        serde_json::to_vec(&value)
            .map_err(|e| ChatError::bad_request(format!("failed to serialise response: {e}")))
    }

    fn from_hub_stream(
        &self,
        chunk: &HubChunk,
        _ctx: &mut BridgeContext,
    ) -> Result<Vec<String>, ChatError> {
        Ok(hub_chunk_to_responses_sse(chunk))
    }
}

/// Translate one hub chunk into a vector of OpenAI Responses SSE
/// frames. The Responses streaming wire format uses typed
/// `event: response.*` markers (`response.created`,
/// `response.output_text.delta`, `response.function_call_arguments.delta`,
/// `response.completed`). Each entry returned is a complete
/// `event: ...\ndata: ...\n\n` payload.
pub(crate) fn hub_chunk_to_responses_sse(chunk: &HubChunk) -> Vec<String> {
    match chunk {
        HubChunk::MessageStart { id, model } => {
            let body = json!({
                "type": "response.created",
                "response": {
                    "id": id,
                    "object": "response",
                    "model": model,
                    "status": "in_progress",
                    "output": []
                }
            });
            vec![format!("event: response.created\ndata: {body}\n\n")]
        }
        HubChunk::ContentDelta { index, delta } => match delta {
            ContentPartDelta::Text(t) => {
                let body = json!({
                    "type": "response.output_text.delta",
                    "output_index": index,
                    "content_index": 0,
                    "delta": t,
                });
                vec![format!(
                    "event: response.output_text.delta\ndata: {body}\n\n"
                )]
            }
        },
        HubChunk::ToolCallDelta { index, delta } => {
            let mut frames = Vec::new();
            // First delta carrying id+name announces the function
            // call output item; subsequent argument-chunk deltas use
            // `response.function_call_arguments.delta`.
            if delta.id.is_some() || delta.name.is_some() {
                let mut item = Map::new();
                item.insert("type".into(), Value::String("function_call".into()));
                if let Some(id) = &delta.id {
                    item.insert("id".into(), Value::String(id.clone()));
                }
                if let Some(name) = &delta.name {
                    item.insert("name".into(), Value::String(name.clone()));
                }
                item.insert("arguments".into(), Value::String(String::new()));
                let body = json!({
                    "type": "response.output_item.added",
                    "output_index": index,
                    "item": Value::Object(item),
                });
                frames.push(format!(
                    "event: response.output_item.added\ndata: {body}\n\n"
                ));
            }
            if let Some(arg) = &delta.arguments_chunk {
                let body = json!({
                    "type": "response.function_call_arguments.delta",
                    "output_index": index,
                    "delta": arg,
                });
                frames.push(format!(
                    "event: response.function_call_arguments.delta\ndata: {body}\n\n"
                ));
            }
            frames
        }
        HubChunk::Usage(_) => Vec::new(),
        HubChunk::MessageStop { finish_reason } => {
            let status = match finish_reason {
                FinishReason::Stop | FinishReason::ToolCalls => "completed",
                FinishReason::Length | FinishReason::ContentFilter => "incomplete",
                FinishReason::Other(_) => "completed",
            };
            let body = json!({
                "type": "response.completed",
                "response": {"status": status}
            });
            vec![format!("event: response.completed\ndata: {body}\n\n")]
        }
    }
}

/// Sanitize a client-supplied tool `type` string for use in a
/// `LossinessNote` field and the warn log: anything outside
/// `[A-Za-z0-9_.-]` becomes `_`, the empty string becomes `unknown`,
/// and the result is capped at 64 characters.
fn tool_type_label(ty: &str) -> String {
    if ty.is_empty() {
        return "unknown".to_string();
    }
    ty.chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

pub(crate) fn parse_responses_message(obj: &Map<String, Value>) -> Result<HubMessage, ChatError> {
    // WOR-599: missing or unknown role is an error, not a silent default to
    // user. Shared helper lives in the format module.
    let role = super::parse_role(obj)?;
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
    // Nothing downstream reads `hub.lossiness` on this path, so the
    // warn log is what makes each drop observable to an operator.
    for note in &hub.lossiness {
        tracing::warn!(
            field = %note.field,
            note = %note.note,
            "AI proxy: /v1/responses request field dropped in translation"
        );
    }
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
    fn previous_response_id_is_refused_with_400() {
        // WOR-2511: the gateway holds no response state, so honoring the
        // request would silently run without the turns it references.
        // Refusal is the ruling; silent context loss is the worse failure.
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "previous_response_id": "resp_old"
        });
        let err = fmt().to_hub(req.to_string().as_bytes()).unwrap_err();
        assert_eq!(err.status(), 400);
        assert!(
            err.message().contains("previous_response_id"),
            "refusal must name the field: {}",
            err.message()
        );
        assert!(
            err.message().contains("input"),
            "refusal must point at the working alternative: {}",
            err.message()
        );
    }

    #[test]
    fn previous_response_id_null_is_not_a_join_request() {
        // SDKs that serialize unset optionals as null are not asking for
        // a stateful join; only a real value is.
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "previous_response_id": null
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.messages.len(), 1);
        assert!(hub.lossiness.is_empty());
    }

    #[test]
    fn conversation_reference_is_refused_with_400() {
        // Same ruling as previous_response_id: the field references
        // upstream-stored conversation state the gateway does not hold.
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "conversation": "conv_123"
        });
        let err = fmt().to_hub(req.to_string().as_bytes()).unwrap_err();
        assert_eq!(err.status(), 400);
        assert!(
            err.message().contains("conversation"),
            "refusal must name the field: {}",
            err.message()
        );
    }

    #[test]
    fn conversation_object_reference_is_refused_with_400() {
        // The field also arrives as {"id": ...}; both shapes are a join
        // request.
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "conversation": {"id": "conv_123"}
        });
        let err = fmt().to_hub(req.to_string().as_bytes()).unwrap_err();
        assert_eq!(err.status(), 400);
        assert!(err.message().contains("conversation"), "{}", err.message());
    }

    #[test]
    fn prompt_template_records_lossiness_note() {
        // A prompt object references a server-side template this gateway
        // does not resolve yet; the drop is noted, not refused, because a
        // bridge onto the gateway prompt store is planned.
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "prompt": {"id": "pmpt_1", "version": "2", "variables": {"city": "SF"}}
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.lossiness.len(), 1);
        assert_eq!(hub.lossiness[0].field, "responses.prompt");
        assert_eq!(
            hub.lossiness[0].direction,
            super::super::LossinessDirection::Unsupported
        );
    }

    #[test]
    fn store_true_is_refused_with_400() {
        // store: true asks for a retrievable server-side response that
        // will never exist once the request is translated to Chat
        // Completions; the returned id would be a dangling reference.
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "store": true
        });
        let err = fmt().to_hub(req.to_string().as_bytes()).unwrap_err();
        assert_eq!(err.status(), 400);
        assert!(err.message().contains("store"), "{}", err.message());
    }

    #[test]
    fn store_false_is_honored_without_note() {
        // store: false asks for nothing to be persisted, which the
        // stateless translation delivers exactly; no loss to report.
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "store": false
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert!(hub.lossiness.is_empty());
        assert_eq!(hub.messages.len(), 1);
    }

    #[test]
    fn file_search_tool_block_records_lossiness_note() {
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "tools": [{"type": "file_search", "vector_store_ids": ["vs_1"]}]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert!(hub.tools.is_empty());
        assert_eq!(hub.lossiness.len(), 1);
        let note = &hub.lossiness[0];
        assert_eq!(note.field, "responses.tools.file_search");
        assert_eq!(
            note.direction,
            super::super::LossinessDirection::Unsupported
        );
        assert!(note.note.contains("file_search"), "{}", note.note);
    }

    #[test]
    fn web_search_preview_tool_block_records_lossiness_note() {
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "tools": [{"type": "web_search_preview"}]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert!(hub.tools.is_empty());
        assert_eq!(hub.lossiness.len(), 1);
        assert_eq!(hub.lossiness[0].field, "responses.tools.web_search_preview");
    }

    #[test]
    fn code_interpreter_tool_block_records_lossiness_note() {
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "tools": [{"type": "code_interpreter", "container": {"type": "auto"}}]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert!(hub.tools.is_empty());
        assert_eq!(hub.lossiness.len(), 1);
        assert_eq!(hub.lossiness[0].field, "responses.tools.code_interpreter");
    }

    #[test]
    fn image_generation_tool_block_records_lossiness_note() {
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "tools": [{"type": "image_generation"}]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert!(hub.tools.is_empty());
        assert_eq!(hub.lossiness.len(), 1);
        assert_eq!(hub.lossiness[0].field, "responses.tools.image_generation");
    }

    #[test]
    fn unknown_tool_block_records_lossiness_note() {
        // The catchall: a type this parser has never heard of still gets
        // named rather than silently vanishing.
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "tools": [{"type": "computer_use_preview", "display_width": 1024}]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert!(hub.tools.is_empty());
        assert_eq!(hub.lossiness.len(), 1);
        assert_eq!(
            hub.lossiness[0].field,
            "responses.tools.computer_use_preview"
        );
    }

    #[test]
    fn typeless_tool_block_records_lossiness_note() {
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "tools": [{"vector_store_ids": ["vs_1"]}]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert!(hub.tools.is_empty());
        assert_eq!(hub.lossiness.len(), 1);
        assert_eq!(hub.lossiness[0].field, "responses.tools.unknown");
    }

    #[test]
    fn tool_type_label_is_sanitized_for_logs() {
        // The type string is client-controlled and lands in the note
        // field and the warn log; hostile characters must not pass
        // through verbatim.
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "tools": [{"type": "we ird\ntype!"}]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.lossiness.len(), 1);
        assert_eq!(hub.lossiness[0].field, "responses.tools.we_ird_type_");
    }

    #[test]
    fn mcp_tool_block_is_refused_with_400() {
        // WOR-2513: an embedded mcp tool block asks the provider to dial
        // an MCP server the gateway never sees. Fail closed and point at
        // the governed mcp action instead.
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "tools": [{
                "type": "mcp",
                "server_label": "internal",
                "server_url": "https://mcp.internal.example/sse?key=s3cret"
            }]
        });
        let err = fmt().to_hub(req.to_string().as_bytes()).unwrap_err();
        assert_eq!(err.status(), 400);
        assert!(err.message().contains("mcp"), "{}", err.message());
        // The refusal must not echo the caller-supplied server URL: it
        // can carry credentials in query parameters.
        assert!(
            !err.message().contains("mcp.internal.example"),
            "refusal echoed the server URL: {}",
            err.message()
        );
    }

    #[test]
    fn responses_native_flat_function_tool_parses() {
        // The Responses wire shape carries function tools flat
        // ({"type": "function", "name": ...}), not nested under a
        // "function" key the way Chat Completions does.
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "tools": [{
                "type": "function",
                "name": "get_weather",
                "description": "Weather lookup.",
                "parameters": {"type": "object"}
            }]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.tools.len(), 1);
        assert_eq!(hub.tools[0].name, "get_weather");
        assert_eq!(hub.tools[0].description, "Weather lookup.");
        assert!(hub.lossiness.is_empty());
    }

    #[test]
    fn chat_style_nested_function_tool_parses_without_note() {
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "tools": [{
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "Weather lookup.",
                    "parameters": {"type": "object"}
                }
            }]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.tools.len(), 1);
        assert_eq!(hub.tools[0].name, "get_weather");
        assert!(hub.lossiness.is_empty());
    }

    #[test]
    fn mixed_tools_forward_functions_and_note_the_rest() {
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "tools": [
                {"type": "function", "function": {"name": "a", "description": "", "parameters": {}}},
                {"type": "file_search"},
                {"type": "web_search_preview"}
            ]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.tools.len(), 1);
        assert_eq!(hub.tools[0].name, "a");
        let fields: Vec<&str> = hub.lossiness.iter().map(|n| n.field.as_str()).collect();
        assert_eq!(
            fields,
            vec![
                "responses.tools.file_search",
                "responses.tools.web_search_preview"
            ]
        );
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
    fn translate_seam_propagates_refusals() {
        // The dispatch shim calls translate_responses_request_to_openai,
        // not to_hub directly; the refusal has to survive that seam.
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "tools": [{"type": "mcp", "server_label": "x", "server_url": "https://mcp.example/sse"}]
        });
        let err = translate_responses_request_to_openai(req.to_string().as_bytes()).unwrap_err();
        assert_eq!(err.status(), 400);
        assert!(err.message().contains("mcp"), "{}", err.message());
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
    fn streaming_message_start_emits_response_created() {
        let frames = fmt()
            .from_hub_stream(
                &HubChunk::MessageStart {
                    id: "resp_1".into(),
                    model: "gpt-4o".into(),
                },
                &mut BridgeContext::default(),
            )
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert!(frames[0].starts_with("event: response.created\n"));
        assert!(frames[0].contains("\"resp_1\""));
    }

    #[test]
    fn streaming_text_delta_emits_output_text_delta() {
        let frames = fmt()
            .from_hub_stream(
                &HubChunk::ContentDelta {
                    index: 0,
                    delta: super::super::ContentPartDelta::Text("hello".into()),
                },
                &mut BridgeContext::default(),
            )
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert!(frames[0].contains("response.output_text.delta"));
        assert!(frames[0].contains("\"delta\":\"hello\""));
    }

    #[test]
    fn streaming_stop_emits_response_completed() {
        let frames = fmt()
            .from_hub_stream(
                &HubChunk::MessageStop {
                    finish_reason: FinishReason::Stop,
                },
                &mut BridgeContext::default(),
            )
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert!(frames[0].contains("response.completed"));
        assert!(frames[0].contains("completed"));
    }

    #[test]
    fn streaming_tool_call_emits_output_item_then_arguments_delta() {
        let f1 = fmt()
            .from_hub_stream(
                &HubChunk::ToolCallDelta {
                    index: 0,
                    delta: super::super::HubToolCallDelta {
                        id: Some("call_1".into()),
                        name: Some("get_weather".into()),
                        arguments_chunk: None,
                    },
                },
                &mut BridgeContext::default(),
            )
            .unwrap();
        assert_eq!(f1.len(), 1);
        assert!(f1[0].contains("response.output_item.added"));
        assert!(f1[0].contains("function_call"));
        let f2 = fmt()
            .from_hub_stream(
                &HubChunk::ToolCallDelta {
                    index: 0,
                    delta: super::super::HubToolCallDelta {
                        id: None,
                        name: None,
                        arguments_chunk: Some("{\"city".into()),
                    },
                },
                &mut BridgeContext::default(),
            )
            .unwrap();
        assert_eq!(f2.len(), 1);
        assert!(f2[0].contains("response.function_call_arguments.delta"));
    }
}
