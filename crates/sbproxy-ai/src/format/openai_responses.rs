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
//!     WOR-2514's evaluation kept conversations refused until the
//!     WOR-2511 stateful join exists). `store: false` is honored
//!     as-is: the stateless translation persists nothing, which is
//!     exactly what it asks for.
//!   * An object-valued `prompt` is a stored-prompt reference the
//!     gateway serves from its own prompt store (WOR-2514): the
//!     dispatcher resolves it BEFORE this translation, rendering the
//!     template into `instructions` and stripping the field. An
//!     object that reaches this translator unresolved is therefore
//!     refused with a 400 rather than dropped. A string-valued
//!     `prompt` is not the object form; it keeps the pre-bridge
//!     note-and-drop.
//!   * `tools`: `function` tools are forwarded, in both the
//!     Responses-native flat shape and the Chat-style nested shape.
//!     Any other tool block records a `LossinessNote` naming the
//!     dropped type (WOR-2512), except `mcp`, which is refused with a
//!     400 because it asks the provider to dial an MCP server the
//!     gateway never sees (WOR-2513 ruling).
//!
//!   * `tool_choice` is honored, in the OpenAI string spellings and in
//!     both the Responses-native flat forced-tool shape and the
//!     Chat-style nested one.
//!
//! Everything else this parser reads past records a `LossinessNote`:
//! every top-level key outside `RESPONSES_REPRESENTED_TOP_LEVEL_KEYS`
//! (`text` structured output, `reasoning`, `truncation`, `metadata`,
//! `include`, and whatever OpenAI ships next), every input content
//! part that maps onto no hub variant, and every non-object entry in a
//! message list. The translate seam counts each class on
//! `sbproxy_ai_translation_dropped_total` and emits one bounded warn
//! per request (WOR-2554 review; this surface has the live translate
//! seam and was the one the first sweep skipped).
//!
//! Outbound shape is the Responses response object: `output` array of
//! typed items wrapping the assistant message; `usage.input_tokens`
//! and `usage.output_tokens`. Streaming is implemented:
//! `from_hub_stream` re-emits hub chunks as typed `response.*` SSE
//! frames via `hub_chunk_to_responses_sse`.

use serde_json::{json, Map, Value};

use super::{
    json_type_name, note_drop, BridgeContext, ChatError, ChatFormat, ContentPart, ContentPartDelta,
    FinishReason, HubChunk, HubMessage, HubRequest, HubResponse, HubToolDefinition, Role,
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

        // WOR-2514: an object-valued `prompt` is a stored-prompt
        // reference the dispatcher resolves against the gateway prompt
        // store before translation (rendered into `instructions`, field
        // stripped, unknown references 404ed there). One that reaches
        // this translator was never resolved, so the request would run
        // without the template it names; refuse rather than drop. A
        // string (or other non-object) `prompt` is not the bridge's
        // object form and keeps the pre-bridge note-and-drop behavior
        // (counted at the translate seam per WOR-2535).
        match obj.get("prompt") {
            None | Some(Value::Null) => {}
            Some(Value::Object(_)) => {
                return Err(ChatError::bad_request(
                    "prompt object was not resolved against the gateway \
                     prompt store: this request path does not bridge \
                     stored-prompt references, so the request would run \
                     without the referenced template; inline the prompt \
                     text in 'input' or 'instructions' instead",
                ));
            }
            Some(_) => {
                hub.lossiness.push(super::LossinessNote {
                    field: "responses.prompt".into(),
                    metric_label: "responses.prompt".into(),
                    direction: super::LossinessDirection::Unsupported,
                    note: "prompt template reference dropped: the gateway does \
                           not resolve server-side prompt objects, so the request \
                           runs without the referenced template"
                        .into(),
                });
            }
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
                            match item.as_object() {
                                Some(o) => {
                                    let message = parse_responses_message(o, &mut hub.lossiness)?;
                                    hub.messages.push(message);
                                }
                                None => note_drop(
                                    &mut hub.lossiness,
                                    "responses.input",
                                    "responses.input".into(),
                                    format!(
                                        "non-object input entry of JSON type '{}' dropped",
                                        json_type_name(item)
                                    ),
                                ),
                            }
                        }
                    } else {
                        let mut content = Vec::new();
                        for part in arr {
                            push_responses_content_part(part, &mut content, &mut hub.lossiness);
                        }
                        hub.messages.push(HubMessage {
                            role: Role::User,
                            content,
                            name: None,
                            tool_call_id: None,
                        });
                    }
                }
                Value::Null => {}
                other => note_drop(
                    &mut hub.lossiness,
                    "responses.input",
                    "responses.input".into(),
                    format!(
                        "input value of JSON type '{}' dropped: expected a string, \
                         an array of content parts, or an array of message objects",
                        json_type_name(other)
                    ),
                ),
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
                    let label = super::sanitize_type_label(ty);
                    note_drop(
                        &mut hub.lossiness,
                        "responses.tools",
                        format!("responses.tools.{label}"),
                        format!(
                            "unsupported Responses tool type '{label}' dropped: \
                             only function tools are forwarded upstream"
                        ),
                    );
                }
            }
        }

        // Tool choice: the Responses spelling is the OpenAI one
        // (`"none"` / `"auto"` / `"required"`) plus a forced tool in
        // either the Responses-native flat shape
        // (`{"type": "function", "name": ...}`) or the Chat-style
        // nested one. All four have canonical representations, so they
        // are honored rather than dropped: the same forced-tool bug
        // WOR-2535 fixed on `/v1/messages` shipped here too, and the
        // hub already carries `HubToolChoice` (WOR-2554 review).
        match obj.get("tool_choice") {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) => match s.as_str() {
                "auto" => hub.tool_choice = super::HubToolChoice::Auto,
                "none" => hub.tool_choice = super::HubToolChoice::None,
                "required" => hub.tool_choice = super::HubToolChoice::Any,
                other => {
                    let label = super::sanitize_type_label(other);
                    note_drop(
                        &mut hub.lossiness,
                        "responses.tool_choice",
                        "responses.tool_choice".into(),
                        format!(
                            "tool_choice '{label}' dropped: it has no canonical \
                             representation, so the model chooses tools as if \
                             tool_choice were 'auto'"
                        ),
                    );
                }
            },
            Some(Value::Object(tc)) => {
                let name = tc
                    .get("name")
                    .and_then(Value::as_str)
                    .or_else(|| tc.get("function").and_then(|f| f.get("name"))?.as_str());
                match (tc.get("type").and_then(Value::as_str), name) {
                    (Some("function"), Some(name)) => {
                        hub.tool_choice = super::HubToolChoice::Required(name.to_string());
                    }
                    (ty, _) => {
                        let label = super::sanitize_type_label(ty.unwrap_or(""));
                        note_drop(
                            &mut hub.lossiness,
                            "responses.tool_choice",
                            "responses.tool_choice".into(),
                            format!(
                                "tool_choice of type '{label}' dropped: it has no \
                                 canonical representation, so the model chooses \
                                 tools as if tool_choice were 'auto'"
                            ),
                        );
                    }
                }
            }
            Some(other) => note_drop(
                &mut hub.lossiness,
                "responses.tool_choice",
                "responses.tool_choice".into(),
                format!(
                    "tool_choice value of JSON type '{}' dropped: expected a \
                     string or an object; the model chooses tools as if \
                     tool_choice were 'auto'",
                    json_type_name(other)
                ),
            ),
        }

        // Every top-level key outside the represented set is a control
        // the canonical chat request cannot carry. The
        // behavior-visible ones get a note naming what changes;
        // everything else, today's unknowns and tomorrow's new
        // Responses fields alike, gets the generic treatment under a
        // sanitized key, so this detector is as wide as the parser
        // above (WOR-2554 review: `text.format` structured output,
        // `reasoning`, `truncation`, `metadata`, and the rest used to
        // fall off the end of this function with no note, no counter,
        // and no warn).
        for (key, value) in obj {
            if value.is_null() || RESPONSES_REPRESENTED_TOP_LEVEL_KEYS.contains(&key.as_str()) {
                continue;
            }
            match key.as_str() {
                "text" => note_drop(
                    &mut hub.lossiness,
                    "responses.text",
                    "responses.text".into(),
                    "text dropped: the response-format request it carries is not \
                     forwarded, so a json_schema client receives free-form prose \
                     instead of the shape it asked for"
                        .into(),
                ),
                "reasoning" => note_drop(
                    &mut hub.lossiness,
                    "responses.reasoning",
                    "responses.reasoning".into(),
                    "reasoning configuration dropped: the provider serves the \
                     request at its default reasoning effort and returns no \
                     reasoning summary"
                        .into(),
                ),
                "parallel_tool_calls" => note_drop(
                    &mut hub.lossiness,
                    "responses.parallel_tool_calls",
                    "responses.parallel_tool_calls".into(),
                    "parallel_tool_calls dropped: the provider may still emit \
                     parallel tool calls"
                        .into(),
                ),
                "truncation" => note_drop(
                    &mut hub.lossiness,
                    "responses.truncation",
                    "responses.truncation".into(),
                    "truncation dropped: an over-length conversation is refused \
                     by the provider rather than truncated"
                        .into(),
                ),
                "metadata" => note_drop(
                    &mut hub.lossiness,
                    "responses.metadata",
                    "responses.metadata".into(),
                    "metadata dropped: the canonical request does not carry it, \
                     so the provider never sees the request metadata"
                        .into(),
                ),
                "include" => note_drop(
                    &mut hub.lossiness,
                    "responses.include",
                    "responses.include".into(),
                    "include dropped: the additional output the client asked to \
                     be returned is not requested from the provider"
                        .into(),
                ),
                "top_logprobs" => note_drop(
                    &mut hub.lossiness,
                    "responses.top_logprobs",
                    "responses.top_logprobs".into(),
                    "top_logprobs dropped: the response arrives without the \
                     token log probabilities the client asked for"
                        .into(),
                ),
                "service_tier" => note_drop(
                    &mut hub.lossiness,
                    "responses.service_tier",
                    "responses.service_tier".into(),
                    "service_tier dropped: the provider serves the request on \
                     its default tier"
                        .into(),
                ),
                "background" => note_drop(
                    &mut hub.lossiness,
                    "responses.background",
                    "responses.background".into(),
                    "background dropped: the request runs inline, so there is no \
                     background job to poll"
                        .into(),
                ),
                "max_tool_calls" => note_drop(
                    &mut hub.lossiness,
                    "responses.max_tool_calls",
                    "responses.max_tool_calls".into(),
                    "max_tool_calls dropped: the provider is not capped and may \
                     emit more tool calls than the client allowed"
                        .into(),
                ),
                other => {
                    let label = super::sanitize_type_label(other);
                    note_drop(
                        &mut hub.lossiness,
                        "responses.request",
                        format!("responses.{label}"),
                        format!(
                            "top-level field '{label}' dropped: it has no \
                             representation in the canonical request the \
                             gateway governs"
                        ),
                    );
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

/// Top-level OpenAI Responses request keys the hub represents (parsed
/// in `to_hub` above) or refuses outright with a 400. Everything else
/// hits the catch-all note loop. Keep this list in lockstep with the
/// parser: a key parsed but not listed would double-note, a key listed
/// but not parsed would drop silently again (WOR-2554 review).
const RESPONSES_REPRESENTED_TOP_LEVEL_KEYS: &[&str] = &[
    "model",
    "input",
    "instructions",
    "tools",
    "tool_choice",
    "temperature",
    "top_p",
    "max_output_tokens",
    "stream",
    // Refused above with a 400, which is louder than a note. Listing
    // them keeps the loop from reporting a field on a request that
    // never reaches it.
    "previous_response_id",
    "conversation",
    "store",
    "prompt",
];

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

/// Parse one Responses message object into a `HubMessage`, recording a
/// `LossinessNote` into `lossiness` for every content part or content
/// value that yields no hub representation (WOR-2554 review; the
/// Anthropic surface got this detector first, on `/v1/messages`).
pub(crate) fn parse_responses_message(
    obj: &Map<String, Value>,
    lossiness: &mut Vec<super::LossinessNote>,
) -> Result<HubMessage, ChatError> {
    // WOR-599: missing or unknown role is an error, not a silent default to
    // user. Shared helper lives in the format module.
    let role = super::parse_role(obj)?;
    let mut content = Vec::new();
    if let Some(c) = obj.get("content") {
        match c {
            Value::String(s) => content.push(ContentPart::Text { text: s.clone() }),
            Value::Array(arr) => {
                for part in arr {
                    push_responses_content_part(part, &mut content, lossiness);
                }
            }
            Value::Null => {}
            other => note_drop(
                lossiness,
                "responses.input.content",
                "responses.input.content".into(),
                format!(
                    "message content of JSON type '{}' dropped: expected a \
                     string or an array of content parts",
                    json_type_name(other)
                ),
            ),
        }
    }
    Ok(HubMessage {
        role,
        content,
        name: None,
        tool_call_id: None,
    })
}

/// Map one wire content part into `content`, recording a note when it
/// yields nothing. An `input_text` whose `text` is a present empty
/// string is represented-as-nothing rather than dropped, so an SDK
/// that pads a turn with an empty part does not tick the drop counter.
fn push_responses_content_part(
    part: &Value,
    content: &mut Vec<ContentPart>,
    lossiness: &mut Vec<super::LossinessNote>,
) {
    let Some(p) = part.as_object() else {
        note_drop(
            lossiness,
            "responses.input.content",
            "responses.input.content".into(),
            format!(
                "non-object content entry of JSON type '{}' dropped",
                json_type_name(part)
            ),
        );
        return;
    };
    if let Some(cp) = parse_responses_content_part(p) {
        content.push(cp);
        return;
    }
    let ty = p.get("type").and_then(|t| t.as_str()).unwrap_or("");
    if matches!(ty, "text" | "input_text") && p.get("text").and_then(Value::as_str) == Some("") {
        return;
    }
    let label = super::sanitize_type_label(ty);
    note_drop(
        lossiness,
        "responses.input.content",
        format!("responses.input.content.{label}"),
        format!(
            "content part of type '{label}' dropped: it has no representation \
             in the canonical request the gateway governs"
        ),
    );
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
    // The hub mirrors every model tool call into both `content` and
    // `tool_calls` (see `HubResponse::tool_calls`), so emitting both
    // pathways unconditionally duplicated every function_call item
    // (WOR-2553, the same double-emit WOR-2535 fixed on the Anthropic
    // rewrap). Only calls `content` does not already carry get a
    // standalone item.
    for tc in &resp.tool_calls {
        let mirrored_in_content = resp.content.iter().any(|part| {
            matches!(
                part,
                ContentPart::ToolUse { id, name, input }
                    if *id == tc.id && *name == tc.name && *input == tc.arguments
            )
        });
        if mirrored_in_content {
            continue;
        }
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
pub fn translate_responses_request_to_openai(
    body: &[u8],
    origin: &str,
    tenant: Option<&str>,
) -> Result<Vec<u8>, ChatError> {
    let (hub, _ctx) = OpenAiResponsesFormat.to_hub(body)?;
    // Nothing downstream reads `hub.lossiness` on this path, so this
    // seam is what makes each drop observable: the folded drop counter
    // plus one aggregated, bounded warn for the request (WOR-2535
    // review; the per-note warn loop this replaces was a
    // client-reachable log flood, here exactly as on /v1/messages).
    super::report_translation_lossiness(
        crate::handler::AiSurface::Responses.label(),
        origin,
        tenant,
        &hub.lossiness,
    );
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
        // `tool_calls`. Tool results become their own `role: "tool"`
        // messages, one per result.
        let mut text_only = String::new();
        let mut parts: Vec<Value> = Vec::new();
        let mut tool_calls: Vec<Value> = Vec::new();
        let mut tool_results: Vec<(String, String)> = Vec::new();
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
                // One `Option` here kept only the LAST result and
                // silently discarded every earlier one, so an
                // Anthropic parallel-tool-use turn (two `tool_result`
                // blocks in one user message, a shape the native
                // bypass never accepts) reached the provider with half
                // its results and looked like a model error
                // (WOR-2554 review).
                ContentPart::ToolResult {
                    tool_call_id,
                    content,
                    ..
                } => tool_results.push((tool_call_id.clone(), content.clone())),
            }
        }
        // The single-part flattening keys on the part KIND, not the
        // count: `text_only` accumulates from text parts alone, so a
        // turn whose only part is an image (a plain "describe this
        // image" request, which `governable_content_block` never
        // bypasses) used to flatten to `"content": ""` and the model
        // answered about nothing (WOR-2554 review).
        let content_value = if parts.len() == 1
            && tool_calls.is_empty()
            && tool_results.is_empty()
            && matches!(m.content.first(), Some(ContentPart::Text { .. }))
        {
            Value::String(text_only)
        } else if parts.is_empty() {
            Value::String(String::new())
        } else {
            Value::Array(parts)
        };

        // A turn carrying nothing but tool results has no message of
        // its own; the `role: "tool"` messages below are the whole
        // turn, which is the shape OpenAI Chat Completions wants.
        let content_is_empty = matches!(&content_value, Value::String(s) if s.is_empty());
        if !(content_is_empty && tool_calls.is_empty() && !tool_results.is_empty()) {
            let mut obj = Map::new();
            obj.insert("role".into(), Value::String(role.into()));
            obj.insert("content".into(), content_value);
            if !tool_calls.is_empty() {
                obj.insert("tool_calls".into(), Value::Array(tool_calls));
            }
            if let Some(name) = &m.name {
                obj.insert("name".into(), Value::String(name.clone()));
            }
            messages.push(Value::Object(obj));
        }
        for (id, body) in tool_results {
            let mut obj = Map::new();
            obj.insert("role".into(), Value::String("tool".into()));
            obj.insert("content".into(), Value::String(body));
            obj.insert("tool_call_id".into(), Value::String(id));
            messages.push(Value::Object(obj));
        }
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
    // top_k is honored, not dropped (WOR-2535 review): OpenAI itself
    // lacks the field, but this canonical body is what the provider
    // translators read. Anthropic accepts `top_k` natively, Gemini
    // re-homes it to `generationConfig.topK`, and much of the
    // OpenAI-compatible fleet honors it; Bedrock's translator
    // documents dropping it. A strict upstream that rejects the field
    // turns the old silent sampling change into a visible 400, which
    // is the failure direction this gateway prefers.
    if let Some(k) = hub.top_k {
        out.insert("top_k".into(), Value::Number(k.into()));
    }
    // Tool choice is honored, not dropped (WOR-2535 review: a
    // forced-tool hint silently became auto). Auto is the OpenAI
    // default, so it emits nothing.
    match &hub.tool_choice {
        super::HubToolChoice::Auto => {}
        super::HubToolChoice::None => {
            out.insert("tool_choice".into(), Value::String("none".into()));
        }
        super::HubToolChoice::Any => {
            out.insert("tool_choice".into(), Value::String("required".into()));
        }
        super::HubToolChoice::Required(name) => {
            out.insert(
                "tool_choice".into(),
                json!({"type": "function", "function": {"name": name}}),
            );
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
    fn unresolved_prompt_object_is_refused_with_400() {
        // WOR-2514: an object-valued `prompt` is a stored-prompt
        // reference the gateway resolves against its own prompt store
        // BEFORE translation (rendered into `instructions`, field
        // stripped). One that reaches the translator was never
        // resolved, and dropping it would run the request without the
        // template it names. Refuse instead.
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "prompt": {"id": "pmpt_1", "version": "2", "variables": {"city": "SF"}}
        });
        let err = fmt().to_hub(req.to_string().as_bytes()).unwrap_err();
        assert_eq!(err.status(), 400);
        assert!(err.message().contains("prompt"), "{}", err.message());
    }

    #[test]
    fn string_prompt_keeps_the_lossiness_note() {
        // A string `prompt` is not the Responses object form the
        // WOR-2514 bridge serves; it keeps the pre-bridge
        // note-and-drop behavior unchanged.
        let req = json!({
            "model": "gpt-4o",
            "input": "hi",
            "prompt": "greeting@2"
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
    fn unsupported_tool_type_label_is_sanitized_for_logs() {
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
        let err = translate_responses_request_to_openai(
            req.to_string().as_bytes(),
            "test.sbproxy.dev",
            None,
        )
        .unwrap_err();
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
        let bytes = translate_responses_request_to_openai(
            req.to_string().as_bytes(),
            "test.sbproxy.dev",
            None,
        )
        .unwrap();
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

    #[test]
    fn responses_rewrap_emits_each_mirrored_tool_call_once() {
        // Red-first (WOR-2553): openai_to_hub_response mirrors every
        // model tool call into both `content` and `tool_calls`, and the
        // Responses rewrap emitted both pathways, so every function_call
        // item appeared twice. Same double-emit WOR-2535 fixed on the
        // Anthropic rewrap.
        let openai = json!({
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "model": "gpt-4o-mini",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "get_weather", "arguments": "{\"city\":\"SF\"}"}
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        });
        let body = translate_openai_response_to_responses(openai.to_string().as_bytes());
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        let calls: Vec<&Value> = parsed["output"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|item| item["type"] == "function_call")
            .collect();
        assert_eq!(calls.len(), 1, "{parsed}");
        assert_eq!(calls[0]["id"], "call_1");
    }

    #[test]
    fn responses_rewrap_keeps_standalone_tool_calls() {
        // Deduplication must not eat a call that exists only on the
        // standalone `tool_calls` pathway.
        let resp = HubResponse {
            id: "resp_01".into(),
            model: "gpt-4o-mini".into(),
            content: vec![ContentPart::ToolUse {
                id: "call_1".into(),
                name: "lookup".into(),
                input: json!({"q": "a"}),
            }],
            tool_calls: vec![
                super::super::HubToolCall {
                    id: "call_1".into(),
                    name: "lookup".into(),
                    arguments: json!({"q": "a"}),
                },
                super::super::HubToolCall {
                    id: "call_2".into(),
                    name: "lookup".into(),
                    arguments: json!({"q": "b"}),
                },
            ],
            finish_reason: FinishReason::ToolCalls,
            usage: super::super::HubUsage::default(),
            extensions: Default::default(),
        };
        let bytes = fmt().from_hub(&resp, &BridgeContext::default()).unwrap();
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        let ids: Vec<&str> = parsed["output"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|item| item["type"] == "function_call")
            .filter_map(|item| item["id"].as_str())
            .collect();
        assert_eq!(ids, vec!["call_1", "call_2"], "{parsed}");
    }

    // --- WOR-2554 review: the Responses sweep ---

    fn notes_for(req: Value) -> Vec<super::super::LossinessNote> {
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        hub.lossiness
    }

    #[test]
    fn structured_output_requests_record_a_lossiness_note() {
        // Red-first: `text` was never read, `response_format` was never
        // emitted, and no note was pushed, so a client asking for
        // schema-constrained JSON got free-form prose with the counter
        // flat and nothing in the log.
        let notes = notes_for(json!({
            "model": "gpt-4.1",
            "input": "extract the fields",
            "text": {"format": {"type": "json_schema", "name": "r", "schema": {}}}
        }));
        let note = notes
            .iter()
            .find(|n| n.metric_label == "responses.text")
            .unwrap_or_else(|| panic!("expected a text note, got {notes:?}"));
        assert!(note.note.contains("free-form prose"), "{}", note.note);
    }

    #[test]
    fn unrepresented_responses_top_level_fields_record_lossiness_notes() {
        for (key, value) in [
            ("reasoning", json!({"effort": "high"})),
            ("parallel_tool_calls", json!(false)),
            ("truncation", json!("auto")),
            ("metadata", json!({"k": "v"})),
            ("include", json!(["reasoning.encrypted_content"])),
            ("top_logprobs", json!(3)),
            ("service_tier", json!("flex")),
            ("background", json!(true)),
            ("max_tool_calls", json!(2)),
            ("some_field_openai_adds_next", json!(1)),
        ] {
            let mut req = json!({"model": "gpt-4.1", "input": "hi"});
            req[key] = value.clone();
            let notes = notes_for(req);
            assert_eq!(notes.len(), 1, "{key}={value}: {notes:?}");
            assert!(
                notes[0].field.contains(key) || notes[0].field == "responses.request",
                "{key}: {:?}",
                notes[0]
            );
        }
    }

    #[test]
    fn represented_and_null_responses_fields_note_nothing() {
        let notes = notes_for(json!({
            "model": "gpt-4.1",
            "input": [{"role": "user", "content": [{"type": "input_text", "text": "hi"}]}],
            "instructions": "be terse",
            "temperature": 0.2,
            "top_p": 0.9,
            "max_output_tokens": 64,
            "stream": true,
            "tools": [{"type": "function", "name": "f", "parameters": {}}],
            "tool_choice": "required",
            "store": false,
            "metadata": null
        }));
        assert!(notes.is_empty(), "{notes:?}");
    }

    #[test]
    fn responses_tool_choice_is_honored_through_to_the_canonical_body() {
        // Red-first: the forced-tool bug WOR-2535 fixed on
        // /v1/messages still shipped here, and the hub already carried
        // HubToolChoice.
        for (wire, expected) in [
            (json!("required"), json!("required")),
            (json!("none"), json!("none")),
            (
                json!({"type": "function", "name": "get_weather"}),
                json!({"type": "function", "function": {"name": "get_weather"}}),
            ),
            (
                json!({"type": "function", "function": {"name": "get_weather"}}),
                json!({"type": "function", "function": {"name": "get_weather"}}),
            ),
        ] {
            let req = json!({
                "model": "gpt-4.1",
                "input": "hi",
                "tools": [{"type": "function", "name": "get_weather", "parameters": {}}],
                "tool_choice": wire.clone(),
            });
            let bytes = translate_responses_request_to_openai(
                req.to_string().as_bytes(),
                "test.sbproxy.dev",
                None,
            )
            .unwrap();
            let parsed: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(parsed["tool_choice"], expected, "sent {wire}");
        }
    }

    #[test]
    fn an_unmappable_responses_tool_choice_records_a_note() {
        let notes = notes_for(json!({
            "model": "gpt-4.1",
            "input": "hi",
            "tool_choice": {"type": "file_search"}
        }));
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert_eq!(notes[0].metric_label, "responses.tool_choice");
    }

    #[test]
    fn unmapped_input_content_parts_record_lossiness_notes() {
        // Red-first: `parse_responses_content_part` returned None and
        // the caller dropped it with `if let Some(..)`, so input_file,
        // refusal, and a non-string input_text vanished with no note.
        for part in [
            json!({"type": "input_file", "file_id": "file_1"}),
            json!({"type": "refusal", "refusal": "no"}),
            json!({"type": "input_text", "text": {"nested": true}}),
        ] {
            let notes = notes_for(json!({
                "model": "gpt-4.1",
                "input": [{"role": "user", "content": [part.clone()]}]
            }));
            assert_eq!(notes.len(), 1, "{part}: {notes:?}");
            assert_eq!(notes[0].metric_label, "responses.input.content", "{part}");
        }
    }

    #[test]
    fn a_non_object_input_entry_records_a_lossiness_note() {
        let notes = notes_for(json!({
            "model": "gpt-4.1",
            "input": [{"role": "user", "content": "hi"}, "stray"]
        }));
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert_eq!(notes[0].metric_label, "responses.input");
    }

    #[test]
    fn an_empty_input_text_part_is_not_counted_as_a_drop() {
        let notes = notes_for(json!({
            "model": "gpt-4.1",
            "input": [{"role": "user", "content": [
                {"type": "input_text", "text": ""},
                {"type": "input_text", "text": "hi"}
            ]}]
        }));
        assert!(notes.is_empty(), "{notes:?}");
    }

    // --- WOR-2554 review: the canonical message emitter ---

    #[test]
    fn an_image_only_turn_reaches_the_upstream_as_a_content_array() {
        // Red-first: `parts.len() == 1` flattened to `text_only`, which
        // only text parts contribute to, so a "describe this image"
        // turn arrived upstream as `"content": ""` and the model
        // answered about nothing.
        let hub = HubRequest {
            model: "gpt-4o".into(),
            messages: vec![HubMessage {
                role: Role::User,
                content: vec![ContentPart::Image {
                    source: "data:image/png;base64,iVBORw0".into(),
                    media_type: "image/png".into(),
                }],
                name: None,
                tool_call_id: None,
            }],
            ..Default::default()
        };
        let parsed: Value = serde_json::from_slice(&hub_request_to_openai_bytes(&hub)).unwrap();
        let content = &parsed["messages"][0]["content"];
        assert!(content.is_array(), "the image must survive: {parsed}");
        assert_eq!(content[0]["type"], "image_url");
        assert_eq!(
            content[0]["image_url"]["url"],
            "data:image/png;base64,iVBORw0"
        );
    }

    #[test]
    fn a_text_only_turn_still_flattens_to_a_plain_string() {
        let hub = HubRequest {
            model: "gpt-4o".into(),
            messages: vec![HubMessage {
                role: Role::User,
                content: vec![ContentPart::Text { text: "hi".into() }],
                name: None,
                tool_call_id: None,
            }],
            ..Default::default()
        };
        let parsed: Value = serde_json::from_slice(&hub_request_to_openai_bytes(&hub)).unwrap();
        assert_eq!(parsed["messages"][0]["content"], "hi");
    }

    #[test]
    fn every_tool_result_in_a_turn_reaches_the_canonical_body() {
        // Red-first: `tool_result_for` was one Option assigned inside
        // the loop, so an Anthropic parallel-tool-use turn (two
        // tool_result blocks in one user message, a shape the native
        // bypass never accepts) lost every result but the last and the
        // failure looked like a model error.
        let req = json!({
            "model": "claude-3-5-sonnet",
            "max_tokens": 100,
            "messages": [{"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_a", "content": "A"},
                {"type": "tool_result", "tool_use_id": "toolu_b", "content": "B"}
            ]}]
        });
        let bytes = super::super::anthropic_messages::translate_anthropic_request_to_openai(
            req.to_string().as_bytes(),
            "test.sbproxy.dev",
            None,
        )
        .unwrap();
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        let messages = parsed["messages"].as_array().unwrap();
        let results: Vec<(&str, &str)> = messages
            .iter()
            .filter(|m| m["role"] == "tool")
            .map(|m| {
                (
                    m["tool_call_id"].as_str().unwrap_or(""),
                    m["content"].as_str().unwrap_or(""),
                )
            })
            .collect();
        assert_eq!(
            results,
            vec![("toolu_a", "A"), ("toolu_b", "B")],
            "both results must survive: {parsed}"
        );
    }

    #[test]
    fn a_single_tool_result_turn_is_one_tool_message() {
        let hub = HubRequest {
            model: "gpt-4o".into(),
            messages: vec![HubMessage {
                role: Role::User,
                content: vec![ContentPart::ToolResult {
                    tool_call_id: "call_1".into(),
                    content: "42".into(),
                    is_error: false,
                }],
                name: None,
                tool_call_id: None,
            }],
            ..Default::default()
        };
        let parsed: Value = serde_json::from_slice(&hub_request_to_openai_bytes(&hub)).unwrap();
        let messages = parsed["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1, "{parsed}");
        assert_eq!(messages[0]["role"], "tool");
        assert_eq!(messages[0]["tool_call_id"], "call_1");
        assert_eq!(messages[0]["content"], "42");
    }
}
