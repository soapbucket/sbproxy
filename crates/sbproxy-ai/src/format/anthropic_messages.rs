//! Anthropic Messages API `ChatFormat` implementation.
//!
//! Parses the Anthropic Messages wire shape (`POST /v1/messages`) into
//! the hub, and emits hub responses back as Anthropic Messages JSON. The
//! wire shape has three differences from the hub baseline that this
//! module owns:
//!
//!   * A top-level `system` field rather than interleaved `system`
//!     turns. Maps to `HubRequest::system` directly. String and
//!     text-block-array shapes are represented; every other system
//!     value or block records a `LossinessNote` (WOR-2535).
//!   * Typed content blocks (`text`, `tool_use`, `tool_result`,
//!     `image`) that map onto the hub `ContentPart` variants. A block
//!     that maps onto no variant, an image whose source yields no
//!     string included, is dropped with a `LossinessNote` naming its
//!     sanitized type (WOR-2535, mirroring WOR-2512 on
//!     `/v1/responses`). A block the parser KEEPS gets the same
//!     treatment for every attribute it read past, `cache_control` and
//!     `citations` included, so nothing about a block is silent
//!     (WOR-2554 review).
//!   * `stop_reason` strings (`end_turn`, `max_tokens`, `tool_use`,
//!     `stop_sequence`) normalized to the hub `FinishReason`.
//!
//! `tool_choice` (auto, any, none, and forced-tool) and `top_k` are
//! honored end to end. "End to end" means past the canonical body:
//! this parser fills the hub, `hub_request_to_openai_bytes` emits the
//! canonical spelling, and each provider translator in
//! `crate::translators` rewrites it into that provider's shape, which
//! is where the first pass stopped and shipped `"tool_choice":
//! "required"` to an upstream that requires an object.
//!
//! Every top-level field outside the represented set (`metadata`,
//! `thinking`, `service_tier`, `container`, and anything newer)
//! records a `LossinessNote`, and so does a represented field whose
//! typed read fails (`"max_tokens": 1024.0`, `"stream": "true"`); the
//! translate seam ticks `sbproxy_ai_translation_dropped_total` once
//! per class and emits one bounded warn per request naming the origin
//! and tenant (WOR-2535 review, WOR-2554 review).
//!
//! Streaming for the Anthropic outbound emitter is implemented in
//! `from_hub_stream`, which turns each hub chunk into the matching
//! Anthropic Messages SSE frames (`event: message_start`,
//! `content_block_*`, `message_delta`, `message_stop`).

use serde_json::{json, Map, Value};

use super::{
    json_type_name, note_drop, BridgeContext, ChatError, ChatFormat, ContentPart, ContentPartDelta,
    FinishReason, HubChunk, HubMessage, HubRequest, HubResponse, HubToolDefinition, HubUsage, Role,
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

        // Numeric knobs go through range-honest helpers rather than
        // bare `as` casts: `max_tokens: 2^32 + 5` used to truncate to
        // 5 with no trace (review Minor 1). Values beyond u32 clamp
        // with a Downgrade note; floats that overflow f32 drop with a
        // note. In-range f64->f32 precision loss is accepted silently:
        // sampling knobs are sub-percent precision by nature.
        let mut notes: Vec<super::LossinessNote> = Vec::new();
        let mut hub = HubRequest {
            model: obj
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            temperature: finite_f32(obj, "temperature", "anthropic.temperature", &mut notes),
            top_p: finite_f32(obj, "top_p", "anthropic.top_p", &mut notes),
            top_k: clamped_u32(obj, "top_k", "anthropic.top_k", &mut notes),
            max_tokens: clamped_u32(obj, "max_tokens", "anthropic.max_tokens", &mut notes),
            stream: obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false),
            ..Default::default()
        };
        hub.lossiness = notes;

        // `model` and `stream` read through `unwrap_or`, which hides a
        // wrong-typed value behind a plausible default, and both names
        // are in the represented list so the catch-all below skips
        // them. Without these two arms `{"stream": "true"}` served one
        // buffered JSON body to a client parsing SSE, silently
        // (WOR-2554 review).
        if obj
            .get("model")
            .is_some_and(|v| !v.is_null() && !v.is_string())
        {
            let found = json_type_name(&obj["model"]);
            note_drop(
                &mut hub.lossiness,
                "anthropic.model",
                "anthropic.model".into(),
                format!(
                    "model of JSON type '{found}' dropped: expected a string, so \
                     the canonical request names no model and routing falls back \
                     to the origin default"
                ),
            );
        }
        if obj
            .get("stream")
            .is_some_and(|v| !v.is_null() && !v.is_boolean())
        {
            let found = json_type_name(&obj["stream"]);
            note_drop(
                &mut hub.lossiness,
                "anthropic.stream",
                "anthropic.stream".into(),
                format!(
                    "stream of JSON type '{found}' dropped: expected a boolean, \
                     so the request is served as one buffered body rather than \
                     the SSE stream it asked for"
                ),
            );
        }

        // Anthropic `system` is either a string or an array of typed
        // content blocks. Concatenate text blocks; every block that
        // carries no text records a `LossinessNote` naming its type,
        // and an unrepresentable `system` value records one for the
        // whole field, so the operator can see the drop (WOR-2535).
        if let Some(sys) = obj.get("system") {
            match sys {
                Value::String(s) => hub.system = Some(s.clone()),
                Value::Array(arr) => {
                    let mut chunks = Vec::new();
                    for block in arr {
                        if let Some(t) = block.get("text").and_then(|v| v.as_str()) {
                            chunks.push(t.to_string());
                        } else {
                            let label = block_type_label(block);
                            note_drop(
                                &mut hub.lossiness,
                                "anthropic.system",
                                format!("anthropic.system.{label}"),
                                format!(
                                    "system block of type '{label}' dropped: only \
                                     text blocks flatten into the hub system prompt"
                                ),
                            );
                        }
                    }
                    if !chunks.is_empty() {
                        hub.system = Some(chunks.join("\n\n"));
                    }
                }
                // A JSON null is an SDK serializing an unset optional,
                // not content; nothing is lost.
                Value::Null => {}
                other => note_drop(
                    &mut hub.lossiness,
                    "anthropic.system",
                    "anthropic.system".into(),
                    format!(
                        "system value of JSON type '{}' dropped: expected a \
                         string or an array of text blocks",
                        json_type_name(other)
                    ),
                ),
            }
        }

        match obj.get("stop_sequences") {
            Some(Value::Array(stops)) => {
                for s in stops {
                    if let Some(s) = s.as_str() {
                        hub.stop.push(s.to_string());
                    } else {
                        note_drop(
                            &mut hub.lossiness,
                            "anthropic.stop_sequences",
                            "anthropic.stop_sequences".into(),
                            format!(
                                "non-string stop_sequences entry of JSON type \
                                 '{}' dropped",
                                json_type_name(s)
                            ),
                        );
                    }
                }
            }
            None | Some(Value::Null) => {}
            Some(other) => note_drop(
                &mut hub.lossiness,
                "anthropic.stop_sequences",
                "anthropic.stop_sequences".into(),
                format!(
                    "stop_sequences value of JSON type '{}' dropped: expected \
                     an array of strings",
                    json_type_name(other)
                ),
            ),
        }

        match obj.get("messages") {
            Some(Value::Array(arr)) => {
                for m in arr {
                    if let Some(msg_obj) = m.as_object() {
                        let message = parse_anthropic_message(msg_obj, &mut hub.lossiness)?;
                        hub.messages.push(message);
                    } else {
                        note_drop(
                            &mut hub.lossiness,
                            "anthropic.messages",
                            "anthropic.messages".into(),
                            format!(
                                "non-object messages entry of JSON type '{}' \
                                 dropped",
                                json_type_name(m)
                            ),
                        );
                    }
                }
            }
            None | Some(Value::Null) => {}
            Some(other) => note_drop(
                &mut hub.lossiness,
                "anthropic.messages",
                "anthropic.messages".into(),
                format!(
                    "messages value of JSON type '{}' dropped: expected an \
                     array of message objects",
                    json_type_name(other)
                ),
            ),
        }

        // Tools: Anthropic ships `[{name, description, input_schema}]`.
        // A non-object entry or a wrong-shape `tools` value carries
        // definitions the hub cannot represent; each records a
        // `LossinessNote` (WOR-2535).
        match obj.get("tools") {
            Some(Value::Array(arr)) => {
                for t in arr {
                    if let Some(tobj) = t.as_object() {
                        // A client tool carries `input_schema`. A
                        // server tool (`web_search_20250305`,
                        // `code_execution_20250522`, ...) does not: it
                        // asks Anthropic to run the tool itself, and
                        // the canonical body has no way to say that.
                        // Forwarding it as a function with an empty
                        // description and a null schema was a mangle
                        // rather than a drop, and the provider would
                        // have asked the model to call a tool the
                        // client cannot answer (WOR-2554 review).
                        if !tobj.contains_key("input_schema") {
                            let label = super::sanitize_type_label(
                                tobj.get("type").and_then(Value::as_str).unwrap_or(""),
                            );
                            note_drop(
                                &mut hub.lossiness,
                                "anthropic.tools",
                                format!("anthropic.tools.{label}"),
                                format!(
                                    "tool of type '{label}' dropped: it declares no \
                                     input_schema, so it is a provider-run server \
                                     tool the canonical request cannot express"
                                ),
                            );
                            continue;
                        }
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
                    } else {
                        note_drop(
                            &mut hub.lossiness,
                            "anthropic.tools",
                            "anthropic.tools".into(),
                            format!(
                                "non-object tools entry of JSON type '{}' dropped",
                                json_type_name(t)
                            ),
                        );
                    }
                }
            }
            None | Some(Value::Null) => {}
            Some(other) => note_drop(
                &mut hub.lossiness,
                "anthropic.tools",
                "anthropic.tools".into(),
                format!(
                    "tools value of JSON type '{}' dropped: expected an array \
                     of tool objects",
                    json_type_name(other)
                ),
            ),
        }

        // Tool choice: Anthropic ships `{"type": "auto" | "any" |
        // "none" | "tool", ...}`. All four have canonical
        // representations, so they are honored rather than noted
        // (WOR-2535 review: the forced-tool hint used to vanish and
        // the model silently chose tools as if the client had sent
        // auto). The shapes the hub cannot carry record a note that
        // names that same fallback, because it is behavior-visible.
        match obj.get("tool_choice") {
            None | Some(Value::Null) => {}
            Some(Value::Object(tc)) => {
                match tc.get("type").and_then(Value::as_str) {
                    Some("auto") => hub.tool_choice = super::HubToolChoice::Auto,
                    Some("any") => hub.tool_choice = super::HubToolChoice::Any,
                    Some("none") => hub.tool_choice = super::HubToolChoice::None,
                    Some("tool") => match tc.get("name").and_then(Value::as_str) {
                        Some(name) => {
                            hub.tool_choice = super::HubToolChoice::Required(name.to_string());
                        }
                        None => note_drop(
                            &mut hub.lossiness,
                            "anthropic.tool_choice",
                            "anthropic.tool_choice".into(),
                            "tool_choice of type 'tool' without a string name \
                             dropped: the forced-tool requirement is lost and \
                             the model chooses tools as if tool_choice were \
                             'auto'"
                                .into(),
                        ),
                    },
                    other => {
                        let label = super::sanitize_type_label(other.unwrap_or(""));
                        note_drop(
                            &mut hub.lossiness,
                            "anthropic.tool_choice",
                            "anthropic.tool_choice".into(),
                            format!(
                                "tool_choice of type '{label}' dropped: it has \
                                 no canonical representation, so the model \
                                 chooses tools as if tool_choice were 'auto'"
                            ),
                        );
                    }
                }
                if tc.get("disable_parallel_tool_use").and_then(Value::as_bool) == Some(true) {
                    note_drop(
                        &mut hub.lossiness,
                        "anthropic.tool_choice",
                        "anthropic.tool_choice.disable_parallel_tool_use".into(),
                        "tool_choice.disable_parallel_tool_use dropped: the \
                         canonical request does not carry it, so the provider \
                         may still emit parallel tool calls"
                            .into(),
                    );
                }
            }
            Some(other) => note_drop(
                &mut hub.lossiness,
                "anthropic.tool_choice",
                "anthropic.tool_choice".into(),
                format!(
                    "tool_choice value of JSON type '{}' dropped: expected an \
                     object; the model chooses tools as if tool_choice were \
                     'auto'",
                    json_type_name(other)
                ),
            ),
        }

        // Every top-level key outside the represented set is a control
        // or content the canonical request cannot carry; each present,
        // non-null one records a note so no field vanishes silently
        // (WOR-2535 review: metadata, thinking, service_tier, and
        // container used to). The known behavior-visible fields get a
        // note naming what changes; anything else, today's unknowns
        // and tomorrow's new API fields alike, gets the generic
        // treatment under a sanitized key, so this detector is as wide
        // as the parser above.
        for (key, value) in obj {
            if value.is_null() || REPRESENTED_TOP_LEVEL_KEYS.contains(&key.as_str()) {
                continue;
            }
            match key.as_str() {
                "metadata" => note_drop(
                    &mut hub.lossiness,
                    "anthropic.metadata",
                    "anthropic.metadata".into(),
                    "metadata dropped: the canonical request does not carry \
                     it, so the provider never sees the request metadata \
                     (user_id included)"
                        .into(),
                ),
                "thinking" => note_drop(
                    &mut hub.lossiness,
                    "anthropic.thinking",
                    "anthropic.thinking".into(),
                    "thinking configuration dropped: extended thinking is not \
                     requested from the provider, so the response arrives \
                     without the thinking blocks the client asked for"
                        .into(),
                ),
                "service_tier" => note_drop(
                    &mut hub.lossiness,
                    "anthropic.service_tier",
                    "anthropic.service_tier".into(),
                    "service_tier dropped: the provider serves the request on \
                     its default tier"
                        .into(),
                ),
                "container" => note_drop(
                    &mut hub.lossiness,
                    "anthropic.container",
                    "anthropic.container".into(),
                    "container dropped: the request runs without the container \
                     reuse it asked for"
                        .into(),
                ),
                other => {
                    let label = super::sanitize_type_label(other);
                    note_drop(
                        &mut hub.lossiness,
                        "anthropic.request",
                        format!("anthropic.{label}"),
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
        chunk: &HubChunk,
        ctx: &mut BridgeContext,
    ) -> Result<Vec<String>, ChatError> {
        Ok(hub_chunk_to_anthropic_sse(chunk, ctx))
    }
}

/// Translate one hub chunk into a vector of Anthropic Messages SSE
/// frames. Each entry is a complete `event: ...\ndata: ...\n\n`
/// payload ready for the wire.
///
/// The Anthropic shape is more frame-heavy than the hub vocabulary:
/// `MessageStart` expands to `event: message_start` *and* an opening
/// `event: content_block_start` so a first `text_delta` always lands
/// at a known content block. `MessageStop` emits a
/// `event: content_block_stop` for every still-open block, then a
/// `event: message_delta` carrying `stop_reason` and the terminal
/// `event: message_stop` frame.
pub(crate) fn hub_chunk_to_anthropic_sse(chunk: &HubChunk, ctx: &mut BridgeContext) -> Vec<String> {
    match chunk {
        HubChunk::MessageStart { id, model } => {
            let start = json!({
                "type": "message_start",
                "message": {
                    "id": id,
                    "type": "message",
                    "role": "assistant",
                    "model": model,
                    "content": [],
                    "stop_reason": Value::Null,
                    "stop_sequence": Value::Null,
                    "usage": {"input_tokens": 0, "output_tokens": 0},
                }
            });
            let block_open = json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""}
            });
            record_open_block(ctx, 0);
            vec![
                format!("event: message_start\ndata: {start}\n\n"),
                format!("event: content_block_start\ndata: {block_open}\n\n"),
            ]
        }
        HubChunk::ContentDelta { index, delta } => match delta {
            ContentPartDelta::Text(t) => {
                let body = json!({
                    "type": "content_block_delta",
                    "index": index,
                    "delta": {"type": "text_delta", "text": t}
                });
                vec![format!("event: content_block_delta\ndata: {body}\n\n")]
            }
        },
        HubChunk::ToolCallDelta { index, delta } => {
            let mut frames = Vec::new();
            // The first delta carrying id+name opens a tool-use
            // content block. Subsequent argument-chunk deltas emit
            // `input_json_delta` events.
            if delta.id.is_some() || delta.name.is_some() {
                let mut block = Map::new();
                block.insert("type".into(), Value::String("tool_use".into()));
                if let Some(id) = &delta.id {
                    block.insert("id".into(), Value::String(id.clone()));
                }
                if let Some(name) = &delta.name {
                    block.insert("name".into(), Value::String(name.clone()));
                }
                block.insert("input".into(), Value::Object(Map::new()));
                let body = json!({
                    "type": "content_block_start",
                    "index": index,
                    "content_block": Value::Object(block),
                });
                record_open_block(ctx, *index);
                frames.push(format!("event: content_block_start\ndata: {body}\n\n"));
            }
            if let Some(arg) = &delta.arguments_chunk {
                let body = json!({
                    "type": "content_block_delta",
                    "index": index,
                    "delta": {"type": "input_json_delta", "partial_json": arg}
                });
                frames.push(format!("event: content_block_delta\ndata: {body}\n\n"));
            }
            frames
        }
        HubChunk::Usage(u) => {
            // Anthropic carries usage on `message_delta` rather than
            // as a standalone event; we emit a partial `message_delta`
            // here so clients that read usage incrementally see the
            // running totals.
            let body = json!({
                "type": "message_delta",
                "delta": {},
                "usage": {
                    "input_tokens": u.prompt_tokens,
                    "output_tokens": u.completion_tokens,
                }
            });
            vec![format!("event: message_delta\ndata: {body}\n\n")]
        }
        HubChunk::MessageStop { finish_reason } => {
            let stop_reason = match finish_reason {
                FinishReason::Stop => "end_turn",
                FinishReason::Length => "max_tokens",
                FinishReason::ToolCalls => "tool_use",
                FinishReason::ContentFilter => "stop_sequence",
                FinishReason::Other(s) => s.as_str(),
            };
            let mut frames = Vec::new();
            for index in take_open_block_indexes(ctx) {
                let block_close = json!({"type": "content_block_stop", "index": index});
                frames.push(format!(
                    "event: content_block_stop\ndata: {block_close}\n\n"
                ));
            }
            let mdelta = json!({
                "type": "message_delta",
                "delta": {"stop_reason": stop_reason, "stop_sequence": Value::Null},
                "usage": {"output_tokens": 0}
            });
            let mstop = json!({"type": "message_stop"});
            frames.push(format!("event: message_delta\ndata: {mdelta}\n\n"));
            frames.push(format!("event: message_stop\ndata: {mstop}\n\n"));
            frames
        }
    }
}

const OPEN_BLOCK_INDEXES: &str = "anthropic.open_block_indexes";

fn record_open_block(ctx: &mut BridgeContext, index: usize) {
    let indexes = ctx
        .extras
        .entry(OPEN_BLOCK_INDEXES.to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Some(arr) = indexes.as_array_mut() {
        let value = json!(index);
        if !arr.contains(&value) {
            arr.push(value);
        }
    }
}

fn take_open_block_indexes(ctx: &mut BridgeContext) -> Vec<usize> {
    let indexes = ctx
        .extras
        .remove(OPEN_BLOCK_INDEXES)
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let parsed: Vec<usize> = indexes
        .iter()
        .filter_map(|value| value.as_u64().map(|n| n as usize))
        .collect();
    // Isolated MessageStop fixtures (and a stream that never opened a
    // block) still need the historical index-0 terminator so single-tool
    // and text-only clients keep a well-formed block lifecycle.
    if parsed.is_empty() {
        vec![0]
    } else {
        parsed
    }
}

/// Top-level Anthropic request keys the hub represents (parsed above,
/// re-emitted by `hub_request_to_openai_bytes`). Everything else hits
/// the catch-all note loop in `to_hub`. Keep this list in lockstep
/// with the parser: a key parsed but not listed would double-note, a
/// key listed but not parsed would drop silently again.
///
/// "Represented" is about the NAME, not the value. A key here whose
/// value the parser cannot read still has to note the drop itself,
/// because this list makes the catch-all skip it: that is why
/// `clamped_u32`, `finite_f32`, and the `model` / `stream` arms in
/// `to_hub` each push a note on a wrong-typed value rather than
/// leaning on the loop below (WOR-2554 review).
const REPRESENTED_TOP_LEVEL_KEYS: &[&str] = &[
    "model",
    "messages",
    "system",
    "stop_sequences",
    "stream",
    "temperature",
    "top_p",
    "top_k",
    "max_tokens",
    "tools",
    "tool_choice",
];

/// Read an optional unsigned integer field, clamping a value beyond
/// `u32::MAX` to `u32::MAX` with a `Downgrade` note instead of the
/// silent `as u32` truncation this parser shipped with (2^32 + 5 used
/// to arrive upstream as 5).
fn clamped_u32(
    obj: &Map<String, Value>,
    field: &str,
    metric_label: &'static str,
    notes: &mut Vec<super::LossinessNote>,
) -> Option<u32> {
    let raw = obj.get(field)?;
    if raw.is_null() {
        return None;
    }
    // A wrong-typed value used to read as absent. `REPRESENTED_TOP_LEVEL_KEYS`
    // is a name list, so the catch-all below skips the key and
    // `"max_tokens": 1024.0` (a float, which `as_u64` refuses) vanished
    // with no note, no counter, and no warn (WOR-2554 review).
    let Some(n) = raw.as_u64() else {
        note_drop(
            notes,
            metric_label,
            format!("anthropic.{field}"),
            format!(
                "{field} of JSON type '{}' dropped: expected a non-negative \
                 integer, so the canonical request carries no {field} at all",
                json_type_name(raw)
            ),
        );
        return None;
    };
    match u32::try_from(n) {
        Ok(v) => Some(v),
        Err(_) => {
            notes.push(super::LossinessNote {
                field: format!("anthropic.{field}"),
                metric_label: metric_label.to_string(),
                direction: super::LossinessDirection::Downgrade,
                note: format!(
                    "{field} {n} exceeds the canonical u32 range and was \
                     clamped to {}",
                    u32::MAX
                ),
            });
            Some(u32::MAX)
        }
    }
}

/// Read an optional float field, dropping (with a note) a value whose
/// `f32` narrowing overflows to infinity. In-range precision loss is
/// accepted without a note; the sampling knobs this parses carry no
/// meaning at f64-only precision.
fn finite_f32(
    obj: &Map<String, Value>,
    field: &str,
    metric_label: &'static str,
    notes: &mut Vec<super::LossinessNote>,
) -> Option<f32> {
    let raw = obj.get(field)?;
    if raw.is_null() {
        return None;
    }
    // Same silent-drop shape as `clamped_u32`: `"temperature": "0.7"`
    // read as absent and the catch-all skipped the represented name.
    let Some(f) = raw.as_f64() else {
        note_drop(
            notes,
            metric_label,
            format!("anthropic.{field}"),
            format!(
                "{field} of JSON type '{}' dropped: expected a number, so the \
                 canonical request carries no {field} at all",
                json_type_name(raw)
            ),
        );
        return None;
    };
    let narrowed = f as f32;
    if narrowed.is_finite() {
        Some(narrowed)
    } else {
        notes.push(super::LossinessNote {
            field: format!("anthropic.{field}"),
            metric_label: metric_label.to_string(),
            direction: super::LossinessDirection::Unsupported,
            note: format!("{field} {f} overflows the canonical f32 range and was dropped"),
        });
        None
    }
}

/// Sanitized `type` label for a content block: the block's `type`
/// string through [`super::sanitize_type_label`], or `"unknown"` when
/// the entry is not an object or carries no string `type`.
fn block_type_label(block: &Value) -> String {
    super::sanitize_type_label(block.get("type").and_then(Value::as_str).unwrap_or(""))
}

/// Note every attribute of a KEPT content block that the parser read
/// past, plus every represented attribute whose typed read failed.
///
/// The "no part pushed" detector covers blocks the parser drops whole.
/// This covers the other half of the same gap: a block that yields a
/// hub part but carries `cache_control`, `citations`, a non-string
/// `id`, and so on. `native_request_is_losslessly_governable` already
/// documented this hole in its own doc comment, so the enforcer
/// described a case the detector could not see (WOR-2554 review).
fn note_block_attribute_drops(part: &Value, lossiness: &mut Vec<super::LossinessNote>) {
    let Some(p) = part.as_object() else {
        return;
    };
    let ty = block_type_label(part);
    // Second slot: represented keys whose value the parser reads with
    // `unwrap_or("")`, so a wrong type produces an empty field rather
    // than a dropped block. Keys whose failure already routes to the
    // no-part-pushed detector (`text`, `image.source`) are not listed.
    let (represented, string_valued): (&[&str], &[&str]) = match ty.as_str() {
        "text" => (&["type", "text"], &[]),
        "tool_use" => (&["type", "id", "name", "input"], &["id", "name"]),
        "tool_result" => (
            &["type", "tool_use_id", "content", "is_error"],
            &["tool_use_id"],
        ),
        "image" => (&["type", "source"], &[]),
        _ => return,
    };
    for key in p.keys() {
        if represented.contains(&key.as_str()) {
            continue;
        }
        let label = super::sanitize_type_label(key);
        note_drop(
            lossiness,
            "anthropic.messages.content",
            format!("anthropic.messages.content.{ty}.{label}"),
            format!(
                "attribute '{label}' on a kept '{ty}' content block dropped: the \
                 canonical request carries the block's content only, so the \
                 provider never sees it"
            ),
        );
    }
    for field in string_valued {
        let Some(value) = p.get(*field) else {
            continue;
        };
        if value.is_null() || value.is_string() {
            continue;
        }
        note_drop(
            lossiness,
            "anthropic.messages.content",
            format!("anthropic.messages.content.{ty}.{field}"),
            format!(
                "'{field}' on a '{ty}' content block is JSON type '{}' rather \
                 than a string, so the canonical block carries an empty value",
                json_type_name(value)
            ),
        );
    }
}

/// Parse one Anthropic message object into a `HubMessage`, recording a
/// `LossinessNote` into `lossiness` for every content block or content
/// value that yields no hub representation (WOR-2535).
pub(crate) fn parse_anthropic_message(
    obj: &Map<String, Value>,
    lossiness: &mut Vec<super::LossinessNote>,
) -> Result<HubMessage, ChatError> {
    // WOR-599: parse via the shared helper (missing or unknown role -> error,
    // never a silent default to user), then enforce that Anthropic message
    // turns carry only user or assistant roles (system is a top-level field,
    // tool results are content blocks).
    let role = super::parse_role(obj)?;
    if !matches!(role, Role::User | Role::Assistant) {
        return Err(ChatError::bad_request(format!(
            "anthropic messages support only 'user' and 'assistant' roles, got {role:?}"
        )));
    }

    let mut content: Vec<ContentPart> = Vec::new();
    match obj.get("content") {
        Some(Value::String(s)) => {
            content.push(ContentPart::Text { text: s.clone() });
        }
        Some(Value::Array(arr)) => {
            for part in arr {
                let parts_before = content.len();
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
                            // Anthropic ships the result body as a
                            // string or as a nested array of content
                            // blocks; text blocks flatten into the hub
                            // result string, and every other nested
                            // block or body shape records a
                            // `LossinessNote` (WOR-2535).
                            let body = match p.get("content") {
                                Some(Value::String(s)) => s.clone(),
                                Some(Value::Array(blocks)) => {
                                    let mut chunks: Vec<String> = Vec::new();
                                    for b in blocks {
                                        if let Some(t) = b.get("text").and_then(|t| t.as_str()) {
                                            chunks.push(t.to_string());
                                        } else {
                                            let label = block_type_label(b);
                                            note_drop(
                                                lossiness,
                                                "anthropic.messages.tool_result",
                                                format!("anthropic.messages.tool_result.{label}"),
                                                format!(
                                                    "tool_result content block of type \
                                                     '{label}' dropped: only text blocks \
                                                     flatten into the hub tool result"
                                                ),
                                            );
                                        }
                                    }
                                    chunks.join("")
                                }
                                None | Some(Value::Null) => String::new(),
                                Some(other) => {
                                    note_drop(
                                        lossiness,
                                        "anthropic.messages.tool_result",
                                        "anthropic.messages.tool_result".into(),
                                        format!(
                                            "tool_result content of JSON type '{}' \
                                             dropped: expected a string or an array \
                                             of content blocks",
                                            json_type_name(other)
                                        ),
                                    );
                                    String::new()
                                }
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
                            // the source string verbatim. A source
                            // shape that yields no string (a file id,
                            // a wrong-typed object) used to be mangled
                            // into an empty-source image part; pushing
                            // nothing here routes it to the
                            // no-part-pushed detector below instead,
                            // so it drops with a note rather than
                            // forwarding a part the client never sent
                            // (WOR-2554 decision).
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
                            if !source.is_empty() {
                                let media_type = src
                                    .get("media_type")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("image/*")
                                    .to_string();
                                content.push(ContentPart::Image { source, media_type });
                            }
                        }
                        _ => {}
                    }
                }
                // WOR-2535: the drop detector sits on "no part pushed"
                // rather than on a list of unknown types, so a
                // malformed known-type block (a `text` block with no
                // string `text`) and a non-object entry are caught by
                // the same seam as an unknown block type.
                if content.len() == parts_before {
                    let label = block_type_label(part);
                    note_drop(
                        lossiness,
                        "anthropic.messages.content",
                        format!("anthropic.messages.content.{label}"),
                        format!(
                            "content block of type '{label}' dropped: it has no \
                             representation in the canonical request the gateway \
                             governs"
                        ),
                    );
                } else {
                    // A block the parser KEEPS can still carry
                    // attributes it read past. `cache_control` is the
                    // expensive one: prompt caching never engages and
                    // the customer pays full input price on every turn
                    // of a long conversation (WOR-2554 review).
                    note_block_attribute_drops(part, lossiness);
                }
            }
        }
        // Absent content is an empty turn and a JSON null is an SDK
        // serializing an unset optional; neither loses content.
        None | Some(Value::Null) => {}
        Some(other) => note_drop(
            lossiness,
            "anthropic.messages.content",
            "anthropic.messages.content".into(),
            format!(
                "message content of JSON type '{}' dropped: expected a string \
                 or an array of content blocks",
                json_type_name(other)
            ),
        ),
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
    // Standalone tool_calls also surface as tool_use blocks in the
    // Anthropic shape, but only the calls `content` does not already
    // carry: the hub mirrors every model tool call into both `content`
    // and `tool_calls` (see `HubResponse::tool_calls`), so emitting
    // both pathways unconditionally duplicated every block (WOR-2535
    // comment-drift sweep; the old comment promised "separate from
    // content" while the code emitted all of them).
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
pub fn translate_anthropic_request_to_openai(
    body: &[u8],
    origin: &str,
    tenant: Option<&str>,
) -> Result<Vec<u8>, ChatError> {
    let (hub, _ctx) = AnthropicMessagesFormat.to_hub(body)?;
    // Nothing downstream reads `hub.lossiness` on this path, so this
    // seam is what makes each drop observable: the folded drop counter
    // plus one aggregated, bounded warn for the request (WOR-2535; the
    // review killed the per-note warn loop, which was a
    // client-reachable log flood). `origin` and `tenant` name the
    // caller on the warn so an alert on the counter has somewhere to
    // go next.
    super::report_translation_lossiness(
        crate::handler::AiSurface::Messages.label(),
        origin,
        tenant,
        &hub.lossiness,
    );
    Ok(super::openai_responses::hub_request_to_openai_bytes(&hub))
}

/// Return whether every Anthropic request field that can affect content or
/// provider behavior is represented in the canonical request inspected by
/// gateway governance.
///
/// The Anthropic parser notes what it cannot represent rather than
/// representing it: an unmappable content block is dropped with a
/// `LossinessNote`, and so is every extension attribute on a block it
/// keeps. A note is a record, not a substitute for governance, so
/// native byte forwarding is safe only when this stricter check proves
/// no such field can skip the canonical policy path. This is
/// deliberately conservative: new Anthropic fields remain on the translated
/// path until their canonical representation is implemented here and in the
/// hub bridge.
pub fn native_request_is_losslessly_governable(body: &[u8]) -> bool {
    let Ok(Value::Object(request)) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    if !has_only_keys(
        &request,
        &[
            "model",
            "messages",
            "max_tokens",
            "system",
            "stop_sequences",
            "stream",
            "temperature",
            "top_p",
            "tools",
        ],
    ) {
        return false;
    }
    if request.get("model").and_then(Value::as_str).is_none()
        || request
            .get("messages")
            .and_then(Value::as_array)
            .is_none_or(|messages| !messages.iter().all(governable_message))
    {
        return false;
    }
    if request.get("max_tokens").is_some_and(|value| {
        value
            .as_u64()
            .is_none_or(|tokens| tokens > u64::from(u32::MAX))
    }) || request
        .get("stream")
        .is_some_and(|value| !value.is_boolean())
        || ["temperature", "top_p"].iter().any(|field| {
            request
                .get(*field)
                .is_some_and(|value| !governable_f32(value))
        })
        || request.get("stop_sequences").is_some_and(|value| {
            value
                .as_array()
                .is_none_or(|items| !items.iter().all(Value::is_string))
        })
        || request
            .get("system")
            .is_some_and(|value| !governable_system(value))
        || request.get("tools").is_some_and(|value| {
            value
                .as_array()
                .is_none_or(|tools| !tools.iter().all(governable_tool))
        })
    {
        return false;
    }
    true
}

fn has_only_keys(object: &Map<String, Value>, allowed: &[&str]) -> bool {
    object.keys().all(|key| allowed.contains(&key.as_str()))
}

fn governable_system(value: &Value) -> bool {
    match value {
        Value::String(_) => true,
        Value::Array(blocks) => blocks.iter().all(governable_text_block),
        _ => false,
    }
}

fn governable_f32(value: &Value) -> bool {
    value
        .as_f64()
        .is_some_and(|number| (number as f32).is_finite())
}

fn governable_message(value: &Value) -> bool {
    let Some(message) = value.as_object() else {
        return false;
    };
    if !has_only_keys(message, &["role", "content"])
        || !matches!(
            message.get("role").and_then(Value::as_str),
            Some("user" | "assistant")
        )
    {
        return false;
    }
    match message.get("content") {
        Some(Value::String(_)) => true,
        Some(Value::Array(blocks)) => {
            if !blocks.iter().all(governable_content_block) {
                return false;
            }
            let tool_result_count = blocks
                .iter()
                .filter(|block| block.get("type").and_then(Value::as_str) == Some("tool_result"))
                .count();
            tool_result_count == 0 || (tool_result_count == 1 && blocks.len() == 1)
        }
        _ => false,
    }
}

fn governable_content_block(value: &Value) -> bool {
    let Some(block) = value.as_object() else {
        return false;
    };
    match block.get("type").and_then(Value::as_str) {
        Some("text") => governable_text_block(value),
        Some("tool_use") => {
            has_only_keys(block, &["type", "id", "name", "input"])
                && block.get("id").is_some_and(Value::is_string)
                && block.get("name").is_some_and(Value::is_string)
                && block.contains_key("input")
        }
        Some("tool_result") => {
            has_only_keys(block, &["type", "tool_use_id", "content"])
                && block.get("tool_use_id").is_some_and(Value::is_string)
                && block
                    .get("content")
                    .is_some_and(governable_tool_result_content)
        }
        _ => false,
    }
}

fn governable_text_block(value: &Value) -> bool {
    value.as_object().is_some_and(|block| {
        has_only_keys(block, &["type", "text"])
            && block.get("type").and_then(Value::as_str) == Some("text")
            && block.get("text").is_some_and(Value::is_string)
    })
}

fn governable_tool_result_content(value: &Value) -> bool {
    match value {
        Value::String(_) => true,
        Value::Array(blocks) => blocks.iter().all(governable_text_block),
        _ => false,
    }
}

fn governable_tool(value: &Value) -> bool {
    value.as_object().is_some_and(|tool| {
        has_only_keys(tool, &["name", "description", "input_schema"])
            && tool.get("name").is_some_and(Value::is_string)
            && tool.get("description").is_none_or(Value::is_string)
            && tool.contains_key("input_schema")
    })
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
    // WOR-1809: a reasoning model can spend the entire max_tokens budget
    // on thinking. The bridge keeps thinking out of `content`, so the
    // client sees an empty message with `stop_reason: max_tokens` and no
    // hint why. Name the cause so the operator raises max_tokens instead
    // of debugging an "empty response".
    let choice0 = parsed.get("choices").and_then(|c| c.get(0));
    let msg = choice0.and_then(|c| c.get("message"));
    let budget_ate_reasoning = choice0
        .and_then(|c| c.get("finish_reason"))
        .and_then(|f| f.as_str())
        == Some("length")
        && msg
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .is_none_or(str::is_empty)
        && msg
            .and_then(|m| m.get("reasoning_content"))
            .and_then(|c| c.as_str())
            .is_some_and(|s| !s.is_empty());
    if budget_ate_reasoning {
        tracing::warn!(
            "anthropic bridge: empty content with stop_reason max_tokens; the model spent the \
             whole token budget on reasoning. Raise the request's max_tokens."
        );
    }
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
    fn native_bypass_eligibility_rejects_content_the_hub_drops() {
        for block in [
            json!({
                "type": "document",
                "source": {"type": "text", "data": "governed document"}
            }),
            json!({
                "type": "search_result",
                "source": "search",
                "content": [{"type": "text", "text": "governed result"}]
            }),
        ] {
            let req = json!({
                "model": "claude-3-5-sonnet",
                "max_tokens": 64,
                "messages": [{
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "supported"},
                        block
                    ]
                }]
            });
            assert!(!native_request_is_losslessly_governable(
                req.to_string().as_bytes()
            ));
        }
    }

    #[test]
    fn native_bypass_eligibility_accepts_fully_governed_messages() {
        let req = json!({
            "model": "claude-3-5-sonnet",
            "max_tokens": 64,
            "system": [{"type": "text", "text": "be concise"}],
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "hello"}]},
                {
                    "role": "assistant",
                    "content": [{
                        "type": "tool_use",
                        "id": "toolu_1",
                        "name": "lookup",
                        "input": {"query": "hello"}
                    }]
                },
                {
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": "toolu_1",
                        "content": "result"
                    }]
                }
            ],
            "stop_sequences": ["STOP"],
            "tools": [{
                "name": "lookup",
                "description": "Look up a value",
                "input_schema": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}}
                }
            }]
        });
        assert!(native_request_is_losslessly_governable(
            req.to_string().as_bytes()
        ));
    }

    #[test]
    fn native_bypass_eligibility_rejects_unrepresented_controls() {
        let base = json!({
            "model": "claude-3-5-sonnet",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}]
        });
        for req in [
            {
                let mut request = base.clone();
                request["top_k"] = json!(40);
                request
            },
            {
                let mut request = base.clone();
                request["metadata"] = json!({"user_id": "customer-1"});
                request
            },
            {
                let mut request = base.clone();
                request["messages"][0]["content"] = json!([{
                    "type": "text",
                    "text": "hello",
                    "cache_control": {"type": "ephemeral"}
                }]);
                request
            },
            {
                let mut request = base.clone();
                request["temperature"] = json!(1e100);
                request
            },
        ] {
            assert!(!native_request_is_losslessly_governable(
                req.to_string().as_bytes()
            ));
        }
    }

    #[test]
    fn native_bypass_eligibility_rejects_lossy_tool_result_arrays() {
        for content in [
            json!([
                {
                    "type": "tool_result",
                    "tool_use_id": "toolu_1",
                    "content": "first result"
                },
                {
                    "type": "tool_result",
                    "tool_use_id": "toolu_2",
                    "content": "second result"
                }
            ]),
            json!([
                {"type": "text", "text": "context the bridge would drop"},
                {
                    "type": "tool_result",
                    "tool_use_id": "toolu_1",
                    "content": "tool result"
                }
            ]),
        ] {
            let req = json!({
                "model": "claude-3-5-sonnet",
                "max_tokens": 64,
                "messages": [{"role": "user", "content": content}]
            });
            assert!(!native_request_is_losslessly_governable(
                req.to_string().as_bytes()
            ));
        }
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
    fn streaming_message_start_emits_two_frames() {
        let frames = fmt()
            .from_hub_stream(
                &HubChunk::MessageStart {
                    id: "msg_1".into(),
                    model: "claude-3-5-sonnet".into(),
                },
                &mut BridgeContext::default(),
            )
            .unwrap();
        assert_eq!(frames.len(), 2);
        assert!(frames[0].starts_with("event: message_start\n"));
        assert!(frames[1].starts_with("event: content_block_start\n"));
    }

    #[test]
    fn streaming_text_delta_emits_content_block_delta() {
        let frames = fmt()
            .from_hub_stream(
                &HubChunk::ContentDelta {
                    index: 0,
                    delta: super::super::ContentPartDelta::Text("hi".into()),
                },
                &mut BridgeContext::default(),
            )
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert!(frames[0].contains("text_delta"));
        assert!(frames[0].contains("\"text\":\"hi\""));
    }

    #[test]
    fn streaming_stop_emits_three_terminator_frames() {
        let frames = fmt()
            .from_hub_stream(
                &HubChunk::MessageStop {
                    finish_reason: FinishReason::ToolCalls,
                },
                &mut BridgeContext::default(),
            )
            .unwrap();
        assert_eq!(frames.len(), 3);
        assert!(frames[0].contains("content_block_stop"));
        assert!(frames[1].contains("\"stop_reason\":\"tool_use\""));
        assert!(frames[2].contains("message_stop"));
    }

    #[test]
    fn streaming_stop_closes_every_open_tool_block_index() {
        // WOR-2425: MessageStart opens text at 0, and each tool-call
        // opening delta opens its own index. The terminator has to
        // close every one of those, not just index 0.
        let mut ctx = BridgeContext::default();
        let _ = fmt()
            .from_hub_stream(
                &HubChunk::MessageStart {
                    id: "msg_1".into(),
                    model: "claude-3-5-sonnet".into(),
                },
                &mut ctx,
            )
            .unwrap();
        for (index, (id, name)) in [
            (1usize, ("toolu_1", "get_weather")),
            (2usize, ("toolu_2", "get_time")),
        ] {
            let _ = fmt()
                .from_hub_stream(
                    &HubChunk::ToolCallDelta {
                        index,
                        delta: super::super::HubToolCallDelta {
                            id: Some(id.into()),
                            name: Some(name.into()),
                            arguments_chunk: Some("{}".into()),
                        },
                    },
                    &mut ctx,
                )
                .unwrap();
        }
        let frames = fmt()
            .from_hub_stream(
                &HubChunk::MessageStop {
                    finish_reason: FinishReason::ToolCalls,
                },
                &mut ctx,
            )
            .unwrap();
        let stop_indexes: Vec<u64> = frames
            .iter()
            .filter(|frame| frame.contains("content_block_stop"))
            .map(|frame| {
                let data = frame
                    .split("data: ")
                    .nth(1)
                    .and_then(|rest| rest.split('\n').next())
                    .expect("sse data line");
                serde_json::from_str::<Value>(data).unwrap()["index"]
                    .as_u64()
                    .expect("stop index")
            })
            .collect();
        assert_eq!(
            stop_indexes,
            vec![0, 1, 2],
            "every opened block must close: {frames:?}"
        );
        assert!(frames
            .iter()
            .any(|f| f.contains("\"stop_reason\":\"tool_use\"")));
        assert!(frames.iter().any(|f| f.contains("message_stop")));
    }

    #[test]
    fn streaming_tool_call_emits_block_start_then_input_delta() {
        // First delta carrying id+name opens the block.
        let f1 = fmt()
            .from_hub_stream(
                &HubChunk::ToolCallDelta {
                    index: 1,
                    delta: super::super::HubToolCallDelta {
                        id: Some("toolu_1".into()),
                        name: Some("get_weather".into()),
                        arguments_chunk: None,
                    },
                },
                &mut BridgeContext::default(),
            )
            .unwrap();
        assert_eq!(f1.len(), 1);
        assert!(f1[0].contains("content_block_start"));
        assert!(f1[0].contains("\"tool_use\""));
        // Subsequent delta with arguments emits input_json_delta only.
        let f2 = fmt()
            .from_hub_stream(
                &HubChunk::ToolCallDelta {
                    index: 1,
                    delta: super::super::HubToolCallDelta {
                        id: None,
                        name: None,
                        arguments_chunk: Some("{\"ci".into()),
                    },
                },
                &mut BridgeContext::default(),
            )
            .unwrap();
        assert_eq!(f2.len(), 1);
        assert!(f2[0].contains("input_json_delta"));
        assert!(f2[0].contains("partial_json"));
    }

    #[test]
    fn system_non_text_block_records_lossiness_note() {
        // WOR-2535: the parser claimed non-text system blocks were
        // "flagged as lossiness" while pushing no note. Every dropped
        // system block must leave a trace naming its type.
        let req = json!({
            "model": "claude-3-5-sonnet",
            "system": [
                {"type": "text", "text": "be terse"},
                {"type": "server_instructions", "value": "governed"}
            ],
            "messages": [{"role": "user", "content": "hi"}]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.system.as_deref(), Some("be terse"));
        assert_eq!(hub.lossiness.len(), 1);
        let note = &hub.lossiness[0];
        assert_eq!(note.field, "anthropic.system.server_instructions");
        assert_eq!(
            note.direction,
            super::super::LossinessDirection::Unsupported
        );
        assert!(note.note.contains("server_instructions"), "{}", note.note);
    }

    #[test]
    fn system_block_label_is_sanitized_for_logs() {
        // The block type is client-controlled and lands in the note field
        // and the warn log; hostile characters must not pass through.
        let req = json!({
            "model": "claude-3-5-sonnet",
            "system": [{"type": "we ird\ntype!"}],
            "messages": [{"role": "user", "content": "hi"}]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.lossiness.len(), 1);
        assert_eq!(hub.lossiness[0].field, "anthropic.system.we_ird_type_");
    }

    #[test]
    fn system_unsupported_shape_records_lossiness_note() {
        // A system value that is neither a string nor an array is content
        // the client sent that the hub cannot carry; the drop is noted.
        let req = json!({
            "model": "claude-3-5-sonnet",
            "system": 42,
            "messages": [{"role": "user", "content": "hi"}]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.system, None);
        assert_eq!(hub.lossiness.len(), 1);
        assert_eq!(hub.lossiness[0].field, "anthropic.system");
        assert!(
            hub.lossiness[0].note.contains("number"),
            "{}",
            hub.lossiness[0].note
        );
    }

    #[test]
    fn system_null_is_not_a_drop() {
        // SDKs serialize unset optionals as null; nothing is lost.
        let req = json!({
            "model": "claude-3-5-sonnet",
            "system": null,
            "messages": [{"role": "user", "content": "hi"}]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.system, None);
        assert!(hub.lossiness.is_empty());
    }

    #[test]
    fn unknown_content_block_records_lossiness_note() {
        // A `document` block has no hub representation and must be named
        // rather than silently vanishing (WOR-2535, the same class
        // WOR-2512 closed on the Responses tools loop).
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "supported"},
                    {"type": "document", "source": {"type": "text", "data": "dropped"}}
                ]
            }]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.messages[0].content.len(), 1);
        assert_eq!(hub.lossiness.len(), 1);
        assert_eq!(
            hub.lossiness[0].field,
            "anthropic.messages.content.document"
        );
    }

    #[test]
    fn text_block_without_text_records_lossiness_note() {
        // The drop detector sits on "no hub part produced", not on a list
        // of unknown types, so a malformed known-type block is caught by
        // the same seam as an unknown type.
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{
                "role": "user",
                "content": [{"type": "text", "text": 7}]
            }]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert!(hub.messages[0].content.is_empty());
        assert_eq!(hub.lossiness.len(), 1);
        assert_eq!(hub.lossiness[0].field, "anthropic.messages.content.text");
    }

    #[test]
    fn non_object_content_entry_records_lossiness_note() {
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{
                "role": "user",
                "content": ["rogue", {"type": "text", "text": "hi"}]
            }]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.messages[0].content.len(), 1);
        assert_eq!(hub.lossiness.len(), 1);
        assert_eq!(hub.lossiness[0].field, "anthropic.messages.content.unknown");
    }

    #[test]
    fn unsupported_content_shape_records_lossiness_note() {
        // Content that is neither a string nor an array drops the whole
        // turn body; a null stays silent (an SDK's unset optional).
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{"role": "user", "content": 42}]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert!(hub.messages[0].content.is_empty());
        assert_eq!(hub.lossiness.len(), 1);
        assert_eq!(hub.lossiness[0].field, "anthropic.messages.content");

        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{"role": "user", "content": null}]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert!(hub.lossiness.is_empty());
    }

    #[test]
    fn tool_result_non_text_block_records_lossiness_note() {
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": "toolu_1",
                    "content": [
                        {"type": "text", "text": "ok"},
                        {"type": "image", "source": {"media_type": "image/png", "data": "abc=="}}
                    ]
                }]
            }]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        match &hub.messages[0].content[0] {
            ContentPart::ToolResult { content, .. } => assert_eq!(content, "ok"),
            other => panic!("expected tool_result, got {other:?}"),
        }
        assert_eq!(hub.lossiness.len(), 1);
        assert_eq!(
            hub.lossiness[0].field,
            "anthropic.messages.tool_result.image"
        );
    }

    #[test]
    fn tool_result_unsupported_content_shape_records_lossiness_note() {
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": "toolu_1",
                    "content": {"nested": "object"}
                }]
            }]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        match &hub.messages[0].content[0] {
            ContentPart::ToolResult { content, .. } => assert_eq!(content, ""),
            other => panic!("expected tool_result, got {other:?}"),
        }
        assert_eq!(hub.lossiness.len(), 1);
        assert_eq!(hub.lossiness[0].field, "anthropic.messages.tool_result");
    }

    #[test]
    fn non_string_stop_sequence_records_lossiness_note() {
        let req = json!({
            "model": "claude-3-5-sonnet",
            "stop_sequences": ["STOP", 42],
            "messages": [{"role": "user", "content": "hi"}]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.stop, vec!["STOP".to_string()]);
        assert_eq!(hub.lossiness.len(), 1);
        assert_eq!(hub.lossiness[0].field, "anthropic.stop_sequences");
    }

    #[test]
    fn non_object_message_entry_records_lossiness_note() {
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{"role": "user", "content": "hi"}, "rogue"]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.messages.len(), 1);
        assert_eq!(hub.lossiness.len(), 1);
        assert_eq!(hub.lossiness[0].field, "anthropic.messages");
    }

    #[test]
    fn non_object_tool_entry_records_lossiness_note() {
        let req = json!({
            "model": "claude-3-5-sonnet",
            "tools": [
                {"name": "lookup", "description": "", "input_schema": {}},
                42
            ],
            "messages": [{"role": "user", "content": "hi"}]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.tools.len(), 1);
        assert_eq!(hub.lossiness.len(), 1);
        assert_eq!(hub.lossiness[0].field, "anthropic.tools");
    }

    #[test]
    fn wrong_shape_top_level_fields_record_lossiness_notes() {
        // A messages/tools/stop_sequences value of the wrong JSON type
        // silently dropped everything it carried; each records a note.
        for (field, value) in [
            ("messages", json!("hi")),
            ("tools", json!({"name": "lookup"})),
            ("stop_sequences", json!("STOP")),
        ] {
            let mut req = json!({
                "model": "claude-3-5-sonnet",
                "messages": [{"role": "user", "content": "hi"}]
            });
            req[field] = value;
            let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
            assert_eq!(hub.lossiness.len(), 1, "{field}");
            assert_eq!(hub.lossiness[0].field, format!("anthropic.{field}"));
        }
    }

    #[test]
    fn translate_seam_keeps_dropped_blocks_out_of_the_openai_body() {
        // The dispatch shim calls translate_anthropic_request_to_openai,
        // which warn-logs each lossiness note (WOR-2535); the dropped
        // blocks must not leak into the canonical OpenAI body either.
        let req = json!({
            "model": "claude-3-5-sonnet",
            "system": [
                {"type": "text", "text": "be terse"},
                {"type": "server_instructions", "value": "governed"}
            ],
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "supported"},
                    {"type": "document", "source": {"type": "text", "data": "dropped"}}
                ]
            }]
        });
        let bytes = translate_anthropic_request_to_openai(
            req.to_string().as_bytes(),
            "test.sbproxy.dev",
            None,
        )
        .unwrap();
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["messages"][0]["role"], "system");
        assert_eq!(parsed["messages"][0]["content"], "be terse");
        let body = String::from_utf8(bytes).unwrap();
        assert!(!body.contains("document"), "{body}");
    }

    #[test]
    fn openai_tool_call_response_emits_a_single_tool_use_block() {
        // WOR-2535 drift sweep: the emit comment promised "standalone
        // tool_calls (separate from content)" but the code emitted every
        // hub-mirrored call twice: once from `content`, once from
        // `tool_calls`.
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
        let body = translate_openai_response_to_anthropic(openai.to_string().as_bytes());
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        let tool_use_blocks: Vec<&Value> = parsed["content"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|b| b["type"] == "tool_use")
            .collect();
        assert_eq!(tool_use_blocks.len(), 1, "{parsed}");
        assert_eq!(tool_use_blocks[0]["id"], "call_1");
        assert_eq!(parsed["stop_reason"], "tool_use");
    }

    #[test]
    fn standalone_tool_calls_still_emit_blocks() {
        // Deduplication must not eat a call that exists only on the
        // standalone `tool_calls` pathway.
        let resp = HubResponse {
            id: "msg_01".into(),
            model: "claude-3-5-sonnet".into(),
            content: vec![ContentPart::ToolUse {
                id: "toolu_1".into(),
                name: "lookup".into(),
                input: json!({"q": "a"}),
            }],
            tool_calls: vec![
                super::super::HubToolCall {
                    id: "toolu_1".into(),
                    name: "lookup".into(),
                    arguments: json!({"q": "a"}),
                },
                super::super::HubToolCall {
                    id: "toolu_2".into(),
                    name: "lookup".into(),
                    arguments: json!({"q": "b"}),
                },
            ],
            finish_reason: FinishReason::ToolCalls,
            usage: HubUsage::default(),
            extensions: Default::default(),
        };
        let bytes = fmt().from_hub(&resp, &BridgeContext::default()).unwrap();
        let out: Value = serde_json::from_slice(&bytes).unwrap();
        let ids: Vec<&str> = out["content"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|b| b["type"] == "tool_use")
            .filter_map(|b| b["id"].as_str())
            .collect();
        assert_eq!(ids, vec!["toolu_1", "toolu_2"]);
    }

    // --- WOR-2535 fix round: honored controls ---

    #[test]
    fn tool_choice_forced_tool_is_honored_in_the_openai_body() {
        // Red-first for the review's Major 1: a forced-tool hint used to
        // vanish in to_hub, so the model was silently told "auto".
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"name": "lookup", "description": "d", "input_schema": {}}],
            "tool_choice": {"type": "tool", "name": "lookup"}
        });
        let bytes = translate_anthropic_request_to_openai(
            req.to_string().as_bytes(),
            "test.sbproxy.dev",
            None,
        )
        .unwrap();
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["tool_choice"]["type"], "function", "{parsed}");
        assert_eq!(
            parsed["tool_choice"]["function"]["name"], "lookup",
            "{parsed}"
        );
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert!(
            hub.lossiness.is_empty(),
            "honored, not noted: {:?}",
            hub.lossiness
        );
    }

    #[test]
    fn tool_choice_any_maps_to_openai_required() {
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{"role": "user", "content": "hi"}],
            "tool_choice": {"type": "any"}
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.tool_choice, super::super::HubToolChoice::Any);
        assert!(hub.lossiness.is_empty(), "{:?}", hub.lossiness);
        let bytes = translate_anthropic_request_to_openai(
            req.to_string().as_bytes(),
            "test.sbproxy.dev",
            None,
        )
        .unwrap();
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["tool_choice"], "required", "{parsed}");
    }

    #[test]
    fn tool_choice_none_and_auto_are_honored() {
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{"role": "user", "content": "hi"}],
            "tool_choice": {"type": "none"}
        });
        let bytes = translate_anthropic_request_to_openai(
            req.to_string().as_bytes(),
            "test.sbproxy.dev",
            None,
        )
        .unwrap();
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["tool_choice"], "none", "{parsed}");

        // auto is the OpenAI default: honored by emitting nothing.
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{"role": "user", "content": "hi"}],
            "tool_choice": {"type": "auto"}
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert!(hub.lossiness.is_empty(), "{:?}", hub.lossiness);
        let bytes = translate_anthropic_request_to_openai(
            req.to_string().as_bytes(),
            "test.sbproxy.dev",
            None,
        )
        .unwrap();
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(parsed.get("tool_choice").is_none(), "{parsed}");
    }

    #[test]
    fn tool_choice_unknown_type_note_names_the_auto_fallback() {
        // The one tool_choice shape the hub cannot carry is
        // behavior-visible: the model chooses tools as if the client
        // had sent auto. The note must say so.
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{"role": "user", "content": "hi"}],
            "tool_choice": {"type": "so mething odd"}
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.lossiness.len(), 1, "{:?}", hub.lossiness);
        let note = &hub.lossiness[0];
        assert_eq!(note.field, "anthropic.tool_choice");
        assert_eq!(note.metric_label, "anthropic.tool_choice");
        assert!(note.note.contains("auto"), "{}", note.note);
        assert!(note.note.contains("so_mething_odd"), "{}", note.note);
    }

    #[test]
    fn tool_choice_forced_tool_without_a_name_notes_the_auto_fallback() {
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{"role": "user", "content": "hi"}],
            "tool_choice": {"type": "tool"}
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.tool_choice, super::super::HubToolChoice::Auto);
        assert_eq!(hub.lossiness.len(), 1, "{:?}", hub.lossiness);
        assert!(
            hub.lossiness[0].note.contains("auto"),
            "{}",
            hub.lossiness[0].note
        );
    }

    #[test]
    fn tool_choice_disable_parallel_tool_use_records_a_note() {
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{"role": "user", "content": "hi"}],
            "tool_choice": {"type": "auto", "disable_parallel_tool_use": true}
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.tool_choice, super::super::HubToolChoice::Auto);
        assert_eq!(hub.lossiness.len(), 1, "{:?}", hub.lossiness);
        assert_eq!(
            hub.lossiness[0].field,
            "anthropic.tool_choice.disable_parallel_tool_use"
        );
        assert!(
            hub.lossiness[0].note.contains("parallel"),
            "{}",
            hub.lossiness[0].note
        );
    }

    #[test]
    fn top_k_reaches_the_openai_body() {
        // Red-first: top_k was parsed into the hub and then never
        // emitted, so the sampling control silently vanished.
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{"role": "user", "content": "hi"}],
            "top_k": 40
        });
        let bytes = translate_anthropic_request_to_openai(
            req.to_string().as_bytes(),
            "test.sbproxy.dev",
            None,
        )
        .unwrap();
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["top_k"], 40, "{parsed}");
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert!(
            hub.lossiness.is_empty(),
            "honored, not noted: {:?}",
            hub.lossiness
        );
    }

    // --- WOR-2535 fix round: noted top-level drops ---

    #[test]
    fn unrepresented_top_level_fields_record_lossiness_notes() {
        // metadata / service_tier / container / unknown keys used to
        // vanish with no note and no warn.
        for (key, value, field) in [
            ("metadata", json!({"user_id": "u1"}), "anthropic.metadata"),
            (
                "service_tier",
                json!("standard_only"),
                "anthropic.service_tier",
            ),
            ("container", json!("cont_1"), "anthropic.container"),
            (
                "mcp_servers",
                json!([{"url": "https://x"}]),
                "anthropic.mcp_servers",
            ),
        ] {
            let mut req = json!({
                "model": "claude-3-5-sonnet",
                "messages": [{"role": "user", "content": "hi"}]
            });
            req[key] = value;
            let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
            assert_eq!(hub.lossiness.len(), 1, "{key}: {:?}", hub.lossiness);
            assert_eq!(hub.lossiness[0].field, field, "{key}");
            assert_eq!(
                hub.lossiness[0].direction,
                super::super::LossinessDirection::Unsupported,
                "{key}"
            );
        }
    }

    #[test]
    fn unknown_top_level_key_label_is_sanitized_for_logs() {
        let req_text = r#"{
            "model": "claude-3-5-sonnet",
            "messages": [{"role": "user", "content": "hi"}],
            "we ird\nkey!": 1
        }"#;
        let (hub, _) = fmt().to_hub(req_text.as_bytes()).unwrap();
        assert_eq!(hub.lossiness.len(), 1, "{:?}", hub.lossiness);
        assert_eq!(hub.lossiness[0].field, "anthropic.we_ird_key_");
        assert_eq!(hub.lossiness[0].metric_label, "anthropic.request");
    }

    #[test]
    fn thinking_drop_note_names_the_behavior_change() {
        // Dropping `thinking` is behavior-visible: the client asked for
        // extended thinking and gets none. The note must say what
        // changes, not just that a field was dropped.
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{"role": "user", "content": "hi"}],
            "thinking": {"type": "enabled", "budget_tokens": 2048}
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.lossiness.len(), 1, "{:?}", hub.lossiness);
        let note = &hub.lossiness[0];
        assert_eq!(note.field, "anthropic.thinking");
        assert!(note.note.contains("thinking"), "{}", note.note);
        assert!(
            note.note.contains("without") || note.note.contains("no thinking"),
            "must name the behavior change: {}",
            note.note
        );
    }

    #[test]
    fn null_top_level_fields_are_not_drops() {
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{"role": "user", "content": "hi"}],
            "metadata": null,
            "thinking": null,
            "tool_choice": null
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert!(hub.lossiness.is_empty(), "{:?}", hub.lossiness);
    }

    // --- WOR-2535 fix round: lossy numeric casts (review Minor 1) ---

    #[test]
    fn out_of_range_integer_knobs_are_clamped_with_a_note() {
        // 2^32 + 5 used to truncate to 5 via `as u32`: a huge budget
        // silently became a tiny one.
        for (key, get) in [
            (
                "max_tokens",
                (|hub: &HubRequest| hub.max_tokens) as fn(&HubRequest) -> Option<u32>,
            ),
            ("top_k", |hub: &HubRequest| hub.top_k),
        ] {
            let mut req = json!({
                "model": "claude-3-5-sonnet",
                "messages": [{"role": "user", "content": "hi"}]
            });
            req[key] = json!(4_294_967_301_u64);
            let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
            assert_eq!(get(&hub), Some(u32::MAX), "{key}");
            assert_eq!(hub.lossiness.len(), 1, "{key}: {:?}", hub.lossiness);
            let note = &hub.lossiness[0];
            assert_eq!(note.field, format!("anthropic.{key}"));
            assert_eq!(
                note.direction,
                super::super::LossinessDirection::Downgrade,
                "{key}"
            );
            assert!(note.note.contains("clamp"), "{key}: {}", note.note);
        }
    }

    #[test]
    fn f32_overflowing_float_knobs_are_dropped_with_a_note() {
        for key in ["temperature", "top_p"] {
            let mut req = json!({
                "model": "claude-3-5-sonnet",
                "messages": [{"role": "user", "content": "hi"}]
            });
            req[key] = json!(1e300);
            let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
            let value = match key {
                "temperature" => hub.temperature,
                _ => hub.top_p,
            };
            assert_eq!(value, None, "{key}");
            assert_eq!(hub.lossiness.len(), 1, "{key}: {:?}", hub.lossiness);
            assert_eq!(hub.lossiness[0].field, format!("anthropic.{key}"));
        }
    }

    // --- WOR-2554 decision: image blocks are dropped, never mangled ---

    #[test]
    fn image_block_with_unrecognized_source_is_dropped_with_a_note() {
        // An image whose source yields no string used to be mangled
        // into an empty-source image part; drop-plus-note beats
        // forwarding a part the client never sent.
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "look"},
                    {"type": "image", "source": {"type": "file", "file_id": "f_1"}}
                ]
            }]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.messages.len(), 1);
        assert_eq!(
            hub.messages[0].content.len(),
            1,
            "no empty-source image part: {:?}",
            hub.messages[0].content
        );
        assert_eq!(hub.lossiness.len(), 1, "{:?}", hub.lossiness);
        assert_eq!(hub.lossiness[0].field, "anthropic.messages.content.image");
    }

    #[test]
    fn image_block_with_base64_source_still_parses() {
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "image", "source": {
                        "type": "base64", "media_type": "image/png", "data": "aGk="
                    }}
                ]
            }]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert!(hub.lossiness.is_empty(), "{:?}", hub.lossiness);
        assert!(matches!(
            &hub.messages[0].content[0],
            ContentPart::Image { source, media_type }
                if source == "aGk=" && media_type == "image/png"
        ));
    }

    // --- WOR-2535 fix round: bounded warn + drop counter (Major 2) ---

    #[test]
    fn a_flood_of_unknown_blocks_yields_one_bounded_warn_and_an_accurate_counter() {
        // Red-first: the seam used to emit one warn PER note (a 10k-block
        // body produced 10k warn lines, a client-reachable log flood)
        // while no counter moved.
        use tracing_subscriber::layer::SubscriberExt;

        #[derive(Clone, Default)]
        struct WarnCount {
            fields: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        }
        struct GrabFields<'a>(&'a mut Vec<(String, String)>);
        impl tracing::field::Visit for GrabFields<'_> {
            fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                self.0.push((f.name().to_string(), format!("{v:?}")));
            }
        }
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnCount {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                if *event.metadata().level() != tracing::Level::WARN {
                    return;
                }
                let mut fields = Vec::new();
                event.record(&mut GrabFields(&mut fields));
                let line = fields
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                self.fields.lock().unwrap().push(line);
            }
        }

        let mut blocks = vec![json!({"type": "text", "text": "hi"})];
        for _ in 0..10_000 {
            blocks.push(json!({"type": "mystery_block"}));
        }
        let req = json!({
            "model": "claude-3-5-sonnet",
            "messages": [{"role": "user", "content": blocks}]
        });
        let body = req.to_string();

        let before =
            crate::ai_metrics::translation_dropped_value("messages", "anthropic.messages.content");
        let layer = WarnCount::default();
        let subscriber = tracing_subscriber::registry().with(layer.clone());
        tracing::subscriber::with_default(subscriber, || {
            translate_anthropic_request_to_openai(body.as_bytes(), "test.sbproxy.dev", None)
                .unwrap();
        });
        let after =
            crate::ai_metrics::translation_dropped_value("messages", "anthropic.messages.content");

        let warns = layer.fields.lock().unwrap();
        assert_eq!(
            warns.len(),
            1,
            "one aggregated warn per request, got {}",
            warns.len()
        );
        assert!(warns[0].contains("dropped=10000"), "{}", warns[0]);
        // `>=`, not `==`: this is a process-global counter and
        // `translate_seam_keeps_dropped_blocks_out_of_the_openai_body`
        // writes the same series. Under nextest each test owns its
        // process, but the documented `SBPROXY_ALLOW_CARGO_TEST_FALLBACK=1`
        // path shares one, and a shared-global equality assertion is a
        // flake waiting for that run (WOR-2554 review).
        assert!(
            after - before >= 10_000,
            "every dropped block is counted: {before} -> {after}"
        );
        // One folded write per class, not one per note: the counter
        // value is identical either way, which is exactly why the
        // per-note loop could sit there costing 160,000 limiter round
        // trips on one request without any test noticing.
    }

    // --- WOR-2554 review: wrong-typed represented scalars ---

    #[test]
    fn wrong_typed_represented_scalars_record_lossiness_notes() {
        // Red-first: REPRESENTED_TOP_LEVEL_KEYS is a name list while
        // the parsers key on name AND type, so a float `max_tokens` or
        // a string `stream` read as absent and the catch-all skipped
        // the name. Anthropic's required budget knob vanished with no
        // note, no counter, and no warn.
        for (key, value, metric_label) in [
            ("max_tokens", json!(1024.0), "anthropic.max_tokens"),
            ("top_k", json!("40"), "anthropic.top_k"),
            ("temperature", json!("0.7"), "anthropic.temperature"),
            ("top_p", json!(true), "anthropic.top_p"),
            ("stream", json!("true"), "anthropic.stream"),
            ("model", json!(123), "anthropic.model"),
        ] {
            let mut req = json!({
                "model": "claude-3-5-sonnet",
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": "hi"}]
            });
            req[key] = value.clone();
            let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
            let labels: Vec<&str> = hub
                .lossiness
                .iter()
                .map(|n| n.metric_label.as_str())
                .collect();
            assert!(
                labels.contains(&metric_label),
                "{key}={value} must be noted, got {labels:?}"
            );
        }
    }

    #[test]
    fn a_wrong_typed_stream_flag_does_not_silently_buffer() {
        let req = json!({
            "model": "claude-3-5-sonnet",
            "max_tokens": 16,
            "stream": "true",
            "messages": [{"role": "user", "content": "hi"}]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert!(!hub.stream, "the value is still unreadable");
        assert!(
            hub.lossiness
                .iter()
                .any(|n| n.note.contains("SSE stream it asked for")),
            "{:?}",
            hub.lossiness
        );
    }

    // --- WOR-2554 review: attributes on blocks the parser KEEPS ---

    #[test]
    fn cache_control_on_a_kept_text_block_records_a_lossiness_note() {
        // Red-first: the "no part pushed" detector only fires when a
        // block yields nothing. A text block with `cache_control`
        // yields a part, so prompt caching never engaged and the
        // customer paid full input price every turn, silently.
        let req = json!({
            "model": "claude-3-5-sonnet",
            "max_tokens": 16,
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "long context", "cache_control": {"type": "ephemeral"}}
            ]}]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.messages[0].content.len(), 1, "the text is still kept");
        let note = hub
            .lossiness
            .iter()
            .find(|n| n.field.ends_with("text.cache_control"))
            .unwrap_or_else(|| panic!("expected a cache_control note, got {:?}", hub.lossiness));
        assert_eq!(note.metric_label, "anthropic.messages.content");
    }

    #[test]
    fn citations_on_a_kept_text_block_record_a_lossiness_note() {
        let req = json!({
            "model": "claude-3-5-sonnet",
            "max_tokens": 16,
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "cited", "citations": [{"type": "char_location"}]}
            ]}]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert!(
            hub.lossiness
                .iter()
                .any(|n| n.field.ends_with("text.citations")),
            "{:?}",
            hub.lossiness
        );
    }

    #[test]
    fn non_string_identifiers_on_kept_blocks_record_lossiness_notes() {
        let req = json!({
            "model": "claude-3-5-sonnet",
            "max_tokens": 16,
            "messages": [{"role": "assistant", "content": [
                {"type": "tool_use", "id": 7, "name": {"a": 1}, "input": {}}
            ]}]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        let fields: Vec<&str> = hub.lossiness.iter().map(|n| n.field.as_str()).collect();
        assert!(
            fields.contains(&"anthropic.messages.content.tool_use.id")
                && fields.contains(&"anthropic.messages.content.tool_use.name"),
            "{fields:?}"
        );
    }

    #[test]
    fn a_clean_block_notes_nothing() {
        let req = json!({
            "model": "claude-3-5-sonnet",
            "max_tokens": 16,
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "hi"}]},
                {"role": "assistant", "content": [
                    {"type": "tool_use", "id": "t1", "name": "f", "input": {"x": 1}}
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "t1", "content": "ok", "is_error": false}
                ]}
            ]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert!(hub.lossiness.is_empty(), "{:?}", hub.lossiness);
    }

    #[test]
    fn an_anthropic_server_tool_is_dropped_with_a_note_not_mangled() {
        // Red-first: a server tool carries no `input_schema`, so it
        // used to reach the provider as
        // {"type":"function","function":{"name":"web_search","description":"","parameters":null}},
        // a mangle rather than a drop, with no note.
        let req = json!({
            "model": "claude-3-5-sonnet",
            "max_tokens": 16,
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [
                {"type": "web_search_20250305", "name": "web_search", "max_uses": 5},
                {"name": "get_weather", "input_schema": {"type": "object"}}
            ]
        });
        let (hub, _) = fmt().to_hub(req.to_string().as_bytes()).unwrap();
        assert_eq!(hub.tools.len(), 1, "only the client tool survives");
        assert_eq!(hub.tools[0].name, "get_weather");
        let note = hub
            .lossiness
            .iter()
            .find(|n| n.field == "anthropic.tools.web_search_20250305")
            .unwrap_or_else(|| panic!("expected a server-tool note, got {:?}", hub.lossiness));
        assert_eq!(note.metric_label, "anthropic.tools");
    }
}
