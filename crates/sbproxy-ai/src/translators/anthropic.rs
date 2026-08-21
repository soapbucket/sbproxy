//! OpenAI ⇄ Anthropic Messages API translator.
//!
//! Maps the OpenAI chat-completions shape to and from Anthropic's
//! Messages API. Covers the fields most clients use: messages,
//! system prompt, model, temperature, top_p, top_k, max_tokens,
//! stop sequences, stream, and tool calls.
//!
//! This module owns non-streaming request/response JSON translation.
//! Streaming responses are handled by the native stream translator in
//! `format::native_streams`, which parses Anthropic SSE frames into
//! the shared hub stream before the inbound route re-emits them.

use serde_json::{json, Map, Value};

use crate::format::{note_drop, report_translation_lossiness, LossinessNote};

/// Surface label for the provider leg of translation.
///
/// The lossiness counter's other call sites are inbound seams and pass
/// an `AiSurface::label`. This leg runs after the inbound seam, on the
/// canonical body, so it deliberately uses a value no inbound surface
/// can produce: a drop-rate panel that divides by
/// `sbproxy_ai_surface_requests_total` keeps every existing row exact
/// and gains one clearly-named row for the provider translation.
const LOSSINESS_SURFACE: &str = "anthropic_translator";

/// Convert an OpenAI request body to Anthropic Messages API shape.
///
/// Differences handled:
///   * The OpenAI `system` role, and `developer` which is OpenAI's
///     rename of it, are hoisted to a top-level `system` field.
///     Anthropic allows neither in the messages list. A system turn
///     whose content is a block array contributes its text blocks,
///     rather than vanishing.
///   * `max_tokens` is required by Anthropic; we default to 1024 when
///     the OpenAI client omitted it.
///   * `messages` array shape stays compatible (role + content) for
///     plain-text turns. Multimodal `content: [...]` arrays pass
///     through unchanged.
///   * A `role: "tool"` turn becomes a `user` turn carrying one
///     `tool_result` block, and an assistant turn's `tool_calls`
///     become `tool_use` content blocks. Anthropic has no `tool` role
///     and no top-level `tool_calls` key, so a multi-turn tool
///     conversation used to reach the provider as a 400.
///   * `tools` are rewritten from the OpenAI `{"type": "function",
///     "function": {name, description, parameters}}` shape into
///     Anthropic's `{name, description, input_schema}`.
///   * The path is rewritten from `/v1/chat/completions` to
///     `/v1/messages`.
///   * `tool_choice` is rewritten from the OpenAI spelling
///     (`"none"` / `"auto"` / `"required"` / `{"type": "function",
///     "function": {"name": ...}}`) into Anthropic's object form
///     (`{"type": "none" | "auto" | "any" | "tool"}`). Anthropic
///     rejects a bare string with a 400, so forwarding the canonical
///     value verbatim broke every forced-tool request.
///   * `user` becomes Anthropic's `metadata.user_id`, which is the
///     field that carries the same end-user attribution.
///   * Unsupported OpenAI knobs (`logit_bias`, `n`,
///     `presence_penalty`, `frequency_penalty`, `response_format`,
///     `seed`) are dropped, because Anthropic answers an unrecognized
///     argument with a 400. Every one of those drops records a
///     lossiness note, so the request that lost a field is counted and
///     logged rather than silently degraded. Unknown extensions pass
///     through.
pub fn request_to_native(body: Value, path: &str) -> (Value, String) {
    let mut obj: Map<String, Value> = match body {
        Value::Object(m) => m,
        other => return (other, path.to_string()),
    };
    let mut lossiness: Vec<LossinessNote> = Vec::new();

    // 1. One walk over `messages`: hoist the instruction turns into the
    //    top-level `system` field Anthropic wants, and reshape every
    //    remaining turn into Anthropic's message form. A body whose
    //    `messages` is not an array goes back untouched, so a malformed
    //    request reaches the provider as the provider's error rather
    //    than losing its messages here.
    let mut system_chunks: Vec<String> = Vec::new();
    match obj.remove("messages") {
        Some(Value::Array(messages)) => {
            let mut kept: Vec<Value> = Vec::with_capacity(messages.len());
            for m in messages {
                if is_instruction_role(&m) {
                    match message_text(&m) {
                        Some(text) => system_chunks.push(text),
                        None => note_drop(
                            &mut lossiness,
                            "anthropic.request.system",
                            "anthropic.request.system".into(),
                            "a system turn carrying no text was dropped: Anthropic's \
                             top-level system field is text only, so the model is \
                             answering without those instructions"
                                .into(),
                        ),
                    }
                    continue;
                }
                kept.push(message_to_anthropic(&m));
            }
            obj.insert("messages".to_string(), Value::Array(kept));
        }
        Some(other) => {
            obj.insert("messages".to_string(), other);
        }
        None => {}
    }
    if !system_chunks.is_empty() {
        obj.insert(
            "system".to_string(),
            Value::String(system_chunks.join("\n\n")),
        );
    }

    // 2. Anthropic requires max_tokens. OpenAI defaults it server
    //    side; we pick a conservative default so requests don't get
    //    rejected.
    obj.entry("max_tokens".to_string())
        .or_insert(Value::Number(1024.into()));

    // 3. Rewrite tool_choice into Anthropic's object form. The
    //    canonical body carries the OpenAI spelling, and Anthropic's
    //    `/v1/messages` requires an object: a bare `"required"` or
    //    `"none"` is a 400 `invalid_request_error`, and the nested
    //    `{"type": "function", "function": {"name": ...}}` shape is
    //    not one Anthropic recognizes either.
    if let Some(choice) = obj.remove("tool_choice") {
        match anthropic_tool_choice(&choice) {
            NativeToolChoice::Native(native) => {
                obj.insert("tool_choice".to_string(), native);
            }
            NativeToolChoice::OmitAsDefault => {}
            NativeToolChoice::Unrepresentable => note_drop(
                &mut lossiness,
                "anthropic.request.tool_choice",
                "anthropic.request.tool_choice".into(),
                "tool_choice dropped: the shape has no Anthropic equivalent, so \
                 the model chooses tools as if it were 'auto'"
                    .into(),
            ),
        }
    }

    // 4. Rewrite tool definitions. Anthropic takes a flat
    //    `{name, description, input_schema}`, not OpenAI's nested
    //    `function` object, and rejects the nested form with a 400
    //    that no tool_choice rewrite can rescue.
    match obj.remove("tools") {
        Some(Value::Array(tools)) => {
            let converted = anthropic_tools(tools, &mut lossiness);
            if !converted.is_empty() {
                obj.insert("tools".to_string(), Value::Array(converted));
            }
        }
        // Not an array: relay it and let the provider name the error,
        // rather than deleting a field the client did send.
        Some(other) => {
            obj.insert("tools".to_string(), other);
        }
        None => {}
    }

    // 5. `user` is end-user attribution, and Anthropic carries the same
    //    thing under `metadata.user_id`. Map it rather than drop it,
    //    but never overwrite a metadata object the body already has.
    if let Some(user) = obj.remove("user") {
        match user.as_str() {
            Some(id) if !obj.contains_key("metadata") => {
                obj.insert("metadata".to_string(), json!({"user_id": id}));
            }
            _ => note_drop(
                &mut lossiness,
                "anthropic.request.user",
                "anthropic.request.user".into(),
                "user dropped: the provider sees the request without its \
                 end-user attribution"
                    .into(),
            ),
        }
    }

    // 6. Drop OpenAI-only knobs Anthropic rejects with 400. Each one
    //    changes what the model does, so each one is a note.
    for (key, effect) in DROPPED_OPENAI_KNOBS {
        let Some(value) = obj.remove(*key) else {
            continue;
        };
        if value.is_null() {
            continue;
        }
        // `n: 1` is the OpenAI default and asks for exactly what
        // Anthropic already returns, so removing it loses nothing.
        if *key == "n" && value.as_u64() == Some(1) {
            continue;
        }
        note_drop(
            &mut lossiness,
            "anthropic.request.knob",
            format!("anthropic.request.{key}"),
            format!("{key} dropped: Anthropic has no equivalent, so {effect}"),
        );
    }

    // 7. Path rewrite. Translator only supports chat completions and
    //    its native equivalent today.
    let new_path = if path.ends_with("/chat/completions") {
        path.trim_end_matches("/chat/completions")
            .trim_end_matches('/')
            .to_string()
            + "/messages"
    } else {
        path.to_string()
    };

    report_translation_lossiness(LOSSINESS_SURFACE, "", None, &lossiness);
    (Value::Object(obj), new_path)
}

/// OpenAI request knobs Anthropic answers with a 400, paired with what
/// the operator loses when the translator strips them. The sentence
/// fragment completes "`{key}` dropped: Anthropic has no equivalent, so
/// ...".
const DROPPED_OPENAI_KNOBS: &[(&str, &str)] = &[
    (
        "logit_bias",
        "the requested token biases are not applied to sampling",
    ),
    ("n", "the response carries one completion, not several"),
    (
        "presence_penalty",
        "sampling runs without the requested repetition penalty",
    ),
    (
        "frequency_penalty",
        "sampling runs without the requested frequency penalty",
    ),
    (
        "response_format",
        "the reply is free text rather than the requested structured shape",
    ),
    ("seed", "repeated identical requests are not reproducible"),
];

/// Whether a turn is an instruction turn that belongs in Anthropic's
/// top-level `system` field rather than in `messages`.
///
/// `developer` is OpenAI's own rename of `system` and carries exactly
/// the same meaning, so it hoists the same way. Left in `messages` it
/// is a 400: Anthropic's roles are `user` and `assistant`, and nothing
/// else.
fn is_instruction_role(m: &Value) -> bool {
    matches!(
        m.get("role").and_then(Value::as_str),
        Some("system" | "developer")
    )
}

/// Flatten a message's content down to text, for the one place
/// Anthropic takes a bare string: the top-level `system` field and a
/// `tool_result` body. A block array contributes its `text` blocks;
/// anything with no text at all yields `None` so the caller can note
/// the loss rather than send an empty string.
fn message_text(m: &Value) -> Option<String> {
    match m.get("content") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Array(parts)) => {
            let text: Vec<&str> = parts
                .iter()
                .filter_map(|p| p.get("text").and_then(Value::as_str))
                .collect();
            (!text.is_empty()).then(|| text.join(""))
        }
        _ => None,
    }
}

/// Reshape one non-instruction turn into Anthropic's message form.
///
/// Two turns need reshaping and everything else is forwarded as it
/// stands, which keeps plain-text and multimodal turns byte-identical
/// to what the client sent:
///   * `role: "tool"` has no Anthropic counterpart. It becomes a
///     `user` turn holding a single `tool_result` block keyed by the
///     `tool_call_id` the assistant's matching `tool_use` block
///     carries.
///   * An assistant turn's `tool_calls` are a top-level OpenAI key
///     with no Anthropic counterpart either; they become `tool_use`
///     content blocks alongside whatever text the turn had. Every
///     other key on that turn is kept, so the reshape adds no drop
///     the pass-through branch would not also have.
fn message_to_anthropic(m: &Value) -> Value {
    let role = m.get("role").and_then(Value::as_str).unwrap_or("user");

    if role == "tool" {
        let tool_use_id = m
            .get("tool_call_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        return json!({
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": tool_use_id,
                "content": message_text(m).unwrap_or_default(),
            }],
        });
    }

    let Some(Value::Array(tool_calls)) = m.get("tool_calls") else {
        return m.clone();
    };

    let mut blocks: Vec<Value> = Vec::with_capacity(tool_calls.len() + 1);
    match m.get("content") {
        Some(Value::String(s)) if !s.is_empty() => {
            blocks.push(json!({"type": "text", "text": s}));
        }
        Some(Value::Array(parts)) => blocks.extend(parts.iter().cloned()),
        _ => {}
    }
    for call in tool_calls {
        let function = call.get("function");
        let arguments = function
            .and_then(|f| f.get("arguments"))
            .and_then(Value::as_str)
            .unwrap_or("{}");
        blocks.push(json!({
            "type": "tool_use",
            "id": call.get("id").and_then(Value::as_str).unwrap_or_default(),
            "name": function
                .and_then(|f| f.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default(),
            // Anthropic's `input` is an object. An unparsable argument
            // string becomes an empty one rather than a null the
            // provider rejects.
            "input": serde_json::from_str::<Value>(arguments)
                .ok()
                .filter(Value::is_object)
                .unwrap_or_else(|| json!({})),
        }));
    }
    // Keep every other key the turn had. `tool_calls` folded into
    // `content` and is gone; anything else (`name`, `refusal`, a
    // client extension) is forwarded exactly as it is on a turn
    // without tool calls, so this branch introduces no drop of its
    // own.
    let mut out: Map<String, Value> = match m {
        Value::Object(fields) => fields.clone(),
        _ => Map::new(),
    };
    out.remove("tool_calls");
    out.insert("content".to_string(), Value::Array(blocks));
    Value::Object(out)
}

/// Rewrite OpenAI tool definitions into Anthropic's flat shape.
///
/// A definition already carrying `input_schema` is Anthropic's own and
/// passes through, so a `/v1/messages` client whose body took the hub
/// round trip and one that skipped it send the same tools upstream. A
/// definition with no usable name is dropped with a note: Anthropic
/// refuses the whole request over one malformed entry, and losing one
/// tool is a smaller failure than losing the call.
fn anthropic_tools(tools: Vec<Value>, lossiness: &mut Vec<LossinessNote>) -> Vec<Value> {
    let mut converted = Vec::with_capacity(tools.len());
    for tool in tools {
        if tool.get("input_schema").is_some() {
            converted.push(tool);
            continue;
        }
        let name = tool
            .get("function")
            .and_then(|f| f.get("name"))
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty());
        let (Some(name), Some(function)) = (name, tool.get("function")) else {
            note_drop(
                lossiness,
                "anthropic.request.tools",
                "anthropic.request.tools".into(),
                "a tool definition with no function name was dropped: the model \
                 cannot call it, and forwarding it would fail the whole request"
                    .into(),
            );
            continue;
        };
        let mut spec = Map::new();
        spec.insert("name".to_string(), Value::String(name.to_string()));
        if let Some(description) = function.get("description") {
            spec.insert("description".to_string(), description.clone());
        }
        spec.insert(
            "input_schema".to_string(),
            function
                .get("parameters")
                .cloned()
                .unwrap_or_else(|| json!({"type": "object", "properties": {}})),
        );
        converted.push(Value::Object(spec));
    }
    converted
}

/// What an OpenAI `tool_choice` becomes on the Anthropic wire.
enum NativeToolChoice {
    /// Anthropic's equivalent object.
    Native(Value),
    /// Send nothing: `auto` is Anthropic's default when tools are
    /// offered, so omitting the field produces the same request.
    OmitAsDefault,
    /// No Anthropic equivalent. Forwarding it is a 400, so it is
    /// dropped, and the drop is a real change in behavior.
    Unrepresentable,
}

/// Map an OpenAI-shaped `tool_choice` onto Anthropic's object form.
///
/// Anthropic's own object form passes through unchanged so a
/// `/v1/messages` client on an Anthropic upstream that skips the hub
/// round trip and one that takes it produce the same upstream body.
fn anthropic_tool_choice(choice: &Value) -> NativeToolChoice {
    if let Some(s) = choice.as_str() {
        return match s {
            "none" => NativeToolChoice::Native(json!({"type": "none"})),
            "required" => NativeToolChoice::Native(json!({"type": "any"})),
            "auto" => NativeToolChoice::OmitAsDefault,
            _ => NativeToolChoice::Unrepresentable,
        };
    }
    let Some(obj) = choice.as_object() else {
        return NativeToolChoice::Unrepresentable;
    };
    let named = |name: Option<&str>| match name {
        Some(name) => NativeToolChoice::Native(json!({"type": "tool", "name": name})),
        None => NativeToolChoice::Unrepresentable,
    };
    match obj.get("type").and_then(Value::as_str) {
        // Already Anthropic-shaped (a native body that reached this
        // translator without a hub round trip).
        Some("auto") => NativeToolChoice::OmitAsDefault,
        Some("any") => NativeToolChoice::Native(json!({"type": "any"})),
        Some("none") => NativeToolChoice::Native(json!({"type": "none"})),
        Some("tool") => named(obj.get("name").and_then(Value::as_str)),
        Some("function") => named(
            obj.get("function")
                .and_then(|f| f.get("name"))
                .and_then(Value::as_str),
        ),
        _ => NativeToolChoice::Unrepresentable,
    }
}

/// Convert an Anthropic Messages API response back to the OpenAI
/// chat-completions shape so OpenAI SDK clients can parse it.
///
/// Field map:
///   * Anthropic `content: [{type: "text", text}, ...]` →
///     OpenAI `choices[0].message.content` (concatenated text blocks).
///     Tool-use blocks become `tool_calls` on the message.
///   * Anthropic `thinking` blocks → `message.reasoning_content`, the
///     field the rest of this crate already reads for a reasoning
///     model's visible thoughts. Without it an extended-thinking reply
///     that spent its whole budget thinking reached the client as an
///     empty message with no explanation.
///   * Anthropic `stop_reason` → OpenAI `finish_reason`
///     (`end_turn` → `stop`, `max_tokens` → `length`,
///     `tool_use` → `tool_calls`, others pass through).
///   * Anthropic `usage.input_tokens` / `output_tokens` →
///     OpenAI `usage.prompt_tokens` / `completion_tokens`.
///   * `model` and `id` pass through.
///
/// Content blocks with no OpenAI counterpart are still dropped:
/// `redacted_thinking` (an opaque blob only Anthropic can read back),
/// `server_tool_use`, `web_search_tool_result`, and any block type a
/// later API version adds. Anthropic's cache-read and cache-creation
/// token counts are likewise not folded into `usage`; the gateway's own
/// accounting reads them off the raw upstream body instead.
pub fn response_to_openai(body: Value) -> Value {
    let m = match body {
        Value::Object(m) => m,
        other => return other,
    };

    let id = m.get("id").cloned().unwrap_or(Value::Null);
    let model = m.get("model").cloned().unwrap_or(Value::Null);

    let (content_text, tool_calls, reasoning) = extract_content_and_tools(&m);

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
    if let Some(obj) = message.as_object_mut() {
        if !tool_calls.is_empty() {
            obj.insert("tool_calls".to_string(), Value::Array(tool_calls));
        }
        if !reasoning.is_empty() {
            obj.insert("reasoning_content".to_string(), Value::String(reasoning));
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

/// Split an Anthropic response's content blocks into the OpenAI
/// message's `content`, its `tool_calls`, and its `reasoning_content`.
fn extract_content_and_tools(m: &Map<String, Value>) -> (Value, Vec<Value>, String) {
    let blocks = match m.get("content") {
        Some(Value::Array(a)) => a,
        Some(other) => return (other.clone(), Vec::new(), String::new()),
        None => return (Value::String(String::new()), Vec::new(), String::new()),
    };
    let mut texts: Vec<String> = Vec::new();
    let mut thoughts: Vec<String> = Vec::new();
    let mut tool_calls: Vec<Value> = Vec::new();
    for block in blocks {
        let ty = block.get("type").and_then(|s| s.as_str()).unwrap_or("");
        match ty {
            "text" => {
                if let Some(t) = block.get("text").and_then(|s| s.as_str()) {
                    texts.push(t.to_string());
                }
            }
            // Extended thinking. The block's `signature` is Anthropic's
            // own integrity token for a turn replayed back to it, and
            // the OpenAI shape has nowhere to put it, so only the text
            // crosses over.
            "thinking" => {
                if let Some(t) = block.get("thinking").and_then(|s| s.as_str()) {
                    thoughts.push(t.to_string());
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
    (Value::String(texts.join("")), tool_calls, thoughts.join(""))
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

    /// The only test in this module that reads the
    /// `anthropic.request.knob` counter, deliberately: the counter is
    /// process-global, so a second test asserting a delta on the same
    /// label pair would race this one under a threaded runner.
    #[test]
    fn request_drops_openai_only_fields_and_counts_each_one() {
        let count = || {
            crate::ai_metrics::translation_dropped_value(
                LOSSINESS_SURFACE,
                "anthropic.request.knob",
            )
        };

        let before = count();
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
        assert_eq!(
            count() - before,
            6,
            "each knob Anthropic cannot honor is one note; `user` is mapped \
             onto metadata rather than dropped, so it is not one"
        );

        // A null and the OpenAI default change nothing when removed, so
        // neither is a drop worth reporting.
        let before = count();
        let (out, _) = request_to_native(
            json!({
                "messages": [{"role": "user", "content": "hi"}],
                "logit_bias": null,
                "n": 1,
            }),
            "/v1/chat/completions",
        );
        let obj = out.as_object().unwrap();
        assert!(!obj.contains_key("logit_bias") && !obj.contains_key("n"));
        assert_eq!(count(), before, "nothing was lost, so nothing is counted");
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

    /// The whole request-direction tool surface, in one body, because
    /// Anthropic refuses a `tool_result` whose `tool_use_id` has no
    /// matching `tool_use` in the turn before it. Fixing any one of the
    /// three in isolation trades one 400 for another.
    fn tool_conversation() -> Value {
        json!({
            "model": "claude-3-5-sonnet",
            "messages": [
                {"role": "user", "content": "weather in SF?"},
                {
                    "role": "assistant",
                    "content": "let me look",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "get_weather", "arguments": "{\"city\":\"SF\"}"},
                    }],
                },
                {"role": "tool", "tool_call_id": "call_1", "content": "72F"},
            ],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "current weather",
                    "parameters": {"type": "object", "properties": {"city": {"type": "string"}}},
                },
            }],
        })
    }

    #[test]
    fn request_converts_tool_role_to_tool_result_block() {
        let (out, _) = request_to_native(tool_conversation(), "/v1/chat/completions");
        let result = &out["messages"][2];
        assert_eq!(result["role"], "user", "Anthropic has no tool role: {out}");
        assert_eq!(result["content"][0]["type"], "tool_result");
        assert_eq!(result["content"][0]["tool_use_id"], "call_1");
        assert_eq!(result["content"][0]["content"], "72F");
        assert!(
            result.get("tool_call_id").is_none(),
            "tool_call_id belongs in the block, not on the turn: {out}"
        );
    }

    #[test]
    fn request_converts_assistant_tool_calls_to_tool_use_blocks() {
        let (out, _) = request_to_native(tool_conversation(), "/v1/chat/completions");
        let assistant = &out["messages"][1];
        assert!(
            assistant.get("tool_calls").is_none(),
            "Anthropic has no top-level tool_calls key: {out}"
        );
        let blocks = assistant["content"].as_array().expect("block array");
        assert_eq!(blocks[0], json!({"type": "text", "text": "let me look"}));
        assert_eq!(blocks[1]["type"], "tool_use");
        assert_eq!(blocks[1]["id"], "call_1");
        assert_eq!(blocks[1]["name"], "get_weather");
        assert_eq!(
            blocks[1]["input"],
            json!({"city": "SF"}),
            "the arguments string is parsed into an object"
        );
    }

    #[test]
    fn request_converts_tools_to_input_schema() {
        let (out, _) = request_to_native(tool_conversation(), "/v1/chat/completions");
        let tools = out["tools"].as_array().expect("tools survive");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "get_weather");
        assert_eq!(tools[0]["description"], "current weather");
        assert_eq!(
            tools[0]["input_schema"]["properties"]["city"]["type"],
            "string"
        );
        assert!(
            tools[0].get("function").is_none() && tools[0].get("type").is_none(),
            "the OpenAI nesting is gone: {out}"
        );
    }

    #[test]
    fn request_defaults_a_missing_tool_parameter_schema() {
        let body = json!({
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [
                {"type": "function", "function": {"name": "ping"}},
                // Already Anthropic-shaped, because the body reached
                // this translator without a hub round trip. Converting
                // it again would strip the schema it already carries.
                {"name": "pong", "input_schema": {"type": "object", "required": ["x"]}},
            ],
        });
        let (out, _) = request_to_native(body, "/v1/chat/completions");
        assert_eq!(
            out["tools"][0]["input_schema"],
            json!({"type": "object", "properties": {}}),
            "Anthropic requires input_schema on every tool"
        );
        assert_eq!(
            out["tools"][1],
            json!({"name": "pong", "input_schema": {"type": "object", "required": ["x"]}}),
            "an Anthropic-shaped definition passes through untouched"
        );
    }

    #[test]
    fn request_hoists_a_system_turn_with_block_content() {
        let body = json!({
            "messages": [
                {"role": "system", "content": [
                    {"type": "text", "text": "be terse"},
                    {"type": "text", "text": " and kind"},
                ]},
                {"role": "user", "content": "hi"},
            ],
        });
        let (out, _) = request_to_native(body, "/v1/chat/completions");
        assert_eq!(
            out["system"], "be terse and kind",
            "block-shaped system content used to vanish and leave the turn \
             in messages, which Anthropic rejects: {out}"
        );
        let msgs = out["messages"].as_array().expect("messages");
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0]["role"], "user");
    }

    #[test]
    fn request_hoists_a_developer_turn_like_a_system_turn() {
        let body = json!({
            "messages": [
                {"role": "developer", "content": "answer in english"},
                {"role": "system", "content": "be terse"},
                {"role": "user", "content": "hi"},
            ],
        });
        let (out, _) = request_to_native(body, "/v1/chat/completions");
        assert_eq!(
            out["system"], "answer in english\n\nbe terse",
            "developer is OpenAI's rename of system and hoists the same way: {out}"
        );
        let msgs = out["messages"].as_array().expect("messages");
        assert_eq!(
            msgs.len(),
            1,
            "neither instruction turn is left behind: {out}"
        );
        assert_eq!(msgs[0]["role"], "user");
    }

    #[test]
    fn request_relays_a_messages_field_that_is_not_an_array() {
        // The message walk takes `messages` out of the map to rebuild
        // it. A body the walk cannot handle has to get its field back,
        // or the translator turns a client's malformed request into a
        // different, emptier one.
        let body = json!({"model": "claude-3-5-sonnet", "messages": "oops"});
        let (out, _) = request_to_native(body, "/v1/chat/completions");
        assert_eq!(out["messages"], "oops");
    }

    #[test]
    fn request_maps_user_onto_anthropic_metadata() {
        let body = json!({
            "messages": [{"role": "user", "content": "hi"}],
            "user": "u-1",
        });
        let (out, _) = request_to_native(body, "/v1/chat/completions");
        assert!(out.get("user").is_none(), "the OpenAI spelling is gone");
        assert_eq!(out["metadata"]["user_id"], "u-1");
    }

    #[test]
    fn request_leaves_a_plain_turn_untouched() {
        let body = json!({
            "messages": [
                {"role": "user", "content": [
                    {"type": "text", "text": "what is this"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}},
                ]},
            ],
        });
        let (out, _) = request_to_native(body.clone(), "/v1/chat/completions");
        assert_eq!(
            out["messages"][0], body["messages"][0],
            "a multimodal turn passes through byte for byte"
        );
    }

    /// Both tool_choice outcomes in one test body, deliberately: the
    /// counter is process-global, so two tests reading the same label
    /// pair could race under a threaded runner.
    #[test]
    fn an_unrepresentable_tool_choice_is_counted_and_auto_is_not() {
        let count = || {
            crate::ai_metrics::translation_dropped_value(
                LOSSINESS_SURFACE,
                "anthropic.request.tool_choice",
            )
        };

        let before = count();
        let (out, _) = request_to_native(
            json!({
                "messages": [{"role": "user", "content": "hi"}],
                "tool_choice": {"type": "allowed_tools", "tools": ["a"]},
            }),
            "/v1/chat/completions",
        );
        assert!(
            out.get("tool_choice").is_none(),
            "a shape Anthropic does not know is a 400 if forwarded: {out}"
        );
        assert_eq!(
            count() - before,
            1,
            "dropping it changes which tools the model may call, so it counts"
        );

        let before = count();
        let (out, _) = request_to_native(
            json!({
                "messages": [{"role": "user", "content": "hi"}],
                "tool_choice": "auto",
            }),
            "/v1/chat/completions",
        );
        assert!(
            out.get("tool_choice").is_none(),
            "auto is Anthropic's default and needs no field"
        );
        assert_eq!(
            count(),
            before,
            "omitting a field that changes nothing is not lossiness"
        );
    }

    #[test]
    fn response_surfaces_thinking_as_reasoning_content() {
        let body = json!({
            "content": [
                {"type": "thinking", "thinking": "the user wants SF weather", "signature": "sig"},
                {"type": "text", "text": "It is 72F."},
            ],
            "stop_reason": "end_turn",
        });
        let out = response_to_openai(body);
        let message = &out["choices"][0]["message"];
        assert_eq!(message["content"], "It is 72F.");
        assert_eq!(message["reasoning_content"], "the user wants SF weather");

        // A reply with no thinking blocks must not grow an empty field.
        let plain = response_to_openai(json!({
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "end_turn",
        }));
        assert!(plain["choices"][0]["message"]
            .get("reasoning_content")
            .is_none());
    }

    #[test]
    fn round_trip_of_a_tool_call_survives_both_directions() {
        // What the response direction emits for a tool call has to be
        // what the request direction accepts on the next turn, or a
        // client replaying the conversation loses the call.
        let raw = json!({
            "id": "msg_1",
            "content": [{
                "type": "tool_use",
                "id": "toolu_1",
                "name": "get_weather",
                "input": {"city": "SF"},
            }],
            "stop_reason": "tool_use",
        });
        let openai = response_to_openai(raw);
        let assistant = openai["choices"][0]["message"].clone();
        let next = json!({
            "messages": [
                {"role": "user", "content": "weather?"},
                assistant,
                {"role": "tool", "tool_call_id": "toolu_1", "content": "72F"},
            ],
        });
        let (out, _) = request_to_native(next, "/v1/chat/completions");
        assert_eq!(out["messages"][1]["content"][0]["type"], "tool_use");
        assert_eq!(out["messages"][1]["content"][0]["id"], "toolu_1");
        assert_eq!(
            out["messages"][1]["content"][0]["input"],
            json!({"city": "SF"})
        );
        assert_eq!(out["messages"][2]["content"][0]["tool_use_id"], "toolu_1");
    }
}
