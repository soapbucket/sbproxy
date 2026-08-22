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
//! SigV4 request signing is handled at the HTTP transport layer, by
//! `crate::aws_sigv4` at the `client::send_governed` transport boundary,
//! and it is not part of the JSON body translation contract this module
//! owns. The dependency runs the other way and is load bearing: a SigV4
//! signature covers a SHA-256 of the request body, so the body this
//! module produces is the body that gets hashed. Anything that mutates
//! a Bedrock request after translation has to do it above the signing
//! boundary, or the signature will not match what is sent and the
//! failure will arrive as a 403 that reads like a permissions problem.

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
///   * `guardrail`, when set, becomes the Converse `guardrailConfig`
///     block. It has no OpenAI counterpart: it comes from the
///     provider entry's `bedrock_guardrail`, not from the caller's
///     body, and a caller-supplied `guardrailConfig` is never honored
///     because the canonical body is OpenAI-shaped and has no such
///     field to carry one.
pub fn request_to_native(
    body: Value,
    path: &str,
    guardrail: Option<&crate::provider::BedrockGuardrailPassthrough>,
) -> (Value, String) {
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
    // Converse exposes model-specific controls through this escape hatch.
    // Preserve fields installed by per-attempt reasoning policy selection.
    if let Some(fields) = obj.get("additionalModelRequestFields") {
        out.insert("additionalModelRequestFields".to_string(), fields.clone());
    }

    // 2b. Inline guardrail. Converse evaluates the prompt and the
    // completion inside this same call when `guardrailConfig` is
    // present, so nothing downstream has to make a second AWS request.
    // `trace: "enabled"` is what makes `trace.guardrail` come back on
    // the response; without it an intervention arrives as a bare
    // `stopReason` with no policy names to report.
    if let Some(guardrail) = guardrail {
        out.insert(
            "guardrailConfig".to_string(),
            json!({
                "guardrailIdentifier": guardrail.identifier,
                "guardrailVersion": guardrail.version,
                "trace": if guardrail.trace { "enabled" } else { "disabled" },
            }),
        );
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

/// Guardrail name recorded when an inline Converse guardrail
/// intervenes. Distinct from the `bedrock` name an out-of-band
/// `ApplyGuardrail` external guardrail records, so an operator reading
/// a decision record can tell which layer stopped the request.
pub const INLINE_GUARDRAIL_NAME: &str = "bedrock_guardrail";

/// Most policies this module will name in a block reason. The reason
/// reaches the caller's 403 envelope, `ctx.deny_reason`, and the
/// decision audit record, so the count is bounded even though every
/// component of it is already an enum value or an operator-authored
/// name.
///
/// This caps the number of names, not the byte length. Each name is
/// either a closed AWS enum value or a topic or regex name the
/// operator wrote in their own AWS guardrail, so the length is bounded
/// by the operator's own config rather than by anything a caller
/// sends.
const MAX_REASON_POLICIES: usize = 8;

/// Detect an inline Converse guardrail intervention on a 2xx Bedrock
/// response body.
///
/// Bedrock does not answer a guardrail block with an error status: the
/// Converse call returns 200 with `stopReason: "guardrail_intervened"`
/// and, when the request asked for `trace: "enabled"`, a
/// `trace.guardrail` assessment describing which policies fired. Both
/// halves are read here, before `response_to_openai` rebuilds the body
/// from a fresh object and drops `trace` entirely.
///
/// **The returned reason never carries caller content.** A Bedrock
/// assessment reports the matched span for a custom word
/// (`wordPolicy.customWords[].match`) and for a PII entity
/// (`sensitiveInformationPolicy.piiEntities[].match`), and both of
/// those are the caller's own prompt or the model's own completion.
/// Only policy *types* and operator-authored *names* are summarized,
/// and only up to [`MAX_REASON_POLICIES`] of them.
///
/// **What this cannot see.** Streaming responses: a `ConverseStream`
/// intervention arrives as a stream event, not as this body, and is
/// mapped to a `content_filter` finish reason by
/// `format::native_streams` without reaching here. A response whose
/// request did not set `trace: enabled` yields a block with no policy
/// names, because Bedrock sends none.
pub fn guardrail_intervention(body: &[u8]) -> Option<crate::guardrails::GuardrailBlock> {
    let parsed: Value = serde_json::from_slice(body).ok()?;
    if parsed.get("stopReason").and_then(|v| v.as_str()) != Some("guardrail_intervened") {
        return None;
    }
    let guardrail_trace = parsed.get("trace").and_then(|t| t.get("guardrail"));
    let mut input_policies = Vec::new();
    let mut output_policies = Vec::new();
    if let Some(trace) = guardrail_trace {
        // `inputAssessment` is a map of guardrail id to one assessment;
        // `outputAssessments` is a map of guardrail id to a list. The
        // side tells the operator whether the prompt or the completion
        // tripped the policy, which is the only thing distinguishing an
        // input intervention from an output one on the wire.
        if let Some(map) = trace.get("inputAssessment").and_then(|v| v.as_object()) {
            for assessment in map.values() {
                collect_assessment_policies(assessment, &mut input_policies);
            }
        }
        if let Some(map) = trace.get("outputAssessments").and_then(|v| v.as_object()) {
            for assessments in map.values() {
                match assessments {
                    Value::Array(list) => {
                        for assessment in list {
                            collect_assessment_policies(assessment, &mut output_policies);
                        }
                    }
                    other => collect_assessment_policies(other, &mut output_policies),
                }
            }
        }
    }

    let side = match (input_policies.is_empty(), output_policies.is_empty()) {
        (false, true) => "prompt",
        (true, false) => "completion",
        (false, false) => "prompt and completion",
        // No trace at all, or a trace with no fired policy in it.
        (true, true) => "generation",
    };
    let mut policies = input_policies;
    policies.extend(output_policies);
    policies.sort_unstable();
    policies.dedup();
    let truncated = policies.len() > MAX_REASON_POLICIES;
    policies.truncate(MAX_REASON_POLICIES);

    let reason = if policies.is_empty() {
        format!("Bedrock guardrail intervened on the {side}")
    } else {
        format!(
            "Bedrock guardrail intervened on the {side} ({}{})",
            policies.join(", "),
            if truncated { ", ..." } else { "" }
        )
    };
    Some(crate::guardrails::GuardrailBlock {
        name: INLINE_GUARDRAIL_NAME.to_string(),
        reason,
    })
}

/// Summarize one `GuardrailAssessment` into policy labels.
///
/// Every value read here is either a closed AWS enum (`contentPolicy`
/// filter types, managed word list types, PII entity types,
/// contextual-grounding filter types) or a name the operator gave the
/// policy in their own AWS guardrail (`topicPolicy` topics, regex
/// names). The two fields that carry caller text, `customWords[].match`
/// and `piiEntities[].match`, are deliberately reduced to a count and a
/// type respectively.
fn collect_assessment_policies(assessment: &Value, out: &mut Vec<String>) {
    let detected = |entry: &Value| {
        // AWS reports every configured policy in the assessment and
        // marks the ones that fired. `detected` is absent on some
        // policy shapes, in which case an action other than `NONE` is
        // the signal.
        entry
            .get("detected")
            .and_then(Value::as_bool)
            .unwrap_or(true)
            && entry
                .get("action")
                .and_then(|v| v.as_str())
                .is_none_or(|action| !action.eq_ignore_ascii_case("NONE"))
    };
    let mut push_named = |prefix: &str, list: Option<&Value>, key: &str| {
        let entries: &[Value] = list.and_then(Value::as_array).map_or(&[], Vec::as_slice);
        for entry in entries {
            if !detected(entry) {
                continue;
            }
            if let Some(value) = entry.get(key).and_then(|v| v.as_str()) {
                out.push(format!("{prefix}:{value}"));
            }
        }
    };
    push_named(
        "topic",
        assessment.get("topicPolicy").and_then(|p| p.get("topics")),
        "name",
    );
    push_named(
        "content_filter",
        assessment
            .get("contentPolicy")
            .and_then(|p| p.get("filters")),
        "type",
    );
    push_named(
        "word_list",
        assessment
            .get("wordPolicy")
            .and_then(|p| p.get("managedWordLists")),
        "type",
    );
    push_named(
        "pii",
        assessment
            .get("sensitiveInformationPolicy")
            .and_then(|p| p.get("piiEntities")),
        "type",
    );
    push_named(
        "regex",
        assessment
            .get("sensitiveInformationPolicy")
            .and_then(|p| p.get("regexes")),
        "name",
    );
    push_named(
        "grounding",
        assessment
            .get("contextualGroundingPolicy")
            .and_then(|p| p.get("filters")),
        "type",
    );
    // `customWords[].match` is the matched span of the caller's own
    // text. Report only that the custom word list fired.
    let custom_words = assessment
        .get("wordPolicy")
        .and_then(|p| p.get("customWords"))
        .and_then(Value::as_array)
        .map(|list| list.iter().filter(|entry| detected(entry)).count())
        .unwrap_or(0);
    if custom_words > 0 {
        out.push(format!("custom_words:{custom_words}"));
    }
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

    fn passthrough(trace: bool) -> crate::provider::BedrockGuardrailPassthrough {
        crate::provider::BedrockGuardrailPassthrough {
            identifier: "gr-abc123".to_string(),
            version: "DRAFT".to_string(),
            trace,
        }
    }

    #[test]
    fn converse_body_carries_guardrail_config() {
        let body = json!({
            "model": "anthropic.claude-3-5-sonnet-20240620-v1:0",
            "messages": [{"role": "user", "content": "hello"}],
        });
        let guardrail = passthrough(true);
        let (out, _) = request_to_native(body.clone(), "/v1/chat/completions", Some(&guardrail));
        assert_eq!(out["guardrailConfig"]["guardrailIdentifier"], "gr-abc123");
        assert_eq!(out["guardrailConfig"]["guardrailVersion"], "DRAFT");
        assert_eq!(
            out["guardrailConfig"]["trace"], "enabled",
            "without trace: enabled Bedrock sends no assessment, so a \
             block reason would have no policy names in it"
        );

        let quiet = passthrough(false);
        let (out, _) = request_to_native(body.clone(), "/v1/chat/completions", Some(&quiet));
        assert_eq!(out["guardrailConfig"]["trace"], "disabled");

        let (out, _) = request_to_native(body, "/v1/chat/completions", None);
        assert!(
            out.get("guardrailConfig").is_none(),
            "an unconfigured provider must not send an empty guardrail block: {out}"
        );
    }

    /// A Converse intervention with the assessment shape AWS documents.
    /// `wordPolicy.customWords[].match` and
    /// `sensitiveInformationPolicy.piiEntities[].match` carry the
    /// caller's own text; nothing derived from them may reach the
    /// reason string.
    fn intervened_body() -> Vec<u8> {
        json!({
            "stopReason": "guardrail_intervened",
            "output": {"message": {"role": "assistant", "content": [{"text": ""}]}},
            "usage": {"inputTokens": 12, "outputTokens": 0, "totalTokens": 12},
            "trace": {
                "guardrail": {
                    "outputAssessments": {
                        "gr-abc123": [{
                            "topicPolicy": {"topics": [
                                {"name": "legal_advice", "type": "DENY", "action": "BLOCKED", "detected": true},
                                {"name": "medical_advice", "type": "DENY", "action": "NONE", "detected": false}
                            ]},
                            "contentPolicy": {"filters": [
                                {"type": "VIOLENCE", "confidence": "HIGH", "action": "BLOCKED", "detected": true}
                            ]},
                            "wordPolicy": {"customWords": [
                                {"match": "hunter2-secret-passphrase", "action": "BLOCKED", "detected": true}
                            ]},
                            "sensitiveInformationPolicy": {"piiEntities": [
                                {"match": "rick@example.com", "type": "EMAIL", "action": "ANONYMIZED", "detected": true}
                            ]}
                        }]
                    }
                }
            }
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn guardrail_intervention_reads_stop_reason() {
        let block = guardrail_intervention(&intervened_body())
            .expect("stopReason guardrail_intervened is a block");
        assert_eq!(block.name, INLINE_GUARDRAIL_NAME);

        let clean = json!({
            "stopReason": "end_turn",
            "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
        })
        .to_string();
        assert!(
            guardrail_intervention(clean.as_bytes()).is_none(),
            "a normal completion is not a guardrail block"
        );
        assert!(
            guardrail_intervention(b"not json").is_none(),
            "an unparseable body is not a guardrail block"
        );
    }

    #[test]
    fn the_block_reason_names_policies_and_never_caller_content() {
        let block = guardrail_intervention(&intervened_body()).expect("block");
        assert!(
            block.reason.contains("topic:legal_advice"),
            "{}",
            block.reason
        );
        assert!(
            block.reason.contains("content_filter:VIOLENCE"),
            "{}",
            block.reason
        );
        assert!(block.reason.contains("pii:EMAIL"), "{}", block.reason);
        assert!(block.reason.contains("custom_words:1"), "{}", block.reason);
        assert!(
            block.reason.contains("completion"),
            "an outputAssessments-only trace fired on the completion: {}",
            block.reason
        );
        // The two assessment fields that quote the caller's own text.
        for leaked in ["hunter2-secret-passphrase", "rick@example.com"] {
            assert!(
                !block.reason.contains(leaked),
                "the reason reaches the 403 envelope, ctx.deny_reason, and the \
                 decision audit record; it leaked {leaked}: {}",
                block.reason
            );
        }
        // A policy AWS reported but did not fire is not a reason.
        assert!(!block.reason.contains("medical_advice"), "{}", block.reason);
    }

    #[test]
    fn an_intervention_without_a_trace_still_blocks() {
        // `trace: false` is the default, and Bedrock then sends no
        // assessment at all. The block must survive with no policy
        // names rather than being read as a normal completion.
        let body = json!({
            "stopReason": "guardrail_intervened",
            "output": {"message": {"role": "assistant", "content": [{"text": ""}]}},
        })
        .to_string();
        let block = guardrail_intervention(body.as_bytes()).expect("block");
        assert_eq!(block.name, INLINE_GUARDRAIL_NAME);
        assert!(block.reason.contains("generation"), "{}", block.reason);
    }

    #[test]
    fn an_input_side_intervention_is_named_as_the_prompt() {
        let body = json!({
            "stopReason": "guardrail_intervened",
            "trace": {"guardrail": {"inputAssessment": {"gr-abc123": {
                "contentPolicy": {"filters": [
                    {"type": "PROMPT_ATTACK", "action": "BLOCKED", "detected": true}
                ]}
            }}}}
        })
        .to_string();
        let block = guardrail_intervention(body.as_bytes()).expect("block");
        assert!(block.reason.contains("prompt"), "{}", block.reason);
        assert!(
            block.reason.contains("content_filter:PROMPT_ATTACK"),
            "{}",
            block.reason
        );
    }

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
        let (out, path) = request_to_native(body, "/v1/chat/completions", None);
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
        let (out, _) = request_to_native(body, "/v1/chat/completions", None);
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
        let (out, _) = request_to_native(body, "/v1/chat/completions", None);
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
        let (out, _) = request_to_native(body, "/v1/chat/completions", None);
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
        let (out, _) = request_to_native(body, "/v1/chat/completions", None);
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
        let (native, path) = request_to_native(req, "/v1/chat/completions", None);
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
