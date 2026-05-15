//! Hub format types used by the `ChatFormat` trait.
//!
//! The hub is the canonical internal shape that every inbound parser
//! writes into and every outbound emitter reads from. It is deliberately
//! close to the OpenAI Chat Completions wire shape, with three documented
//! divergences (see `docs/adr-ai-hub-format.md`):
//!
//!   * Tool-call `arguments` are typed JSON, not a string.
//!   * `top_k` is present even though OpenAI lacks it.
//!   * `system` is a single optional string, not interleaved.
//!
//! Wire bytes never leave this module. Everything downstream of the
//! trait surface (telemetry, guardrails, caching, routing) speaks these
//! types and only these types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Canonical hub request. Every inbound parser produces one of these;
/// every outbound emitter consumes one.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct HubRequest {
    /// Model identifier as supplied by the client. May be remapped by
    /// the alias resolver before the emitter runs.
    #[serde(default)]
    pub model: String,
    /// Conversation messages in arrival order. `system` turns are hoisted
    /// out of this list at parse time and live in `system` below.
    #[serde(default)]
    pub messages: Vec<HubMessage>,
    /// Tools the client offered for this turn.
    #[serde(default)]
    pub tools: Vec<HubToolDefinition>,
    /// Tool-selection hint (`auto`, `none`, or a specific tool).
    #[serde(default)]
    pub tool_choice: HubToolChoice,
    /// Maximum tokens to generate. `None` lets the upstream pick its
    /// default; Anthropic requires a concrete number and the emitter is
    /// responsible for filling one in when missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Sampling temperature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Nucleus-sampling probability mass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    /// Top-k sampling. Present in the hub even though OpenAI lacks it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
    /// Stop sequences.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stop: Vec<String>,
    /// Whether the client requested SSE streaming.
    #[serde(default)]
    pub stream: bool,
    /// Optional top-level system prompt. Inbound parsers concatenate
    /// any interleaved `system` turns with `\n\n` into this single
    /// string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    /// Format-namespaced extensions. The key is `"<format-id>.<field>"`;
    /// each emitter looks for its own namespace and ignores everything
    /// else. See the ADR for the namespacing rule.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, Value>,
    /// Lossiness notes accumulated by the inbound parser when it had to
    /// drop a wire-level field that the hub does not model. The
    /// outbound emitter may append more on the way out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lossiness: Vec<LossinessNote>,
}

/// A single conversation turn.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HubMessage {
    /// Role of the speaker.
    pub role: Role,
    /// Message content. For plain-text turns this is a single
    /// `ContentPart::Text`; multimodal turns include image and tool
    /// parts in arrival order.
    #[serde(default)]
    pub content: Vec<ContentPart>,
    /// Optional speaker name (OpenAI carries this on `user` and
    /// `assistant` turns; Anthropic does not).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Set when `role == Tool`. Identifies the tool call the result
    /// satisfies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

/// Conversation roles. Renamed for snake_case JSON to match every
/// upstream wire format.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Top-level instructions; hoisted into the `system` field on
    /// parse, but the role is still useful when a hub round-trip
    /// reassembles a wire format that wants per-turn system.
    System,
    /// End user turn.
    User,
    /// Model output turn.
    Assistant,
    /// Tool-result turn (carries `tool_call_id`).
    Tool,
}

/// One piece of message content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentPart {
    /// Plain text segment.
    Text {
        /// Text body.
        text: String,
    },
    /// Image reference (URL or base64 data URI).
    Image {
        /// Image source: URL, base64 data URI, or provider-specific blob id.
        source: String,
        /// MIME type, e.g. `"image/png"`.
        media_type: String,
    },
    /// Assistant-issued tool call.
    ToolUse {
        /// Tool-call identifier as emitted by the model.
        id: String,
        /// Tool name.
        name: String,
        /// Typed JSON arguments. OpenAI's wire format stringifies this
        /// on the way out; the hub keeps it structured.
        input: Value,
    },
    /// Tool result block (user-side response to an earlier tool call).
    ToolResult {
        /// Identifier of the tool call this result satisfies.
        tool_call_id: String,
        /// Result content (serialised to a string for the wire).
        content: String,
        /// Whether the tool call ended in error.
        #[serde(default)]
        is_error: bool,
    },
}

/// Tool offered to the model for this turn.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HubToolDefinition {
    /// Tool name; must be unique within a request.
    pub name: String,
    /// Human description shown to the model.
    #[serde(default)]
    pub description: String,
    /// JSON Schema describing the tool's parameter shape.
    #[serde(default)]
    pub parameters: Value,
}

/// Tool-selection hint.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "mode", content = "name")]
pub enum HubToolChoice {
    /// Let the model decide whether to call a tool.
    #[default]
    Auto,
    /// Disallow tool calls for this turn.
    None,
    /// Require the model to call this specific tool.
    Required(String),
}

/// Canonical hub response.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct HubResponse {
    /// Provider-issued response identifier.
    pub id: String,
    /// Model that produced the response.
    pub model: String,
    /// Output content blocks in arrival order.
    #[serde(default)]
    pub content: Vec<ContentPart>,
    /// Assistant-issued tool calls (also surfaced as `ContentPart::ToolUse`
    /// inside `content` so cross-format emitters that only inspect one
    /// pathway still see them).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<HubToolCall>,
    /// Why the model stopped.
    #[serde(default)]
    pub finish_reason: FinishReason,
    /// Token accounting.
    #[serde(default)]
    pub usage: HubUsage,
    /// Format-namespaced extensions surfaced by the upstream parser.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, Value>,
}

/// Tool call surfaced by the model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HubToolCall {
    /// Tool-call identifier.
    pub id: String,
    /// Tool name.
    pub name: String,
    /// Typed JSON arguments.
    pub arguments: Value,
}

/// Finish reason normalized across providers.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    /// Natural turn boundary.
    #[default]
    Stop,
    /// Hit `max_tokens` or equivalent.
    Length,
    /// Stopped to emit tool calls.
    ToolCalls,
    /// Provider safety filter triggered.
    ContentFilter,
    /// Provider returned a finish reason the hub does not normalise.
    Other(String),
}

/// Token usage.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HubUsage {
    /// Tokens read from the prompt.
    #[serde(default)]
    pub prompt_tokens: u64,
    /// Tokens generated.
    #[serde(default)]
    pub completion_tokens: u64,
    /// Sum of prompt + completion.
    #[serde(default)]
    pub total_tokens: u64,
}

/// A streaming hub event. The vocabulary is deliberately tiny so every
/// provider's SSE shape maps onto it without per-pair demuxers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HubChunk {
    /// First event of a streamed response. Carries the response id and
    /// the resolved model name.
    MessageStart {
        /// Provider-issued response identifier.
        id: String,
        /// Model name.
        model: String,
    },
    /// Incremental text or tool-call argument fragment.
    ContentDelta {
        /// Index of the content block within the assistant's output.
        index: usize,
        /// Body of the delta.
        delta: ContentPartDelta,
    },
    /// Incremental tool-call shape (id / name appear in the first delta;
    /// argument chunks follow).
    ToolCallDelta {
        /// Tool-call index within the assistant turn.
        index: usize,
        /// Body of the delta.
        delta: HubToolCallDelta,
    },
    /// Usage event, typically the last frame before MessageStop.
    Usage(HubUsage),
    /// Terminal event. The emitter is responsible for framing
    /// terminator bytes (`data: [DONE]` on OpenAI, `event: message_stop`
    /// on Anthropic).
    MessageStop {
        /// Why the model stopped.
        finish_reason: FinishReason,
    },
}

/// Delta variant of `ContentPart`. Only text streams today; image and
/// tool-result blocks appear in full inside the surrounding MessageStart
/// metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum ContentPartDelta {
    /// Text fragment.
    Text(String),
}

/// Incremental tool-call data.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct HubToolCallDelta {
    /// Present in the first delta; identifies the call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Present in the first delta; identifies the tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Raw JSON fragment of arguments. OpenAI ships these as string
    /// chunks; Anthropic emits whole partial objects. Both round-trip
    /// through the hub as opaque strings; the assembler on the emit
    /// side reconstructs valid JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments_chunk: Option<String>,
}

/// Out-of-band context passed alongside the `HubRequest` from the
/// inbound parser to the outbound emitter. Carries facts about the
/// wire-level request that the hub does not model (e.g. the streaming
/// shape the client expects, the original inbound path so the response
/// emitter can re-derive a stateful conversation id).
#[derive(Debug, Clone, Default)]
pub struct BridgeContext {
    /// Inbound format id that produced the request (`openai`,
    /// `anthropic`, `responses`). Used by the outbound shim to decide
    /// which `from_hub` emitter to call.
    pub inbound_format: String,
    /// Inbound path the client hit, before any upstream rewrite.
    pub inbound_path: String,
    /// Whether the client asked for streaming. Mirrors
    /// `HubRequest::stream` but the response shim reads it without
    /// re-touching the request.
    pub stream: bool,
    /// Wire-level facts the format wants to preserve across the round
    /// trip. Each format namespaces its own keys (`"responses.previous_id"`,
    /// `"anthropic.system_blocks"`).
    pub extras: BTreeMap<String, Value>,
}

/// Lossiness note: surfaced when an inbound parser had to drop a field
/// the hub does not model, or when an outbound emitter cannot represent
/// a field present in the hub. Telemetry exporters emit these as a span
/// attribute and a counter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LossinessNote {
    /// Field that could not be preserved.
    pub field: String,
    /// Direction of the loss.
    pub direction: LossinessDirection,
    /// One-sentence explanation visible in logs and traces.
    pub note: String,
}

/// Direction of a lossiness event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LossinessDirection {
    /// Hub kept the value but the emitter could not represent it
    /// upstream.
    Downgrade,
    /// Hub does not model the value at all; the inbound parser dropped
    /// it.
    Unsupported,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hub_request_roundtrips_through_json() {
        let req = HubRequest {
            model: "claude-3-5-sonnet".to_string(),
            messages: vec![HubMessage {
                role: Role::User,
                content: vec![ContentPart::Text {
                    text: "hi".to_string(),
                }],
                name: None,
                tool_call_id: None,
            }],
            stream: true,
            ..Default::default()
        };
        let s = serde_json::to_string(&req).expect("serialise");
        let back: HubRequest = serde_json::from_str(&s).expect("deserialise");
        assert_eq!(back, req);
    }

    #[test]
    fn finish_reason_default_is_stop() {
        assert_eq!(FinishReason::default(), FinishReason::Stop);
    }

    #[test]
    fn tool_choice_default_is_auto() {
        assert_eq!(HubToolChoice::default(), HubToolChoice::Auto);
    }

    #[test]
    fn content_part_tool_use_round_trip() {
        let part = ContentPart::ToolUse {
            id: "toolu_1".into(),
            name: "get_weather".into(),
            input: json!({"city": "SF"}),
        };
        let s = serde_json::to_string(&part).unwrap();
        let back: ContentPart = serde_json::from_str(&s).unwrap();
        assert_eq!(back, part);
    }
}
