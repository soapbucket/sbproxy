//! Hub format and the `ChatFormat` trait.
//!
//! The hub is the canonical internal request and response shape every
//! inbound parser writes into and every outbound emitter reads from.
//! Adding a sixth wire format means writing one new `ChatFormat` impl
//! rather than touching N pairwise translators. The design and the
//! rules that govern lossiness, streaming, and extensions live in
//! `docs/adr-ai-hub-format.md`.
//!
//! This module is bytes-in / hub-out at the inbound edge and
//! hub-in / bytes-out at the outbound edge. Wire formats never leave
//! this layer; the rest of the AI gateway speaks hub types only.
//!
//! ## Scope
//!
//! This module lands the trait surface, the hub types, three inbound
//! `ChatFormat` implementations (OpenAI Chat, OpenAI Responses,
//! Anthropic Messages), and the inbound route wiring. The existing
//! pairwise translators in `crates/sbproxy-ai/src/translators/` keep
//! working unchanged; later work migrates them to use this trait. The
//! `from_hub_stream` method is part of the trait surface today; only
//! the OpenAI Chat branch returns frames end to end. The Anthropic and
//! Responses branches return a `not implemented yet` error so a future
//! caller wiring streaming gets a clear pointer rather than silent
//! misbehaviour.

pub mod anthropic_messages;
pub mod native_streams;
pub mod openai_chat;
pub mod openai_responses;
mod registry;
mod types;

pub use anthropic_messages::AnthropicMessagesFormat;
pub use native_streams::{split_sse_frame, NativeStreamFormat, NativeStreamTranslator, SseFramer};
pub use openai_chat::OpenAiChatFormat;
pub use openai_responses::OpenAiResponsesFormat;
pub use registry::FormatRegistry;
pub use types::{
    BridgeContext, ContentPart, ContentPartDelta, FinishReason, HubChunk, HubMessage, HubRequest,
    HubResponse, HubToolCall, HubToolCallDelta, HubToolChoice, HubToolDefinition, HubUsage,
    LossinessDirection, LossinessNote, Role,
};

use std::fmt;

/// Error returned from any `ChatFormat` operation. Errors map to HTTP
/// status codes via `status()`; the gateway uses that to surface a
/// matching response to the client.
#[derive(Debug, Clone)]
pub struct ChatError {
    status: u16,
    message: String,
}

impl ChatError {
    /// HTTP 400 with a client-visible message.
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: 400,
            message: msg.into(),
        }
    }

    /// HTTP 501 with a client-visible message.
    pub fn not_implemented(msg: impl Into<String>) -> Self {
        Self {
            status: 501,
            message: msg.into(),
        }
    }

    /// HTTP status code associated with this error.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Human-readable message safe to surface to the client.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ChatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.status, self.message)
    }
}

impl std::error::Error for ChatError {}

/// Rewrap an OpenAI Chat Completions response body into the wire shape
/// the inbound client expects.
///
/// The AI gateway's internal pipeline normalises every request through
/// the OpenAI Chat Completions hub shape, so by the time the upstream
/// response reaches the client the body is already OpenAI-shaped. When
/// the inbound request came in on a native shim path
/// (`/v1/messages` -> `"anthropic"`, `/v1/responses` -> `"responses"`),
/// this helper translates the body back to the client's expected
/// shape. Unknown inbound formats are passed through untouched, which
/// keeps the canonical chat path zero-cost.
pub fn rewrap_response_for_inbound(inbound_format: Option<&str>, body: &[u8]) -> Vec<u8> {
    match inbound_format {
        Some("anthropic") => anthropic_messages::translate_openai_response_to_anthropic(body),
        Some("responses") => openai_responses::translate_openai_response_to_responses(body),
        _ => body.to_vec(),
    }
}

/// Native-format bypass classification.
///
/// Returned by [`native_bypass_for`] when an inbound format and an
/// upstream provider's wire format are the same, so the gateway can
/// forward the client bytes verbatim and skip both legs of the hub
/// translation. Variants carry the native upstream path the gateway
/// should target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeBypass {
    /// OpenAI Chat Completions client hitting any OpenAI-compatible
    /// upstream. The current pipeline already byte-forwards this case
    /// because no inbound translation runs, but the classification is
    /// recorded for metrics so operators can see the share of native
    /// traffic on the canonical path.
    OpenAiChat,
    /// Anthropic Messages client hitting an Anthropic upstream. The
    /// hub round-trip is genuinely skipped: the native body bytes go
    /// to `/v1/messages` on the upstream and the response bytes come
    /// back unmodified.
    AnthropicMessages,
}

impl NativeBypass {
    /// Inbound HTTP path the bypass dispatches to on the upstream.
    pub fn native_path(self) -> &'static str {
        match self {
            NativeBypass::OpenAiChat => "/v1/chat/completions",
            NativeBypass::AnthropicMessages => "/v1/messages",
        }
    }

    /// Stable label used for the `inbound_format` metric dimension.
    pub fn inbound_label(self) -> &'static str {
        match self {
            NativeBypass::OpenAiChat => "openai",
            NativeBypass::AnthropicMessages => "anthropic",
        }
    }

    /// Stable label used for the `provider_format` metric dimension.
    pub fn provider_label(self) -> &'static str {
        match self {
            NativeBypass::OpenAiChat => "openai",
            NativeBypass::AnthropicMessages => "anthropic",
        }
    }
}

/// Classify whether the inbound format and the upstream provider's
/// wire format are equal enough for a native bypass.
///
/// `inbound_format` is the value stamped on `ctx.ai_inbound_format`
/// after the inbound parse (`None` and `Some("openai")` both mean the
/// canonical OpenAI Chat path; `Some("anthropic")` is `/v1/messages`;
/// `Some("responses")` is `/v1/responses`).
///
/// `provider_format` is the upstream provider's catalog format from
/// `data/ai_providers.yml`.
///
/// `provider_name` is the canonical provider name. Some bypass cases
/// require a specific upstream (e.g. OpenAI Responses currently only
/// exists on `api.openai.com`, not on the broader OpenAI-compatible
/// fleet), so the classifier consults the name to avoid sending a
/// `/v1/responses` payload to a Groq or Together upstream that will
/// 404 it.
///
/// Returns `Some(NativeBypass)` when the gateway should byte-forward
/// the inbound body to the upstream's native path, or `None` when the
/// request must go through the hub round-trip.
pub fn native_bypass_for(
    inbound_format: Option<&str>,
    provider_format: crate::providers::ProviderFormat,
    _provider_name: &str,
) -> Option<NativeBypass> {
    use crate::providers::ProviderFormat;
    match (inbound_format, provider_format) {
        (None | Some("openai"), ProviderFormat::OpenAi) => Some(NativeBypass::OpenAiChat),
        (Some("anthropic"), ProviderFormat::Anthropic) => Some(NativeBypass::AnthropicMessages),
        // OpenAI Responses bypass is intentionally out of scope here.
        // Most OpenAI-compatible upstreams do not yet expose
        // `/v1/responses`, and the hub-mediated path already produces
        // the right wire shape for the client. A future ticket can
        // add an opt-in `provider.supports_responses` flag and flip
        // bypass on when set.
        _ => None,
    }
}

/// A bidirectional translator between a wire format and the hub.
///
/// The trait is method-style and uses the names called out in the
/// ticket (`to_hub`, `from_hub`, `from_hub_stream`). Implementors are
/// stateless and cheap to construct; the gateway holds one instance
/// per registered format inside the `FormatRegistry`.
///
/// The `from_*` methods take `&self` despite clippy's naming
/// convention because the trait is dispatched dynamically through an
/// `Arc<dyn ChatFormat>` in the registry; the receiver is the format
/// identity, not a conversion source.
#[allow(clippy::wrong_self_convention)]
pub trait ChatFormat: Send + Sync + 'static {
    /// Stable identifier used in config and logs (`openai`,
    /// `anthropic`, `responses`).
    fn id(&self) -> &'static str;

    /// Inbound HTTP path this format claims (`/v1/chat/completions`,
    /// `/v1/messages`, `/v1/responses`). Returned as a slice because a
    /// format may claim several paths (Bedrock will claim both
    /// `InvokeModel` and `Converse` once it joins).
    fn inbound_paths(&self) -> &'static [&'static str];

    /// Parse client bytes on an inbound path into the hub request.
    /// Errors here are HTTP 400 to the client: malformed JSON, missing
    /// required fields, an unsupported feature the format cannot
    /// represent in the hub at all.
    fn to_hub(&self, bytes: &[u8]) -> Result<(HubRequest, BridgeContext), ChatError>;

    /// Emit a hub response in this format's wire shape. Returns the
    /// raw bytes the gateway writes back to the client.
    fn from_hub(&self, resp: &HubResponse, ctx: &BridgeContext) -> Result<Vec<u8>, ChatError>;

    /// Translate a single hub streaming chunk into this format's wire
    /// SSE frame(s). A single hub chunk may produce zero (state
    /// updates only) or several wire frames; the return is a vector
    /// of already-framed `data: ...\n\n` strings ready to write.
    ///
    /// Implementors that do not yet wire streaming end to end return
    /// `ChatError::not_implemented` pointing at the follow-up ticket.
    fn from_hub_stream(
        &self,
        chunk: &HubChunk,
        ctx: &BridgeContext,
    ) -> Result<Vec<String>, ChatError>;
}

/// Parse the `role` field of a chat message into a [`Role`].
///
/// WOR-599: a missing or unrecognized role is an error, never a silent
/// default to [`Role::User`]. The role is a security-relevant routing
/// decision (a user turn must not be able to masquerade as a system turn),
/// so the inbound parsers all funnel through this one helper rather than
/// each doing `unwrap_or("user")`.
pub(crate) fn parse_role(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<Role, ChatError> {
    let role_s = obj
        .get("role")
        .and_then(|r| r.as_str())
        .ok_or_else(|| ChatError::bad_request("chat message is missing a 'role' field"))?;
    match role_s {
        "user" => Ok(Role::User),
        "assistant" => Ok(Role::Assistant),
        "system" => Ok(Role::System),
        "tool" => Ok(Role::Tool),
        other => Err(ChatError::bad_request(format!(
            "unsupported message role: {other}"
        ))),
    }
}

#[cfg(test)]
mod role_parse_tests {
    use super::{parse_role, Role};
    use serde_json::json;

    fn obj(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn missing_role_is_an_error_not_user() {
        assert!(
            parse_role(&obj(json!({"content": "x"}))).is_err(),
            "a missing role must error, not default to user"
        );
    }

    #[test]
    fn unknown_role_is_an_error_not_user() {
        assert!(
            parse_role(&obj(json!({"role": "developer", "content": "x"}))).is_err(),
            "an unknown role must error, not default to user"
        );
    }

    #[test]
    fn known_roles_parse_to_their_variant() {
        assert_eq!(
            parse_role(&obj(json!({"role": "user"}))).unwrap(),
            Role::User
        );
        assert_eq!(
            parse_role(&obj(json!({"role": "assistant"}))).unwrap(),
            Role::Assistant
        );
        assert_eq!(
            parse_role(&obj(json!({"role": "system"}))).unwrap(),
            Role::System
        );
        assert_eq!(
            parse_role(&obj(json!({"role": "tool"}))).unwrap(),
            Role::Tool
        );
    }
}

#[cfg(test)]
mod native_bypass_tests {
    use super::{native_bypass_for, NativeBypass};
    use crate::providers::ProviderFormat;

    #[test]
    fn openai_chat_inbound_matches_openai_upstream() {
        assert_eq!(
            native_bypass_for(None, ProviderFormat::OpenAi, "openai"),
            Some(NativeBypass::OpenAiChat),
        );
        assert_eq!(
            native_bypass_for(Some("openai"), ProviderFormat::OpenAi, "groq"),
            Some(NativeBypass::OpenAiChat),
        );
    }

    #[test]
    fn anthropic_inbound_matches_anthropic_upstream() {
        assert_eq!(
            native_bypass_for(Some("anthropic"), ProviderFormat::Anthropic, "anthropic"),
            Some(NativeBypass::AnthropicMessages),
        );
    }

    #[test]
    fn responses_inbound_is_out_of_scope_for_v1() {
        // Most OpenAI-compatible upstreams do not expose
        // `/v1/responses`; bypass is intentionally restricted until
        // a per-provider opt-in lands.
        assert_eq!(
            native_bypass_for(Some("responses"), ProviderFormat::OpenAi, "openai"),
            None,
        );
    }

    #[test]
    fn mismatched_pairs_fall_back_to_hub() {
        assert_eq!(
            native_bypass_for(Some("anthropic"), ProviderFormat::OpenAi, "openai"),
            None,
        );
        assert_eq!(
            native_bypass_for(None, ProviderFormat::Anthropic, "anthropic"),
            None,
        );
        assert_eq!(
            native_bypass_for(Some("anthropic"), ProviderFormat::Google, "gemini"),
            None,
        );
    }

    #[test]
    fn enum_labels_are_stable() {
        assert_eq!(NativeBypass::OpenAiChat.inbound_label(), "openai");
        assert_eq!(NativeBypass::OpenAiChat.provider_label(), "openai");
        assert_eq!(
            NativeBypass::OpenAiChat.native_path(),
            "/v1/chat/completions"
        );
        assert_eq!(NativeBypass::AnthropicMessages.inbound_label(), "anthropic");
        assert_eq!(
            NativeBypass::AnthropicMessages.provider_label(),
            "anthropic"
        );
        assert_eq!(
            NativeBypass::AnthropicMessages.native_path(),
            "/v1/messages"
        );
    }
}

#[cfg(test)]
mod parity_tests {
    //! Cross-parser behavioral-parity guard.
    //!
    //! The OpenAI Chat, Anthropic Messages, and OpenAI Responses message
    //! parsers each handle a different wire format, so they are kept
    //! separate rather than merged behind a shared content/tool-call
    //! helper: the per-format branches genuinely differ (empty-string
    //! handling, the Responses `input_text` alias, image source shape, and
    //! tool-call argument encoding). Role parsing is the one piece they
    //! share, via [`super::parse_role`].
    //!
    //! What this pins: for content the three formats express the same way,
    //! the parsers must agree on the resulting `HubMessage`, so drift in a
    //! shared-intent path is caught here rather than by a customer.
    use super::types::{ContentPart, HubMessage, Role};
    use serde_json::{json, Map, Value};

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object()
            .expect("test input must be a JSON object")
            .clone()
    }

    #[test]
    fn plain_text_string_parses_identically_across_formats() {
        let input = json!({"role": "user", "content": "hello"});
        let expected = HubMessage {
            role: Role::User,
            content: vec![ContentPart::Text {
                text: "hello".into(),
            }],
            name: None,
            tool_call_id: None,
        };
        assert_eq!(
            super::openai_chat::parse_openai_message(&obj(input.clone())).unwrap(),
            expected
        );
        assert_eq!(
            super::anthropic_messages::parse_anthropic_message(&obj(input.clone())).unwrap(),
            expected
        );
        assert_eq!(
            super::openai_responses::parse_responses_message(&obj(input)).unwrap(),
            expected
        );
    }

    #[test]
    fn text_content_block_parses_identically_across_formats() {
        let input = json!({"role": "user", "content": [{"type": "text", "text": "hi"}]});
        let expected = HubMessage {
            role: Role::User,
            content: vec![ContentPart::Text { text: "hi".into() }],
            name: None,
            tool_call_id: None,
        };
        assert_eq!(
            super::openai_chat::parse_openai_message(&obj(input.clone())).unwrap(),
            expected
        );
        assert_eq!(
            super::anthropic_messages::parse_anthropic_message(&obj(input.clone())).unwrap(),
            expected
        );
        assert_eq!(
            super::openai_responses::parse_responses_message(&obj(input)).unwrap(),
            expected
        );
    }

    #[test]
    fn assistant_tool_use_parses_to_same_hub_for_openai_and_anthropic() {
        // OpenAI: separate `tool_calls` array, arguments as a JSON string.
        let openai = super::openai_chat::parse_openai_message(&obj(json!({
            "role": "assistant",
            "tool_calls": [{
                "id": "t1",
                "type": "function",
                "function": {"name": "f", "arguments": "{\"x\":1}"}
            }]
        })))
        .unwrap();
        // Anthropic: inline `tool_use` block, `input` already structured.
        let anthropic = super::anthropic_messages::parse_anthropic_message(&obj(json!({
            "role": "assistant",
            "content": [{"type": "tool_use", "id": "t1", "name": "f", "input": {"x": 1}}]
        })))
        .unwrap();
        let expected = HubMessage {
            role: Role::Assistant,
            content: vec![ContentPart::ToolUse {
                id: "t1".into(),
                name: "f".into(),
                input: json!({"x": 1}),
            }],
            name: None,
            tool_call_id: None,
        };
        assert_eq!(openai, expected);
        assert_eq!(anthropic, expected);
    }
}
