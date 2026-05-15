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
//! ## Scope of WOR-224
//!
//! WOR-224 lands the trait surface, the hub types, three inbound
//! `ChatFormat` implementations (OpenAI Chat, OpenAI Responses,
//! Anthropic Messages), and the inbound route wiring. The existing
//! pairwise translators in `crates/sbproxy-ai/src/translators/` keep
//! working unchanged; a future ticket (WOR-226 for streaming
//! conformance and the Anthropic / Responses streaming branches,
//! WOR-229 for the native-format bypass) will migrate them to use this
//! trait. The `from_hub_stream` method is part of the trait surface
//! today; only the OpenAI Chat branch returns frames end to end. The
//! Anthropic and Responses branches return a `not implemented yet`
//! error pointing at WOR-226 so a future caller wiring streaming
//! gets a clear pointer rather than silent misbehaviour.

pub mod anthropic_messages;
pub mod native_streams;
pub mod openai_chat;
pub mod openai_responses;
mod registry;
mod types;

pub use anthropic_messages::AnthropicMessagesFormat;
pub use native_streams::{
    split_sse_frame, AnthropicStreamState, BedrockStreamState, GeminiStreamState,
    NativeStreamFormat, NativeStreamTranslator, SseFramer,
};
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
