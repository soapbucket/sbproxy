//! Native format translators for non-OpenAI AI providers.
//!
//! Clients always speak the OpenAI chat-completions shape to the
//! gateway. When the upstream is OpenAI-compatible (Groq, Together,
//! DeepSeek, Mistral, Perplexity, OpenRouter, vLLM, Ollama, ...) we
//! pass the body through unchanged. When the upstream speaks a
//! native format (Anthropic Messages API, Google Gemini, AWS
//! Bedrock), we translate request and response so the OpenAI client
//! gets a uniform interface without an OpenRouter hop.
//!
//! This crate is shipped progressively. Anthropic lands first
//! because it's the most-asked-for and the request/response shape is
//! similar enough to OpenAI to translate cleanly. Gemini and Bedrock
//! follow as separate translators registered the same way.

pub mod anthropic;

use crate::providers::ProviderFormat;

/// Translate an OpenAI-shaped request body into the upstream's native
/// format. Returns the body unchanged for OpenAI-compatible
/// providers; calls the matching translator for native providers.
///
/// `path` is the inbound path (e.g. `/v1/chat/completions`) and may
/// be rewritten by the translator (Anthropic uses `/v1/messages`).
/// The returned `(body, path)` pair is what the AI client should
/// send upstream.
pub fn translate_request(
    format: ProviderFormat,
    path: &str,
    body: serde_json::Value,
) -> (serde_json::Value, String) {
    match format {
        ProviderFormat::OpenAi => (body, path.to_string()),
        ProviderFormat::Anthropic => anthropic::request_to_native(body, path),
        // Gemini, Bedrock, Custom: not implemented yet. Pass through
        // and let the caller fail loudly. Documented as a known
        // limitation; covered by OpenRouter routing in the meantime.
        _ => (body, path.to_string()),
    }
}

/// Translate an upstream native response body back into OpenAI shape.
/// `OpenAi` is the no-op pass-through.
pub fn translate_response(format: ProviderFormat, body: serde_json::Value) -> serde_json::Value {
    match format {
        ProviderFormat::OpenAi => body,
        ProviderFormat::Anthropic => anthropic::response_to_openai(body),
        _ => body,
    }
}

/// Convenience: translate raw response bytes back into OpenAI-shaped
/// JSON bytes. Returns the original bytes unchanged when the format is
/// `OpenAi`, when JSON parsing fails, or when re-serialization fails;
/// this keeps the relay path lossless on unexpected upstream shapes.
pub fn translate_response_bytes(format: ProviderFormat, body: &[u8]) -> Vec<u8> {
    if matches!(format, ProviderFormat::OpenAi) {
        return body.to_vec();
    }
    let parsed: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return body.to_vec(),
    };
    let translated = translate_response(format, parsed);
    serde_json::to_vec(&translated).unwrap_or_else(|_| body.to_vec())
}

/// Whether this format requires request/response translation. Streaming
/// responses for non-OpenAI formats are passed through today (event
/// shapes differ between providers), so callers should check this
/// before enabling SSE relay against a translated provider.
pub fn requires_translation(format: ProviderFormat) -> bool {
    !matches!(format, ProviderFormat::OpenAi)
}
