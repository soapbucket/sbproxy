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
//! Anthropic, Gemini, and Bedrock chat translators are registered on
//! the same dispatch path. Gemini also has an embeddings translator
//! for `/v1/embeddings`; native upstream streaming is normalized by
//! `format::native_streams`.

pub mod anthropic;
pub mod bedrock;
pub mod gemini;
/// WOR-824 item 2: Google Gemini embeddings sub-translator.
/// Reachable through [`gemini::request_to_native`] /
/// [`gemini::response_to_openai`] when the path is `/v1/embeddings`
/// (request side) or the response carries an `embedding` /
/// `embeddings` field with no `candidates` (response side).
pub mod gemini_embeddings;

use crate::providers::ProviderFormat;

/// Translate an OpenAI-shaped request body into the upstream's native
/// format. Returns the body unchanged for OpenAI-compatible
/// providers; calls the matching translator for native providers.
///
/// `path` is the inbound path (e.g. `/v1/chat/completions`) and may
/// be rewritten by the translator (Anthropic uses `/v1/messages`,
/// Gemini uses `/v1beta/models/{model}:generateContent`, Bedrock
/// Converse uses `/model/{modelId}/converse`). The returned path is
/// what the AI client should send upstream.
///
/// The body is borrowed (WOR-1701): a `Some(value)` result carries a
/// translated body the caller must send, while `None` means the body
/// passes through unchanged and the caller should send the original
/// borrowed body. This keeps the common OpenAI / Custom formats
/// clone-free on the per-attempt path; only the native translators,
/// which need an owned tree, clone.
///
/// The one field the OpenAI arm does not pass through is `top_k`. The
/// canonical body is the OpenAI Chat Completions shape with three
/// documented divergences (see `format::types`), and `top_k` is the
/// only divergence that reaches the wire: OpenAI has no such argument
/// and `api.openai.com` answers an unrecognized one with a 400. Every
/// other arm resolves the divergence by mapping the field (Anthropic
/// takes it natively, Gemini re-homes it to `generationConfig.topK`,
/// Bedrock drops it because Converse has no top-level equivalent);
/// the OpenAI arm resolves it by
/// dropping it, which is also what this path did before `top_k` was
/// honored end to end. `Custom` keeps its lossless relay contract and
/// forwards whatever the operator's own translator expects.
pub fn translate_request(
    format: ProviderFormat,
    path: &str,
    body: &serde_json::Value,
) -> (Option<serde_json::Value>, String) {
    match format {
        ProviderFormat::OpenAi => {
            if body.get("top_k").is_some() {
                let mut owned = body.clone();
                if let Some(obj) = owned.as_object_mut() {
                    obj.remove("top_k");
                }
                return (Some(owned), path.to_string());
            }
            (None, path.to_string())
        }
        ProviderFormat::Anthropic => {
            let (b, p) = anthropic::request_to_native(body.clone(), path);
            (Some(b), p)
        }
        ProviderFormat::Google => {
            let (b, p) = gemini::request_to_native(body.clone(), path);
            (Some(b), p)
        }
        ProviderFormat::Bedrock => {
            let (b, p) = bedrock::request_to_native(body.clone(), path);
            (Some(b), p)
        }
        // Custom: pass through. Custom-format operators bring their
        // own translator via a plugin; the relay path stays lossless.
        ProviderFormat::Custom => (None, path.to_string()),
    }
}

/// Translate an upstream native response body back into OpenAI shape.
/// `OpenAi` is the no-op pass-through.
pub fn translate_response(format: ProviderFormat, body: serde_json::Value) -> serde_json::Value {
    match format {
        ProviderFormat::OpenAi => body,
        ProviderFormat::Anthropic => anthropic::response_to_openai(body),
        ProviderFormat::Google => gemini::response_to_openai(body),
        ProviderFormat::Bedrock => bedrock::response_to_openai(body),
        ProviderFormat::Custom => body,
    }
}

/// Convenience: translate raw response bytes back into OpenAI-shaped
/// JSON bytes. Returns the original bytes unchanged when the format is
/// `OpenAi`, when the body is a top-level provider error envelope,
/// when JSON parsing fails, or when re-serialization fails; this keeps
/// the relay path lossless on unexpected upstream shapes.
pub fn translate_response_bytes(format: ProviderFormat, body: &[u8]) -> Vec<u8> {
    if matches!(format, ProviderFormat::OpenAi) {
        return body.to_vec();
    }
    let parsed: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return body.to_vec(),
    };
    if parsed
        .get("error")
        .is_some_and(|provider_error| !provider_error.is_null())
    {
        return body.to_vec();
    }
    let translated = translate_response(format, parsed);
    serde_json::to_vec(&translated).unwrap_or_else(|_| body.to_vec())
}

/// Translate only successful upstream responses into the canonical
/// OpenAI shape. Provider error bodies are relayed byte-for-byte so
/// callers can preserve their native error envelopes.
pub fn translate_success_response_bytes(
    format: ProviderFormat,
    status: u16,
    body: &[u8],
) -> Vec<u8> {
    if !(200..300).contains(&status) {
        return body.to_vec();
    }
    translate_response_bytes(format, body)
}

/// Whether this format requires request/response translation. Streaming
/// responses for non-OpenAI formats are passed through today (event
/// shapes differ between providers), so callers should check this
/// before enabling SSE relay against a translated provider.
pub fn requires_translation(format: ProviderFormat) -> bool {
    !matches!(format, ProviderFormat::OpenAi)
}

#[cfg(test)]
mod upstream_body_tests {
    //! Seam tests for the fields the hub honors but the OpenAI Chat
    //! wire shape cannot carry verbatim.
    //!
    //! The canonical body is not the upstream body. `tool_choice` and
    //! `top_k` are parsed on `/v1/messages`, emitted into the canonical
    //! chat shape, and then have to survive one more translation before
    //! they reach a provider. These tests drive that second leg by
    //! name, because asserting on the canonical body alone let a
    //! `"tool_choice": "required"` reach Anthropic (which requires an
    //! object) and a `top_k` reach `api.openai.com` (which rejects
    //! unrecognized arguments).
    use super::*;
    use serde_json::{json, Value};

    /// Run an Anthropic Messages inbound body through the inbound shim
    /// and then through one provider translator, returning the body
    /// the gateway would actually send upstream.
    fn upstream_body(format: ProviderFormat, inbound: Value) -> Value {
        let canonical = crate::format::anthropic_messages::translate_anthropic_request_to_openai(
            inbound.to_string().as_bytes(),
            "test.sbproxy.dev",
            None,
        )
        .expect("inbound Anthropic body parses");
        let canonical: Value = serde_json::from_slice(&canonical).expect("canonical body is JSON");
        let (translated, _path) = translate_request(format, "/v1/chat/completions", &canonical);
        translated.unwrap_or(canonical)
    }

    fn messages_request(tool_choice: Value) -> Value {
        json!({
            "model": "claude-3-5-sonnet",
            "max_tokens": 100,
            "messages": [{"role": "user", "content": "what is the weather"}],
            "tools": [{"name": "get_weather", "input_schema": {"type": "object"}}],
            "tool_choice": tool_choice,
        })
    }

    #[test]
    fn anthropic_upstream_receives_tool_choice_in_its_native_object_shape() {
        for (inbound, expected) in [
            (json!({"type": "any"}), json!({"type": "any"})),
            (json!({"type": "none"}), json!({"type": "none"})),
            (
                json!({"type": "tool", "name": "get_weather"}),
                json!({"type": "tool", "name": "get_weather"}),
            ),
        ] {
            let out = upstream_body(ProviderFormat::Anthropic, messages_request(inbound.clone()));
            assert_eq!(
                out["tool_choice"], expected,
                "Anthropic rejects a string tool_choice with a 400; sent {inbound}"
            );
        }
    }

    #[test]
    fn anthropic_upstream_omits_tool_choice_for_auto() {
        let out = upstream_body(
            ProviderFormat::Anthropic,
            messages_request(json!({"type": "auto"})),
        );
        assert!(
            out.get("tool_choice").is_none(),
            "auto is the provider default and needs no field: {out}"
        );
    }

    #[test]
    fn gemini_upstream_receives_tool_choice_as_function_calling_config() {
        let out = upstream_body(
            ProviderFormat::Google,
            messages_request(json!({"type": "any"})),
        );
        assert!(
            out.get("tool_choice").is_none(),
            "Gemini rejects an unknown top-level name with a 400: {out}"
        );
        assert_eq!(out["toolConfig"]["functionCallingConfig"]["mode"], "ANY");

        let forced = upstream_body(
            ProviderFormat::Google,
            messages_request(json!({"type": "tool", "name": "get_weather"})),
        );
        assert_eq!(forced["toolConfig"]["functionCallingConfig"]["mode"], "ANY");
        assert_eq!(
            forced["toolConfig"]["functionCallingConfig"]["allowedFunctionNames"],
            json!(["get_weather"])
        );

        let disabled = upstream_body(
            ProviderFormat::Google,
            messages_request(json!({"type": "none"})),
        );
        assert_eq!(
            disabled["toolConfig"]["functionCallingConfig"]["mode"],
            "NONE"
        );
    }

    #[test]
    fn openai_format_upstreams_never_receive_top_k() {
        // `top_k` is a documented hub divergence from the OpenAI Chat
        // wire schema. api.openai.com answers an unrecognized argument
        // with a 400, so the OpenAI arm resolves the divergence by
        // dropping the field rather than forwarding it.
        let inbound = json!({
            "model": "claude-3-5-sonnet",
            "max_tokens": 100,
            "top_k": 40,
            "messages": [{"role": "user", "content": "hi"}],
        });
        let out = upstream_body(ProviderFormat::OpenAi, inbound);
        assert!(
            out.get("top_k").is_none(),
            "top_k is not an OpenAI Chat Completions argument: {out}"
        );
        assert_eq!(out["max_tokens"], 100, "the rest of the body is untouched");
    }

    #[test]
    fn native_upstreams_still_receive_top_k() {
        let inbound = json!({
            "model": "claude-3-5-sonnet",
            "max_tokens": 100,
            "top_k": 40,
            "messages": [{"role": "user", "content": "hi"}],
        });
        assert_eq!(
            upstream_body(ProviderFormat::Anthropic, inbound.clone())["top_k"],
            40,
            "Anthropic accepts top_k natively"
        );
        assert_eq!(
            upstream_body(ProviderFormat::Google, inbound)["generationConfig"]["topK"],
            40,
            "Gemini re-homes top_k under generationConfig"
        );
    }

    #[test]
    fn a_body_without_top_k_is_still_forwarded_by_reference() {
        let body = json!({"model": "gpt-4o", "messages": []});
        let (translated, path) =
            translate_request(ProviderFormat::OpenAi, "/v1/chat/completions", &body);
        assert!(
            translated.is_none(),
            "the OpenAI pass-through must stay clone-free when there is nothing to strip"
        );
        assert_eq!(path, "/v1/chat/completions");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anthropic_top_level_error_envelope_is_not_translated_as_a_message() {
        let body =
            br#"{"type":"error","error":{"type":"invalid_request_error","message":"bad input"}}"#;

        assert_eq!(
            translate_response_bytes(ProviderFormat::Anthropic, body),
            body
        );
    }

    #[test]
    fn non_success_anthropic_response_is_not_translated() {
        let body = br#"{"type":"message","content":[{"type":"text","text":"upstream details"}]}"#;

        assert_eq!(
            translate_success_response_bytes(ProviderFormat::Anthropic, 400, body),
            body
        );
    }
}
