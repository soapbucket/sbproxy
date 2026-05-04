//! API endpoint routing for non-chat AI endpoints.
//!
//! Provides path-based detection of AI API endpoints and per-provider
//! capability checks for routing and validation.

/// AI API endpoint types.
///
/// Covers all standard OpenAI-compatible API paths plus common extensions
/// for embeddings, reranking, image generation, and audio.
#[derive(Debug, Clone, PartialEq)]
pub enum AiEndpoint {
    /// POST /v1/chat/completions - Chat completion (text generation).
    ChatCompletions,
    /// POST /v1/embeddings - Text embedding generation.
    Embeddings,
    /// POST /v1/rerank or /v1/reranking - Document reranking.
    Reranking,
    /// POST /v1/images/generations - Image generation.
    ImageGeneration,
    /// POST /v1/audio/transcriptions - Audio transcription (speech to text).
    AudioTranscription,
    /// POST /v1/audio/speech - Audio synthesis (text to speech).
    AudioSpeech,
    /// POST /v1/moderations - Content moderation.
    Moderations,
    /// GET /v1/models - List available models.
    Models,
    /// Any path not matching a known endpoint.
    Unknown(String),
}

/// Parse an AI API path into an `AiEndpoint` variant.
///
/// Matches against OpenAI-compatible endpoint paths. The `Unknown` variant
/// captures unrecognized paths for pass-through or logging.
pub fn parse_endpoint(path: &str) -> AiEndpoint {
    // Strip query string if present for matching.
    let base = path.split('?').next().unwrap_or(path);
    match base {
        "/v1/chat/completions" => AiEndpoint::ChatCompletions,
        "/v1/embeddings" => AiEndpoint::Embeddings,
        "/v1/rerank" | "/v1/reranking" => AiEndpoint::Reranking,
        "/v1/images/generations" => AiEndpoint::ImageGeneration,
        "/v1/audio/transcriptions" => AiEndpoint::AudioTranscription,
        "/v1/audio/speech" => AiEndpoint::AudioSpeech,
        "/v1/moderations" => AiEndpoint::Moderations,
        "/v1/models" => AiEndpoint::Models,
        other => AiEndpoint::Unknown(other.to_string()),
    }
}

/// Check whether a provider supports a given AI endpoint.
///
/// Provider capability matrix:
/// - All providers support `ChatCompletions` and `Models`.
/// - OpenAI supports all endpoints.
/// - Anthropic does not support embeddings or image generation.
/// - Gemini supports all endpoints.
/// - Cohere supports embeddings and reranking only (no chat/image/audio).
/// - All other providers: only chat completions and models.
pub fn provider_supports_endpoint(provider: &str, endpoint: &AiEndpoint) -> bool {
    match (provider, endpoint) {
        // Universal: all providers support chat and models.
        (_, AiEndpoint::ChatCompletions) => true,
        (_, AiEndpoint::Models) => true,

        // OpenAI: supports everything.
        ("openai", _) => true,

        // Anthropic: no embeddings, no image generation.
        ("anthropic", AiEndpoint::Embeddings) => false,
        ("anthropic", AiEndpoint::ImageGeneration) => false,
        // Anthropic supports audio, reranking, moderations.
        ("anthropic", _) => true,

        // Gemini: supports all endpoints.
        ("gemini", _) => true,

        // Cohere: only embeddings and reranking (plus chat/models covered above).
        ("cohere", AiEndpoint::Embeddings) => true,
        ("cohere", AiEndpoint::Reranking) => true,
        ("cohere", _) => false,

        // Unknown providers: only chat completions and models (covered above).
        _ => false,
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_endpoint tests ---

    #[test]
    fn parse_chat_completions() {
        assert_eq!(
            parse_endpoint("/v1/chat/completions"),
            AiEndpoint::ChatCompletions
        );
    }

    #[test]
    fn parse_embeddings() {
        assert_eq!(parse_endpoint("/v1/embeddings"), AiEndpoint::Embeddings);
    }

    #[test]
    fn parse_reranking_both_paths() {
        assert_eq!(parse_endpoint("/v1/rerank"), AiEndpoint::Reranking);
        assert_eq!(parse_endpoint("/v1/reranking"), AiEndpoint::Reranking);
    }

    #[test]
    fn parse_image_generation() {
        assert_eq!(
            parse_endpoint("/v1/images/generations"),
            AiEndpoint::ImageGeneration
        );
    }

    #[test]
    fn parse_audio_transcription() {
        assert_eq!(
            parse_endpoint("/v1/audio/transcriptions"),
            AiEndpoint::AudioTranscription
        );
    }

    #[test]
    fn parse_audio_speech() {
        assert_eq!(parse_endpoint("/v1/audio/speech"), AiEndpoint::AudioSpeech);
    }

    #[test]
    fn parse_moderations() {
        assert_eq!(parse_endpoint("/v1/moderations"), AiEndpoint::Moderations);
    }

    #[test]
    fn parse_models() {
        assert_eq!(parse_endpoint("/v1/models"), AiEndpoint::Models);
    }

    #[test]
    fn parse_unknown_path() {
        assert_eq!(
            parse_endpoint("/v1/fine-tuning/jobs"),
            AiEndpoint::Unknown("/v1/fine-tuning/jobs".to_string())
        );
        assert_eq!(
            parse_endpoint("/unknown"),
            AiEndpoint::Unknown("/unknown".to_string())
        );
    }

    #[test]
    fn parse_strips_query_string() {
        assert_eq!(
            parse_endpoint("/v1/chat/completions?stream=true"),
            AiEndpoint::ChatCompletions
        );
    }

    // --- provider_supports_endpoint tests ---

    #[test]
    fn all_providers_support_chat_completions() {
        for provider in &[
            "openai",
            "anthropic",
            "gemini",
            "cohere",
            "unknown-provider",
        ] {
            assert!(
                provider_supports_endpoint(provider, &AiEndpoint::ChatCompletions),
                "{provider} should support chat completions"
            );
        }
    }

    #[test]
    fn all_providers_support_models() {
        for provider in &["openai", "anthropic", "gemini", "cohere", "custom"] {
            assert!(
                provider_supports_endpoint(provider, &AiEndpoint::Models),
                "{provider} should support models endpoint"
            );
        }
    }

    #[test]
    fn openai_supports_all_endpoints() {
        let endpoints = [
            AiEndpoint::ChatCompletions,
            AiEndpoint::Embeddings,
            AiEndpoint::Reranking,
            AiEndpoint::ImageGeneration,
            AiEndpoint::AudioTranscription,
            AiEndpoint::AudioSpeech,
            AiEndpoint::Moderations,
            AiEndpoint::Models,
        ];
        for endpoint in &endpoints {
            assert!(
                provider_supports_endpoint("openai", endpoint),
                "openai should support {endpoint:?}"
            );
        }
    }

    #[test]
    fn anthropic_does_not_support_embeddings() {
        assert!(!provider_supports_endpoint(
            "anthropic",
            &AiEndpoint::Embeddings
        ));
    }

    #[test]
    fn anthropic_does_not_support_image_generation() {
        assert!(!provider_supports_endpoint(
            "anthropic",
            &AiEndpoint::ImageGeneration
        ));
    }

    #[test]
    fn anthropic_supports_audio_and_moderations() {
        assert!(provider_supports_endpoint(
            "anthropic",
            &AiEndpoint::AudioTranscription
        ));
        assert!(provider_supports_endpoint(
            "anthropic",
            &AiEndpoint::AudioSpeech
        ));
        assert!(provider_supports_endpoint(
            "anthropic",
            &AiEndpoint::Moderations
        ));
        assert!(provider_supports_endpoint(
            "anthropic",
            &AiEndpoint::Reranking
        ));
    }

    #[test]
    fn gemini_supports_all_endpoints() {
        let endpoints = [
            AiEndpoint::ChatCompletions,
            AiEndpoint::Embeddings,
            AiEndpoint::Reranking,
            AiEndpoint::ImageGeneration,
            AiEndpoint::AudioTranscription,
            AiEndpoint::AudioSpeech,
            AiEndpoint::Moderations,
            AiEndpoint::Models,
        ];
        for endpoint in &endpoints {
            assert!(
                provider_supports_endpoint("gemini", endpoint),
                "gemini should support {endpoint:?}"
            );
        }
    }

    #[test]
    fn cohere_supports_embeddings_and_reranking() {
        assert!(provider_supports_endpoint(
            "cohere",
            &AiEndpoint::Embeddings
        ));
        assert!(provider_supports_endpoint("cohere", &AiEndpoint::Reranking));
    }

    #[test]
    fn cohere_does_not_support_image_or_audio() {
        assert!(!provider_supports_endpoint(
            "cohere",
            &AiEndpoint::ImageGeneration
        ));
        assert!(!provider_supports_endpoint(
            "cohere",
            &AiEndpoint::AudioTranscription
        ));
        assert!(!provider_supports_endpoint(
            "cohere",
            &AiEndpoint::AudioSpeech
        ));
        assert!(!provider_supports_endpoint(
            "cohere",
            &AiEndpoint::Moderations
        ));
    }

    #[test]
    fn unknown_provider_only_supports_chat_and_models() {
        assert!(provider_supports_endpoint(
            "mystery-ai",
            &AiEndpoint::ChatCompletions
        ));
        assert!(provider_supports_endpoint(
            "mystery-ai",
            &AiEndpoint::Models
        ));
        assert!(!provider_supports_endpoint(
            "mystery-ai",
            &AiEndpoint::Embeddings
        ));
        assert!(!provider_supports_endpoint(
            "mystery-ai",
            &AiEndpoint::ImageGeneration
        ));
    }
}
