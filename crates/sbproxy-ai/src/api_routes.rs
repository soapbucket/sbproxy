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
/// Provider capability matrix, grounded in the actual provider APIs as of
/// 2026-05:
/// - All providers support `ChatCompletions` and `Models`.
/// - OpenAI supports all endpoints.
/// - Anthropic supports only chat completions and models. The older
///   variant of this matrix claimed Anthropic supported audio,
///   reranking, and moderations; the production Anthropic API has none
///   of those.
/// - Gemini supports embeddings, image generation, audio (transcription
///   and speech via the Gemini API), and reranking. Gemini does not
///   support OpenAI's moderation endpoint shape.
/// - Vertex matches Gemini support (same underlying Google API family).
/// - Bedrock supports only chat completions and models. Bedrock has
///   embeddings via Titan but they require the legacy `InvokeModel`
///   shape, not the OpenAI `/v1/embeddings` shape, so they're not
///   listed here.
/// - Cohere supports embeddings and reranking (plus chat/models).
/// - Unknown providers: only chat completions and models.
pub fn provider_supports_endpoint(provider: &str, endpoint: &AiEndpoint) -> bool {
    match (provider, endpoint) {
        // Universal: all providers support chat and models.
        (_, AiEndpoint::ChatCompletions) => true,
        (_, AiEndpoint::Models) => true,

        // OpenAI: supports everything.
        ("openai", _) => true,

        // Anthropic: only chat + models. Everything else is unsupported.
        ("anthropic", _) => false,

        // Gemini and Vertex: embeddings, image, audio, reranking. No
        // moderations (OpenAI shape); use Gemini's separate safety API
        // instead. Vertex AI exposes the same Generative Language
        // surface so its capability matrix mirrors Gemini's.
        ("gemini" | "vertex", AiEndpoint::Embeddings) => true,
        ("gemini" | "vertex", AiEndpoint::ImageGeneration) => true,
        ("gemini" | "vertex", AiEndpoint::AudioTranscription) => true,
        ("gemini" | "vertex", AiEndpoint::AudioSpeech) => true,
        ("gemini" | "vertex", AiEndpoint::Reranking) => true,
        ("gemini" | "vertex", _) => false,

        // Bedrock: chat + models (above). No OpenAI-shape embeddings,
        // image generation, audio, reranking, or moderations.
        ("bedrock", _) => false,

        // Cohere: only embeddings and reranking (plus chat/models covered above).
        ("cohere", AiEndpoint::Embeddings) => true,
        ("cohere", AiEndpoint::Reranking) => true,
        ("cohere", _) => false,

        // Unknown providers: only chat completions and models (covered above).
        _ => false,
    }
}

/// Check whether a provider supports the OpenAI Realtime API.
///
/// Convenience wrapper for the [`provider_supports_surface`] lookup
/// for the Realtime surface specifically; the dispatch path uses
/// this to decide whether to attempt a WebSocket upgrade or return
/// 501 immediately. Today the matrix returns true only for `openai`.
pub fn provider_supports_realtime(provider: &str) -> bool {
    provider_supports_surface(provider, &crate::handler::AiSurface::Realtime)
}

/// Check whether a provider supports a given AI surface.
///
/// Surface-level analogue of [`provider_supports_endpoint`]. Covers the
/// stateful and WebSocket surfaces (assistants, threads, batches,
/// fine-tuning, files, realtime) that the older [`AiEndpoint`] enum
/// did not model.
///
/// The dispatch path uses this matrix to decide whether to return 501
/// Not Implemented before any upstream call is made.
pub fn provider_supports_surface(provider: &str, surface: &crate::handler::AiSurface) -> bool {
    use crate::handler::AiSurface;
    match (provider, surface) {
        // Universal: chat + models. Messages and Responses are
        // native-format inbound shims (WOR-224) that translate down to
        // the same hub shape as chat completions, so every
        // chat-capable provider supports them.
        (_, AiSurface::ChatCompletions) => true,
        (_, AiSurface::Models) => true,
        (_, AiSurface::Messages) => true,
        (_, AiSurface::Responses) => true,

        // OpenAI supports every shipped surface in this enum.
        ("openai", _) => true,

        // Anthropic: only chat + models (above). Everything else is false.
        ("anthropic", _) => false,

        // Gemini and Vertex: embeddings, image generation, audio,
        // reranking. No assistants, threads, batches, fine_tuning
        // (Gemini has fine-tuning but at a different path; not the
        // OpenAI shape), files in the OpenAI sense, realtime, image
        // edits/variations, moderations. Vertex AI sits on the same
        // Google API family so its surface matrix mirrors Gemini.
        ("gemini" | "vertex", AiSurface::Embeddings) => true,
        ("gemini" | "vertex", AiSurface::ImageGeneration) => true,
        ("gemini" | "vertex", AiSurface::AudioTranscription) => true,
        ("gemini" | "vertex", AiSurface::AudioSpeech) => true,
        ("gemini" | "vertex", AiSurface::Reranking) => true,
        ("gemini" | "vertex", _) => false,

        // Bedrock: chat + models only (above). The other OpenAI
        // surfaces don't map onto Bedrock's API family.
        ("bedrock", _) => false,

        // Cohere: embeddings and reranking (plus chat/models above).
        ("cohere", AiSurface::Embeddings) => true,
        ("cohere", AiSurface::Reranking) => true,
        ("cohere", _) => false,

        // Unknown providers: chat + models only.
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
    fn anthropic_supports_only_chat_and_models() {
        // The Anthropic API does not expose OpenAI-shape audio,
        // reranking, or moderations endpoints. Earlier versions of this
        // matrix claimed it did; the matrix has been corrected to
        // match the actual provider surface.
        assert!(provider_supports_endpoint(
            "anthropic",
            &AiEndpoint::ChatCompletions
        ));
        assert!(provider_supports_endpoint("anthropic", &AiEndpoint::Models));
        for endpoint in &[
            AiEndpoint::Embeddings,
            AiEndpoint::Reranking,
            AiEndpoint::ImageGeneration,
            AiEndpoint::AudioTranscription,
            AiEndpoint::AudioSpeech,
            AiEndpoint::Moderations,
        ] {
            assert!(
                !provider_supports_endpoint("anthropic", endpoint),
                "anthropic should not advertise support for {endpoint:?}"
            );
        }
    }

    #[test]
    fn gemini_supports_correct_endpoints() {
        // Gemini supports embeddings, image generation, audio
        // transcription, audio speech, and reranking on top of the
        // universal chat/models. It does not support OpenAI's
        // moderation endpoint shape; the operator should use Gemini's
        // separate safety API instead.
        for endpoint in &[
            AiEndpoint::ChatCompletions,
            AiEndpoint::Models,
            AiEndpoint::Embeddings,
            AiEndpoint::ImageGeneration,
            AiEndpoint::AudioTranscription,
            AiEndpoint::AudioSpeech,
            AiEndpoint::Reranking,
        ] {
            assert!(
                provider_supports_endpoint("gemini", endpoint),
                "gemini should support {endpoint:?}"
            );
        }
        assert!(!provider_supports_endpoint(
            "gemini",
            &AiEndpoint::Moderations
        ));
    }

    #[test]
    fn vertex_matches_gemini_support() {
        // Vertex AI rides on the same Google generative API family, so
        // its support matrix must match Gemini's.
        for endpoint in &[
            AiEndpoint::ChatCompletions,
            AiEndpoint::Models,
            AiEndpoint::Embeddings,
            AiEndpoint::ImageGeneration,
            AiEndpoint::AudioTranscription,
            AiEndpoint::AudioSpeech,
            AiEndpoint::Reranking,
        ] {
            assert!(
                provider_supports_endpoint("vertex", endpoint),
                "vertex should support {endpoint:?}"
            );
        }
        assert!(!provider_supports_endpoint(
            "vertex",
            &AiEndpoint::Moderations
        ));
    }

    #[test]
    fn bedrock_only_supports_chat_and_models() {
        // Bedrock has embeddings via Titan but they're served behind
        // the legacy InvokeModel shape, not OpenAI's /v1/embeddings,
        // so the OpenAI surface matrix lists only chat + models.
        assert!(provider_supports_endpoint(
            "bedrock",
            &AiEndpoint::ChatCompletions
        ));
        assert!(provider_supports_endpoint("bedrock", &AiEndpoint::Models));
        for endpoint in &[
            AiEndpoint::Embeddings,
            AiEndpoint::Reranking,
            AiEndpoint::ImageGeneration,
            AiEndpoint::AudioTranscription,
            AiEndpoint::AudioSpeech,
            AiEndpoint::Moderations,
        ] {
            assert!(
                !provider_supports_endpoint("bedrock", endpoint),
                "bedrock should not advertise support for {endpoint:?}"
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

    // --- provider_supports_surface coverage ---

    #[test]
    fn surface_matrix_universal_chat_and_models() {
        use crate::handler::AiSurface;
        for provider in &[
            "openai",
            "anthropic",
            "gemini",
            "cohere",
            "unknown-provider",
        ] {
            assert!(
                provider_supports_surface(provider, &AiSurface::ChatCompletions),
                "{provider} should support chat completions"
            );
            assert!(
                provider_supports_surface(provider, &AiSurface::Models),
                "{provider} should support models"
            );
        }
    }

    #[test]
    fn surface_matrix_openai_supports_all_shipped_surfaces() {
        use crate::handler::AiSurface;
        for surface in &[
            AiSurface::ChatCompletions,
            AiSurface::Models,
            AiSurface::Embeddings,
            AiSurface::Assistants,
            AiSurface::Threads,
            AiSurface::Batches,
            AiSurface::FineTuning,
            AiSurface::Files,
            AiSurface::Realtime,
            AiSurface::ImageGeneration,
            AiSurface::ImageEdits,
            AiSurface::ImageVariations,
            AiSurface::AudioTranscription,
            AiSurface::AudioSpeech,
            AiSurface::Moderations,
            AiSurface::Reranking,
        ] {
            assert!(
                provider_supports_surface("openai", surface),
                "openai should support {surface:?}"
            );
        }
    }

    #[test]
    fn surface_matrix_anthropic_only_chat_models() {
        use crate::handler::AiSurface;
        for surface in &[
            AiSurface::Embeddings,
            AiSurface::Assistants,
            AiSurface::Threads,
            AiSurface::Batches,
            AiSurface::FineTuning,
            AiSurface::Realtime,
            AiSurface::ImageGeneration,
            AiSurface::AudioTranscription,
            AiSurface::Moderations,
            AiSurface::Reranking,
        ] {
            assert!(
                !provider_supports_surface("anthropic", surface),
                "anthropic should not advertise support for {surface:?}"
            );
        }
    }

    #[test]
    fn surface_matrix_gemini_supports_correct_subset() {
        use crate::handler::AiSurface;
        // True for these:
        for surface in &[
            AiSurface::Embeddings,
            AiSurface::ImageGeneration,
            AiSurface::AudioTranscription,
            AiSurface::AudioSpeech,
            AiSurface::Reranking,
        ] {
            assert!(
                provider_supports_surface("gemini", surface),
                "gemini should support {surface:?}"
            );
        }
        // False for these:
        for surface in &[
            AiSurface::Assistants,
            AiSurface::Threads,
            AiSurface::Batches,
            AiSurface::FineTuning,
            AiSurface::Realtime,
            AiSurface::Moderations,
        ] {
            assert!(
                !provider_supports_surface("gemini", surface),
                "gemini should not advertise support for {surface:?}"
            );
        }
    }

    #[test]
    fn surface_matrix_vertex_matches_gemini() {
        use crate::handler::AiSurface;
        for surface in &[
            AiSurface::ChatCompletions,
            AiSurface::Models,
            AiSurface::Embeddings,
            AiSurface::ImageGeneration,
            AiSurface::AudioTranscription,
            AiSurface::AudioSpeech,
            AiSurface::Reranking,
        ] {
            assert!(
                provider_supports_surface("vertex", surface),
                "vertex should support {surface:?}"
            );
        }
        for surface in &[
            AiSurface::Assistants,
            AiSurface::Threads,
            AiSurface::Batches,
            AiSurface::FineTuning,
            AiSurface::Realtime,
            AiSurface::Moderations,
        ] {
            assert!(
                !provider_supports_surface("vertex", surface),
                "vertex should not advertise support for {surface:?}"
            );
        }
    }

    #[test]
    fn surface_matrix_bedrock_only_chat_models() {
        use crate::handler::AiSurface;
        assert!(provider_supports_surface(
            "bedrock",
            &AiSurface::ChatCompletions
        ));
        assert!(provider_supports_surface("bedrock", &AiSurface::Models));
        for surface in &[
            AiSurface::Assistants,
            AiSurface::Threads,
            AiSurface::Batches,
            AiSurface::FineTuning,
            AiSurface::Embeddings,
            AiSurface::ImageGeneration,
            AiSurface::AudioTranscription,
            AiSurface::AudioSpeech,
            AiSurface::Reranking,
            AiSurface::Realtime,
            AiSurface::Moderations,
        ] {
            assert!(
                !provider_supports_surface("bedrock", surface),
                "bedrock should not advertise support for {surface:?}"
            );
        }
    }

    #[test]
    fn surface_matrix_cohere_only_embeddings_reranking() {
        use crate::handler::AiSurface;
        assert!(provider_supports_surface("cohere", &AiSurface::Embeddings));
        assert!(provider_supports_surface("cohere", &AiSurface::Reranking));
        for surface in &[
            AiSurface::Assistants,
            AiSurface::Threads,
            AiSurface::Batches,
            AiSurface::ImageGeneration,
            AiSurface::AudioSpeech,
            AiSurface::Moderations,
        ] {
            assert!(
                !provider_supports_surface("cohere", surface),
                "cohere should not advertise support for {surface:?}"
            );
        }
    }
}
