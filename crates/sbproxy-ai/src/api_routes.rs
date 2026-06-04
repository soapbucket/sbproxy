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
///
/// ## Contract matrix
///
/// | surface | openai | anthropic | gemini | vertex | bedrock | cohere | other |
/// |---|---|---|---|---|---|---|---|
/// | chat, models, messages, responses | yes | yes | yes | yes | yes | yes | yes |
/// | embeddings | yes | no | no | yes | no | yes | no |
/// | reranking | yes | no | no | yes | no | yes | no |
/// | image generation | yes | no | no | yes | no | no | no |
/// | audio transcription, audio speech | yes | no | no | yes | no | no | no |
/// | assistants, threads, batches, fine-tuning, files, moderations, realtime, image edits/variations | yes | no | no | no | no | no | no |
///
/// `yes` means the surface is handled: translated for chat on the Google
/// (gemini) format, passed through unchanged for OpenAI-compatible
/// formats (openai, vertex). `no` means the gateway returns 501 rather
/// than verbatim-forwarding a path the upstream does not expose (the
/// #240 / Finding A class). The exhaustive
/// `surface_matrix_matches_documented_contract` unit test enforces this
/// table in the required CI job; the e2e `ai_surface_matrix` suite is the
/// live-proxy complement.
///
/// ## Response shape contract
///
/// "Handled" does not imply "normalised". Per-surface translation state:
///
/// | surface | translation today |
/// |---|---|
/// | `chat_completions` | translated to / from the OpenAI shape on Anthropic and Google (gemini) formats; passthrough on OpenAI-compatible upstreams |
/// | `messages` / `responses` | native-format inbound shims that translate down to the same hub shape as chat |
/// | `models` | **passthrough only**: the response body is the upstream's native model-list shape, not normalised to the OpenAI `{"object": "list", "data": [...]}` envelope. Clients hitting a non-OpenAI provider via this surface MUST handle the upstream's shape directly. See `docs/ai-gateway.md` for the per-provider example. |
/// | everything else | passthrough on the providers that support the OpenAI shape (openai, vertex, cohere where applicable); unsupported elsewhere |
///
/// Documenting Models as passthrough-only is the deliberate close of
/// audit Finding C: response normalisation for the universal Models
/// surface is not implemented because the OpenAI / Anthropic / Google
/// model-list shapes diverge enough that a lossy normalisation would
/// mislead callers. Operators that need a unified shape should use a
/// dedicated discovery endpoint (the proxy's own model registry) rather
/// than the passthrough.
pub fn provider_supports_surface(provider: &str, surface: &crate::handler::AiSurface) -> bool {
    // Per-provider narrowings: the wire-format default would admit
    // more surfaces than the upstream actually exposes. Listed
    // ahead of the format dispatch so the narrowing is the first
    // signal a future maintainer sees. Each arm carries the reason
    // the upstream's surface set is narrower than the format's
    // default.
    use crate::handler::AiSurface;
    match (provider, surface) {
        // Bedrock has no chat-completions-shaped embeddings,
        // image, audio, reranking, or moderations endpoint.
        // Titan embeddings exist but require the legacy
        // InvokeModel shape, not the OpenAI /v1/embeddings shape.
        ("bedrock", AiSurface::Embeddings)
        | ("bedrock", AiSurface::ImageGeneration)
        | ("bedrock", AiSurface::ImageEdits)
        | ("bedrock", AiSurface::ImageVariations)
        | ("bedrock", AiSurface::AudioTranscription)
        | ("bedrock", AiSurface::AudioSpeech)
        | ("bedrock", AiSurface::Moderations)
        | ("bedrock", AiSurface::Reranking)
        | ("bedrock", AiSurface::Assistants)
        | ("bedrock", AiSurface::Threads)
        | ("bedrock", AiSurface::Batches)
        | ("bedrock", AiSurface::FineTuning)
        | ("bedrock", AiSurface::Files)
        | ("bedrock", AiSurface::Realtime) => false,

        // Cohere speaks the OpenAI wire shape but only exposes
        // embeddings + reranking (plus the universal chat/models).
        // Narrow the OpenAi-format default so an operator pointing
        // a CohereClient at /v1/images/generations gets a clean
        // 501 instead of a forwarded request the upstream 404s.
        ("cohere", AiSurface::ImageGeneration)
        | ("cohere", AiSurface::ImageEdits)
        | ("cohere", AiSurface::ImageVariations)
        | ("cohere", AiSurface::AudioTranscription)
        | ("cohere", AiSurface::AudioSpeech)
        | ("cohere", AiSurface::Moderations)
        | ("cohere", AiSurface::Assistants)
        | ("cohere", AiSurface::Threads)
        | ("cohere", AiSurface::Batches)
        | ("cohere", AiSurface::FineTuning)
        | ("cohere", AiSurface::Files)
        | ("cohere", AiSurface::Realtime)
        | ("cohere", AiSurface::Unknown) => false,

        // Vertex AI's OpenAI-compatible endpoint covers chat,
        // embeddings, image, audio, and reranking; it does NOT
        // expose the stateful surfaces (assistants, threads,
        // batches, fine-tuning, files), moderations, realtime, or
        // image edits/variations. Narrow the OpenAi-format default
        // so /v1/threads against vertex 501s cleanly instead of
        // 404ing at the upstream.
        ("vertex", AiSurface::Assistants)
        | ("vertex", AiSurface::Threads)
        | ("vertex", AiSurface::Batches)
        | ("vertex", AiSurface::FineTuning)
        | ("vertex", AiSurface::Files)
        | ("vertex", AiSurface::Realtime)
        | ("vertex", AiSurface::ImageEdits)
        | ("vertex", AiSurface::ImageVariations)
        | ("vertex", AiSurface::Moderations)
        | ("vertex", AiSurface::Unknown) => false,

        _ => {
            // Default path: dispatch on the provider's wire format.
            // Unknown providers (not in the catalog) get the
            // most-restrictive answer (chat + models only). The
            // catalog lookup is cached so this stays cheap.
            let format = crate::providers::get_provider_info(provider).map(|info| info.format);
            match format {
                Some(f) => provider_format_supports_surface(f, surface),
                None => matches!(
                    surface,
                    AiSurface::ChatCompletions
                        | AiSurface::Models
                        | AiSurface::Messages
                        | AiSurface::Responses
                ),
            }
        }
    }
}

/// WOR-824 item 3: per-wire-format capability matrix.
///
/// Surface support keyed on [`crate::providers::ProviderFormat`]
/// rather than the provider name string. Any catalog entry with `format: openai`
/// (today's openai, vertex, cohere, mistral, groq, deepseek,
/// ollama, vllm, together, fireworks, perplexity, xai, sagemaker,
/// oracle, watsonx, ...) inherits the OpenAI-format default. The
/// per-provider narrowing in [`provider_supports_surface`] is the
/// only place upstream-specific exceptions live.
///
/// ## Matrix
///
/// | surface | OpenAi | Anthropic | Google | Bedrock | Custom |
/// |---|---|---|---|---|---|
/// | chat, models, messages, responses | yes | yes | yes | yes | yes |
/// | embeddings | yes | no | no | no | no |
/// | reranking | yes | no | no | no | no |
/// | image generation / edits / variations | yes | no | no | no | no |
/// | audio transcription / speech | yes | no | no | no | no |
/// | moderations / assistants / threads / batches / fine-tuning / files / realtime | yes | no | no | no | no |
///
/// The `Google` row is currently `no` for everything beyond the
/// universal arm because no Google-format translator exists for
/// embeddings, image, audio, or reranking yet (WOR-824 item 2 will
/// flip those cells as each translator lands). The `Custom` row is
/// conservatively `no` so unknown shapes do not silently forward.
pub fn provider_format_supports_surface(
    format: crate::providers::ProviderFormat,
    surface: &crate::handler::AiSurface,
) -> bool {
    use crate::handler::AiSurface;
    use crate::providers::ProviderFormat;

    // Universal across every format: chat / models / messages /
    // responses. The matrix's `yes` row.
    if matches!(
        surface,
        AiSurface::ChatCompletions | AiSurface::Models | AiSurface::Messages | AiSurface::Responses
    ) {
        return true;
    }

    match format {
        // OpenAI wire format: every shipped surface passes through.
        // SageMaker / Oracle / Watsonx / any future catalog entry
        // with format: openai inherits this row.
        ProviderFormat::OpenAi => true,

        // Anthropic, Google, Bedrock, Custom: only universal
        // (chat / models / messages / responses) above.
        ProviderFormat::Anthropic
        | ProviderFormat::Google
        | ProviderFormat::Bedrock
        | ProviderFormat::Custom => false,
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    // --- WOR-752: full surface x provider contract matrix ---
    //
    // Locks the request-path contract in the required `build/test` gate
    // (the e2e `ai_surface_matrix` suite is the occasional live-proxy
    // complement). The `expected` helper matches every `AiSurface`
    // variant with no wildcard arm, so adding a surface fails to compile
    // here and forces a triage decision. The contract: a surface is
    // either universal (chat / models / messages / responses, supported
    // by every provider), passed through by an OpenAI-format provider, or
    // 501'd at the gateway. No cell verbatim-forwards an untranslatable
    // path to a provider that does not expose it (the #240 class).
    #[test]
    fn surface_matrix_matches_documented_contract() {
        use crate::handler::AiSurface::{self, *};

        fn expected(provider: &str, surface: &AiSurface) -> bool {
            // Exhaustive (no `_`): a new variant must be triaged here.
            let universal = match surface {
                ChatCompletions | Models | Messages | Responses => true,
                Embeddings | Assistants | Threads | Batches | FineTuning | Files | Realtime
                | ImageGeneration | ImageEdits | ImageVariations | AudioTranscription
                | AudioSpeech | Moderations | Reranking | Unknown => false,
            };
            if universal {
                return true;
            }
            match provider {
                // OpenAI wire format: every surface passes through.
                "openai" => true,
                // Vertex exposes an OpenAI-compatible endpoint (catalog
                // `format: openai`), so these pass through unchanged.
                "vertex" => matches!(
                    surface,
                    Embeddings | ImageGeneration | AudioTranscription | AudioSpeech | Reranking
                ),
                // Cohere: embeddings + reranking.
                "cohere" => matches!(surface, Embeddings | Reranking),
                // anthropic, gemini, bedrock, unknown: universal only.
                _ => false,
            }
        }

        const ALL_SURFACES: [AiSurface; 19] = [
            ChatCompletions,
            Models,
            Embeddings,
            Assistants,
            Threads,
            Batches,
            FineTuning,
            Files,
            Realtime,
            ImageGeneration,
            ImageEdits,
            ImageVariations,
            AudioTranscription,
            AudioSpeech,
            Moderations,
            Reranking,
            Messages,
            Responses,
            Unknown,
        ];
        let providers = [
            "openai",
            "anthropic",
            "gemini",
            "vertex",
            "bedrock",
            "cohere",
            "some-unknown-provider",
        ];

        for provider in providers {
            for surface in &ALL_SURFACES {
                assert_eq!(
                    provider_supports_surface(provider, surface),
                    expected(provider, surface),
                    "matrix mismatch: provider={provider} surface={surface:?}"
                );
            }
        }
    }

    // --- WOR-824 item 3: per-wire-format matrix ---

    /// Pins the per-wire-format default matrix
    /// `provider_format_supports_surface` exposes. Every
    /// catalog entry's format inherits this row by default;
    /// per-provider narrowings in `provider_supports_surface`
    /// are the only place upstream-specific exceptions live.
    ///
    /// Exhaustive (every format, every surface, no wildcard):
    /// adding a `ProviderFormat` variant or an `AiSurface`
    /// variant forces a triage decision here, preventing a
    /// quiet drift between the format matrix and the provider
    /// matrix.
    #[test]
    fn provider_format_matrix_matches_documented_contract() {
        use crate::handler::AiSurface::{self, *};
        use crate::providers::ProviderFormat;

        fn expected(format: ProviderFormat, surface: &AiSurface) -> bool {
            // Universal across every format: chat / models / messages / responses.
            let universal = match surface {
                ChatCompletions | Models | Messages | Responses => true,
                Embeddings | Assistants | Threads | Batches | FineTuning | Files | Realtime
                | ImageGeneration | ImageEdits | ImageVariations | AudioTranscription
                | AudioSpeech | Moderations | Reranking | Unknown => false,
            };
            if universal {
                return true;
            }
            match format {
                ProviderFormat::OpenAi => true,
                ProviderFormat::Anthropic => false,
                ProviderFormat::Google => false,
                ProviderFormat::Bedrock => false,
                ProviderFormat::Custom => false,
            }
        }

        const ALL_SURFACES: [AiSurface; 19] = [
            ChatCompletions,
            Models,
            Embeddings,
            Assistants,
            Threads,
            Batches,
            FineTuning,
            Files,
            Realtime,
            ImageGeneration,
            ImageEdits,
            ImageVariations,
            AudioTranscription,
            AudioSpeech,
            Moderations,
            Reranking,
            Messages,
            Responses,
            Unknown,
        ];
        const ALL_FORMATS: [ProviderFormat; 5] = [
            ProviderFormat::OpenAi,
            ProviderFormat::Anthropic,
            ProviderFormat::Google,
            ProviderFormat::Bedrock,
            ProviderFormat::Custom,
        ];

        for format in ALL_FORMATS {
            for surface in &ALL_SURFACES {
                assert_eq!(
                    provider_format_supports_surface(format, surface),
                    expected(format, surface),
                    "format matrix mismatch: format={format:?} surface={surface:?}"
                );
            }
        }
    }

    // --- WOR-824 Finding C: Models passthrough-only contract ---

    /// Pins the deliberate non-normalisation of the Models surface.
    ///
    /// The Models surface is universal (the matrix returns true for
    /// every provider) but the gateway does NOT translate the response
    /// body. This test exists so any future PR that adds a Models
    /// translator must update this test in lockstep with the rustdoc
    /// table and the operator doc. The check is documentary rather
    /// than functional: it asserts both halves (matrix support AND
    /// passthrough stance) sit together in one place, so the contract
    /// cannot drift unnoticed.
    #[test]
    fn models_surface_is_universal_and_passthrough_only() {
        use crate::handler::AiSurface;
        // Half 1: every wire-format provider supports the Models
        // surface (matrix says yes).
        for provider in [
            "openai",
            "anthropic",
            "gemini",
            "vertex",
            "bedrock",
            "cohere",
        ] {
            assert!(
                provider_supports_surface(provider, &AiSurface::Models),
                "Models surface MUST be universal; provider={provider}"
            );
        }
        // Half 2: the rustdoc on `provider_supports_surface` declares
        // Models passthrough-only. If a Models response-shape
        // translator ever lands, this assertion is the canary: the
        // PR adding the translator must update the rustdoc, the
        // operator doc, AND this test in lockstep so the contract
        // stays internally consistent.
        let rustdoc = include_str!("api_routes.rs");
        assert!(
            rustdoc.contains("`models` | **passthrough only**"),
            "Models passthrough-only stance must remain documented in the \
             `provider_supports_surface` rustdoc table; if the translator \
             lands, update the rustdoc + docs/ai-gateway.md together"
        );
    }

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
    fn surface_matrix_gemini_supports_only_translated_chat_surfaces() {
        use crate::handler::AiSurface;
        // Gemini is the Google wire format and only has a chat-completions
        // translator; chat + the inbound shims (Messages/Responses, which
        // translate down to chat) work, and models is universal.
        for surface in &[
            AiSurface::ChatCompletions,
            AiSurface::Models,
            AiSurface::Messages,
            AiSurface::Responses,
        ] {
            assert!(
                provider_supports_surface("gemini", surface),
                "gemini should support {surface:?}"
            );
        }
        // WOR-752 Finding A: these have no Google translator, so the
        // gateway must 501 rather than forward verbatim to a path Gemini
        // does not expose.
        for surface in &[
            AiSurface::Embeddings,
            AiSurface::ImageGeneration,
            AiSurface::AudioTranscription,
            AiSurface::AudioSpeech,
            AiSurface::Reranking,
            AiSurface::Assistants,
            AiSurface::Threads,
            AiSurface::Moderations,
        ] {
            assert!(
                !provider_supports_surface("gemini", surface),
                "gemini must not advertise {surface:?} without a translator (Finding A)"
            );
        }
    }

    #[test]
    fn surface_matrix_vertex_passthrough_diverges_from_gemini() {
        use crate::handler::AiSurface;
        // Vertex is OpenAI-format passthrough (catalog format: openai), so
        // it keeps the extra surfaces gemini (translated) cannot serve.
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
        // The Finding A divergence: vertex (passthrough) advertises
        // surfaces that gemini (translated, no translator) must not.
        assert!(provider_supports_surface("vertex", &AiSurface::Embeddings));
        assert!(!provider_supports_surface("gemini", &AiSurface::Embeddings));
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
