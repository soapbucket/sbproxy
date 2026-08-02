//! Per-provider capability checks for AI surfaces.
//!
//! Path classification lives in [`crate::handler::classify_surface`],
//! which is what the dispatch path calls. This module answers the
//! second question only: given a classified surface, does this
//! provider expose it, or must the gateway return 501.

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
/// The one capability matrix. It covers the stateful and WebSocket
/// surfaces (assistants, threads, batches, fine-tuning, files,
/// realtime) as well as the request-shaped ones, keyed on the same
/// [`crate::handler::AiSurface`] the dispatch path classifies with, so
/// a surface cannot be recognised by one half and unknown to the other.
///
/// The dispatch path uses this matrix to decide whether to return 501
/// Not Implemented before any upstream call is made.
///
/// ## Contract matrix
///
/// | surface | openai | anthropic | gemini | vertex | bedrock | cohere | other |
/// |---|---|---|---|---|---|---|---|
/// | chat, models, messages, responses | yes | yes | yes | yes | yes | yes | yes |
/// | embeddings | yes | no | yes | yes | no | yes | no |
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
/// | `models` | `GET /v1/models` and `GET /models` return SBproxy's OpenAI-compatible, topology-free logical model aggregate for every AI origin. Ordinary provider discovery endpoints are not called. See `docs/ai-gateway.md`. |
/// | everything else | passthrough on the providers that support the OpenAI shape (openai, vertex, cohere where applicable); unsupported elsewhere |
///
/// Native provider model-list passthrough is deliberately absent because the
/// OpenAI, Anthropic, and Google shapes diverge enough that a lossy
/// normalisation would mislead callers. The gateway instead lists only the
/// public logical names it is configured to serve and adds bounded aggregate
/// availability for managed deployments without exposing topology.
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

/// Whether a provider handles `surface`, consulting a served model's
/// modality (WOR-1908).
///
/// A locally served (`serve:`) provider is not in the provider catalog,
/// so [`provider_supports_surface`] falls to the unknown-provider default
/// (chat + models only) and would blanket-501 `/v1/embeddings` even when
/// the box is serving an embedder. This variant lifts that: when
/// `served_modality` is `Some`, the surfaces its task implies are also
/// handled (an embedder answers embeddings, a reranker answers
/// reranking, and so on). `None` (not a served provider, or an unknown
/// task) keeps the name-based default unchanged.
pub fn provider_supports_surface_for_modality(
    provider: &str,
    surface: &crate::handler::AiSurface,
    served_modality: Option<sbproxy_model_host::Modality>,
) -> bool {
    use crate::handler::AiSurface;
    use sbproxy_model_host::Modality;
    // The name-based matrix already covers the universal surfaces and any
    // real provider format; only widen it for a served non-chat task.
    if provider_supports_surface(provider, surface) {
        return true;
    }
    match served_modality {
        Some(Modality::Embedding) => matches!(surface, AiSurface::Embeddings),
        Some(Modality::Rerank) => matches!(surface, AiSurface::Reranking),
        Some(Modality::SpeechToText) => matches!(surface, AiSurface::AudioTranscription),
        Some(Modality::TextToSpeech) => matches!(surface, AiSurface::AudioSpeech),
        Some(Modality::Image) => matches!(surface, AiSurface::ImageGeneration),
        Some(Modality::Chat) | None => false,
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

        // WOR-824 item 2: Google embeddings translated via the
        // `gemini_embeddings` sub-translator
        // (`embedContent` / `batchEmbedContents`). Other Google
        // non-chat surfaces (image, audio, reranking) are
        // out-of-scope here because they live in separate Google
        // Cloud services (Imagen, Speech-to-Text, Text-to-Speech,
        // Vertex Ranking) rather than the Gemini API surface.
        ProviderFormat::Google if matches!(surface, AiSurface::Embeddings) => true,

        // Anthropic, Google (everything else), Bedrock, Custom:
        // only universal (chat / models / messages / responses)
        // above.
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

    #[test]
    fn served_modality_makes_a_non_chat_surface_legal() {
        use crate::handler::AiSurface;
        use sbproxy_model_host::Modality;
        // A served provider (unknown to the provider catalog) 501s
        // embeddings by name alone.
        assert!(!provider_supports_surface_for_modality(
            "local-embedder",
            &AiSurface::Embeddings,
            None
        ));
        // Declaring the served modality lifts exactly its own surface.
        assert!(provider_supports_surface_for_modality(
            "local-embedder",
            &AiSurface::Embeddings,
            Some(Modality::Embedding)
        ));
        assert!(provider_supports_surface_for_modality(
            "local-reranker",
            &AiSurface::Reranking,
            Some(Modality::Rerank)
        ));
        // It does not over-widen: an embedder does not gain reranking.
        assert!(!provider_supports_surface_for_modality(
            "local-embedder",
            &AiSurface::Reranking,
            Some(Modality::Embedding)
        ));
        // A served chat model keeps the name-based default (no embeddings).
        assert!(!provider_supports_surface_for_modality(
            "local-chat",
            &AiSurface::Embeddings,
            Some(Modality::Chat)
        ));
        // Universal surfaces stay universal regardless of modality.
        assert!(provider_supports_surface_for_modality(
            "local-embedder",
            &AiSurface::ChatCompletions,
            Some(Modality::Embedding)
        ));
    }

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
                // Gemini (Google wire format) gains Embeddings as of
                // WOR-824 item 2: the embeddings sub-translator
                // maps to the Gemini `embedContent` /
                // `batchEmbedContents` API.
                "gemini" => matches!(surface, Embeddings),
                // anthropic, bedrock, unknown: universal only.
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
                // WOR-824 item 2: Google embeddings is translated;
                // other non-chat Google surfaces (image, audio,
                // reranking) live in separate Google Cloud
                // services (Imagen, Speech, Vertex Ranking) and
                // are filed as their own follow-up tickets.
                ProviderFormat::Google => matches!(surface, Embeddings),
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

    // --- WOR-2225: one classifier, one matrix ---

    /// The retired `parse_endpoint` / `AiEndpoint` pair recognised nine
    /// path shapes and answered a second capability matrix for them.
    /// Nothing on the request path ever called either; dispatch has
    /// always classified with `classify_surface` and asked
    /// `provider_supports_surface`. This walks the retired parser's
    /// whole vocabulary through the surviving pair so the deletion is
    /// provably lossless, and so a later narrowing of `classify_surface`
    /// fails here instead of silently un-recognising a shape that used
    /// to have a name.
    ///
    /// The prefixed forms are the half the retired parser could not do
    /// at all: it matched literal strings, so `/api/v1/embeddings` was
    /// `Unknown` to it. Keeping them in the same list is the reminder
    /// that reviving it would have been a downgrade.
    #[test]
    fn every_shape_the_retired_endpoint_parser_named_still_classifies() {
        use crate::handler::{classify_surface, AiSurface};

        let vocabulary = [
            ("/v1/chat/completions", AiSurface::ChatCompletions),
            ("/v1/embeddings", AiSurface::Embeddings),
            ("/v1/rerank", AiSurface::Reranking),
            ("/v1/reranking", AiSurface::Reranking),
            ("/v1/images/generations", AiSurface::ImageGeneration),
            ("/v1/audio/transcriptions", AiSurface::AudioTranscription),
            ("/v1/audio/speech", AiSurface::AudioSpeech),
            ("/v1/moderations", AiSurface::Moderations),
            ("/v1/models", AiSurface::Models),
            // Query strings were the one normalisation the retired
            // parser did do; the live classifier must keep it.
            (
                "/v1/chat/completions?stream=true",
                AiSurface::ChatCompletions,
            ),
            // Prefixed and trailing-slash forms the retired parser
            // called `Unknown`.
            ("/api/v1/embeddings", AiSurface::Embeddings),
            ("/v1/moderations/", AiSurface::Moderations),
        ];

        for (path, expected) in vocabulary {
            assert_eq!(
                classify_surface("POST", path),
                expected,
                "{path} must classify as {expected:?}"
            );
        }

        // The retired matrix disagreed with the live one on Google:
        // it advertised image generation, audio, and reranking for
        // `gemini`, none of which has a Google translator. Wiring it
        // would have re-opened the verbatim-forward class the live
        // matrix exists to close, so pin the live answers.
        for surface in [
            AiSurface::ImageGeneration,
            AiSurface::AudioTranscription,
            AiSurface::AudioSpeech,
            AiSurface::Reranking,
        ] {
            assert!(
                !provider_supports_surface("gemini", &surface),
                "gemini must 501 {surface:?}; no Google translator exists"
            );
        }
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
        // Gemini is the Google wire format. Chat + the inbound shims
        // (Messages/Responses, which translate down to chat) work,
        // and models is universal. WOR-824 item 2 added the
        // embeddings translator, so Embeddings is also true now.
        for surface in &[
            AiSurface::ChatCompletions,
            AiSurface::Models,
            AiSurface::Messages,
            AiSurface::Responses,
            AiSurface::Embeddings, // WOR-824 item 2
        ] {
            assert!(
                provider_supports_surface("gemini", surface),
                "gemini should support {surface:?}"
            );
        }
        // WOR-752 Finding A: these still have no Google translator,
        // so the gateway must 501 rather than forward verbatim to a
        // path Gemini does not expose. Image generation (Imagen),
        // audio transcription / speech (Google Cloud Speech), and
        // reranking (Vertex Ranking) live in separate Google Cloud
        // services and are filed as their own follow-up tickets.
        for surface in &[
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
        // Finding A divergence: vertex (passthrough) advertises
        // image / audio / reranking that gemini (translated, no
        // translator for those surfaces) must not. Embeddings was
        // historically part of this divergence; WOR-824 item 2
        // added the Gemini embeddings translator, so both vertex
        // and gemini now advertise Embeddings (gemini via
        // translator, vertex via the OpenAI-compatible passthrough).
        assert!(provider_supports_surface("vertex", &AiSurface::Embeddings));
        assert!(provider_supports_surface("gemini", &AiSurface::Embeddings));
        assert!(provider_supports_surface(
            "vertex",
            &AiSurface::ImageGeneration
        ));
        assert!(!provider_supports_surface(
            "gemini",
            &AiSurface::ImageGeneration
        ));
        assert!(provider_supports_surface("vertex", &AiSurface::Reranking));
        assert!(!provider_supports_surface("gemini", &AiSurface::Reranking));
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
