//! Per-provider capability checks for AI surfaces.
//!
//! Path classification lives in [`crate::handler::classify_surface`],
//! which is what the dispatch path calls. This module answers the
//! second question only: given a classified surface, does this
//! provider expose it, or must the gateway return 501. Capability is
//! keyed on the provider type ([`crate::ProviderConfig::effective_provider_type`]),
//! never on the entry's display name (WOR-2485).

/// Check whether a provider entry supports the OpenAI Realtime API.
///
/// Convenience wrapper for the [`provider_supports_surface`] lookup
/// for the Realtime surface specifically; the dispatch path uses
/// this to decide whether to attempt a WebSocket upgrade or return
/// 501 immediately. Takes the whole [`crate::ProviderConfig`] so
/// every caller keys the lookup on
/// [`crate::ProviderConfig::effective_provider_type`] by construction
/// rather than by convention (WOR-2485).
///
/// The matrix answers on the entry's wire format, so today this is
/// true for every catalog entry with `format: openai` and not only for
/// the `openai` type itself. That is the gate, not an advertisement:
/// only OpenAI is documented to serve `/v1/realtime`, and
/// [`surface_capability_names`] is what decides whether a model
/// listing names the surface (WOR-2647).
pub fn provider_supports_realtime(provider: &crate::ProviderConfig) -> bool {
    provider_supports_surface(
        provider.effective_provider_type(),
        &crate::handler::AiSurface::Realtime,
    )
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
/// ## Key
///
/// The lookup keys on the provider TYPE: callers pass
/// [`crate::ProviderConfig::effective_provider_type`] (the explicit
/// `provider_type`, falling back to the entry `name` when no type is
/// configured), never the display name alone. An operator entry such
/// as `name: team-openai, provider_type: openai` carries the full
/// openai row. Keying on the display name silently demoted renamed
/// entries to the unknown-provider default and 501'd every
/// non-universal surface (WOR-2485). The column headers below are
/// therefore provider types, and `other` is any type absent from the
/// provider catalog.
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
///
/// ## This is a permission, not an advertisement
///
/// This table answers "will the gateway relay this shape", and for the
/// OpenAI wire format the honest answer is yes for every surface: the
/// path is passed through unchanged, and an operator whose entry is an
/// aggregator that does serve `/v1/images/generations` must not be
/// refused because the vendor's catalog row is silent about it. So the
/// row is wide on purpose, and a surface being `yes` here says nothing
/// about whether that specific vendor answers 200.
///
/// A model listing is a promise rather than a permission, so it may not
/// be derived from this table alone: [`surface_capability_names`]
/// intersects this answer with the catalog's per-vendor claims and
/// publishes only what both agree on. That keeps a published listing
/// from ever naming a surface this gate refuses, without turning "we
/// will forward it" into "this vendor serves it" (WOR-2647).
pub fn provider_supports_surface(provider_type: &str, surface: &crate::handler::AiSurface) -> bool {
    provider_supports_surface_with_format(
        provider_type,
        surface,
        crate::providers::get_provider_info(provider_type).map(|info| info.format),
    )
}

/// [`provider_supports_surface`] with the catalog lookup already done.
///
/// The public entry point resolves the entry's wire format on every
/// call, and that resolution allocates a lowercased key and clones a
/// whole `ProviderInfo`. A caller asking about one provider across many
/// surfaces (a model listing asks about twelve) resolves the format
/// once and comes in here, so the listing path pays one catalog lookup
/// per provider rather than one per surface (WOR-2647).
fn provider_supports_surface_with_format(
    provider_type: &str,
    surface: &crate::handler::AiSurface,
    format: Option<crate::providers::ProviderFormat>,
) -> bool {
    // Per-provider narrowings: the wire-format default would admit
    // more surfaces than the upstream actually exposes. Listed
    // ahead of the format dispatch so the narrowing is the first
    // signal a future maintainer sees. Each arm carries the reason
    // the upstream's surface set is narrower than the format's
    // default.
    use crate::handler::AiSurface;
    match (provider_type, surface) {
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
            // Unknown provider types (not in the catalog) get the
            // most-restrictive answer (chat + models only).
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

/// Whether a provider entry handles `surface`, consulting a served
/// model's modality (WOR-1908).
///
/// A locally served (`serve:`) provider is not in the provider catalog,
/// so [`provider_supports_surface`] falls to the unknown-provider default
/// (chat + models only) and would blanket-501 `/v1/embeddings` even when
/// the box is serving an embedder. This variant lifts that: when
/// `served_modality` is `Some`, the surfaces its task implies are also
/// handled (an embedder answers embeddings, a reranker answers
/// reranking, and so on). `None` (not a served provider, or an unknown
/// task) keeps the type-based default unchanged. Like every matrix
/// entry point this keys on
/// [`crate::ProviderConfig::effective_provider_type`], not the display
/// name, and takes the whole config entry so a caller cannot pass the
/// wrong string (WOR-2485).
pub fn provider_supports_surface_for_modality(
    provider: &crate::ProviderConfig,
    surface: &crate::handler::AiSurface,
    served_modality: Option<sbproxy_model_host::Modality>,
) -> bool {
    // The type-based matrix already covers the universal surfaces and any
    // real provider format; only widen it for a served non-chat task.
    provider_supports_surface(provider.effective_provider_type(), surface)
        || modality_serves_surface(served_modality, surface)
}

/// The one surface a served model's task answers, if any.
///
/// Split out because it is both a widening of the 501 gate and, for a
/// locally served provider, the only per-model claim we have: the box
/// is running that model, so "this entry serves embeddings" is a fact
/// rather than a guess. [`provider_supports_surface_for_modality`] and
/// [`surface_capability_names`] therefore read the same function, so
/// the surface a served embedder is given and the surface its listing
/// advertises cannot come apart (WOR-1908, WOR-2647).
fn modality_serves_surface(
    served_modality: Option<sbproxy_model_host::Modality>,
    surface: &crate::handler::AiSurface,
) -> bool {
    use crate::handler::AiSurface;
    use sbproxy_model_host::Modality;
    match served_modality {
        Some(Modality::Embedding) => matches!(surface, AiSurface::Embeddings),
        Some(Modality::Rerank) => matches!(surface, AiSurface::Reranking),
        Some(Modality::SpeechToText) => matches!(surface, AiSurface::AudioTranscription),
        Some(Modality::TextToSpeech) => matches!(surface, AiSurface::AudioSpeech),
        Some(Modality::Image) => matches!(surface, AiSurface::ImageGeneration),
        Some(Modality::Chat) | None => false,
    }
}

/// The modality of a locally served (`serve:`) provider, or `None` for
/// a provider that proxies an upstream (WOR-1908).
///
/// A served provider is not in the provider catalog, so the type-keyed
/// matrix falls to the unknown-provider default and would blanket-501 a
/// non-chat surface even while the box is serving an embedder. This is
/// the modality [`provider_supports_surface_for_modality`] widens on.
///
/// A served provider hosts one or more models; this reports the first
/// served model whose modality is not chat, so its surface becomes
/// legal. An explicit `modality:` on the serve entry wins, because it is
/// the only way to declare one for a raw `hf:` reference that has no
/// catalog entry; otherwise the certified built-in catalog entry's
/// modality answers. An operator's custom catalog is not consulted here,
/// so a model only they know keeps the chat-only default.
pub fn served_provider_modality(
    provider: &crate::ProviderConfig,
) -> Option<sbproxy_model_host::Modality> {
    let serve = provider.serve.as_ref()?;
    let catalog = builtin_model_catalog();
    serve
        .models
        .iter()
        .filter_map(|entry| {
            entry
                .modality
                .or_else(|| catalog.get(&entry.model).map(|model| model.modality))
        })
        .find(|modality| !modality.uses_kv_cache())
}

/// The certified built-in catalog, parsed once. Resolving a served
/// model's modality must not re-parse the embedded YAML per call.
fn builtin_model_catalog() -> &'static sbproxy_model_host::Catalog {
    static BUILTIN: std::sync::OnceLock<sbproxy_model_host::Catalog> = std::sync::OnceLock::new();
    BUILTIN.get_or_init(sbproxy_model_host::Catalog::builtin)
}

/// Whether a surface is a claim about a model or about the account
/// behind it.
///
/// The capability array hangs off a model entry, so it may only name
/// surfaces a caller reaches by naming that model. `models` lists the
/// account's models, and `files`, `batches`, `assistants`, `threads`,
/// and `fine_tuning` manage account-scoped resources; publishing those
/// per model would invite a caller to read them as per-model facts,
/// which is the same false-advertising failure this function exists to
/// prevent. `Unknown` is not a surface at all.
///
/// Exhaustive on purpose: a new [`crate::handler::AiSurface`] variant is
/// a compile error here rather than a quiet omission from every
/// listing.
fn surface_is_a_model_capability(surface: &crate::handler::AiSurface) -> bool {
    use crate::handler::AiSurface;
    match surface {
        AiSurface::ChatCompletions
        | AiSurface::Embeddings
        | AiSurface::Messages
        | AiSurface::Responses
        | AiSurface::Reranking
        | AiSurface::ImageGeneration
        | AiSurface::ImageEdits
        | AiSurface::ImageVariations
        | AiSurface::AudioTranscription
        | AiSurface::AudioSpeech
        | AiSurface::Moderations
        | AiSurface::Realtime => true,
        AiSurface::Models
        | AiSurface::Assistants
        | AiSurface::Threads
        | AiSurface::Batches
        | AiSurface::FineTuning
        | AiSurface::Files
        | AiSurface::Unknown => false,
    }
}

/// Whether the catalog carries a per-vendor reason to believe this
/// upstream exposes `surface` (WOR-2647).
///
/// The advertising floor. [`provider_supports_surface`] is a permission
/// keyed on the wire format, so it says yes to every surface for the 66
/// catalog entries with `format: openai`; that is right for a gate and
/// wrong for a promise. A listing built from the gate alone would tell
/// a `deepseek` caller that `audio_speech` and `image_generation` are
/// available, and DeepSeek has neither, so the refusal simply moves
/// from our 501 to the upstream's 404 on a request we invited.
///
/// So the listing publishes the intersection: a surface has to pass
/// this too, and this only says yes where something in the tree says
/// the vendor exposes it.
///
/// - Chat and its two native-shape shims come from `supports_chat`. The
///   gateway implements `/v1/messages` and `/v1/responses` itself on
///   top of chat for every wire format, so the only entries that cannot
///   answer them are the ones the catalog records as non-chat (voyage,
///   jina, mixedbread). An entry absent from the catalog keeps the
///   permissive default, matching the gate.
/// - `embeddings` comes from `supports_embeddings`.
/// - The catalog has no field for the rest, so the list below is the
///   `Providers (today)` column of the Supported endpoints table in
///   `docs/ai-gateway.md`, which is the shipped statement of who serves
///   what. Nothing else claims them.
///
/// Absence is not a refusal. An openai-format aggregator that really
/// does serve `/v1/images/generations` is still forwarded; the listing
/// just does not promise it on the vendor's behalf, because no evidence
/// in this tree backs the promise. Widening a row means adding the
/// evidence (a catalog field or a documented vendor) rather than
/// falling back on the format.
fn catalog_claims_surface(
    provider_type: &str,
    surface: &crate::handler::AiSurface,
    info: Option<&crate::providers::ProviderInfo>,
) -> bool {
    use crate::handler::AiSurface;
    match surface {
        AiSurface::ChatCompletions | AiSurface::Messages | AiSurface::Responses => {
            info.is_none_or(|info| info.supports_chat)
        }
        AiSurface::Embeddings => info.is_some_and(|info| info.supports_embeddings),
        // Cohere's `/v1/rerank`. OpenAI has no rerank endpoint, so the
        // openai row is deliberately absent here even though the gate
        // forwards the path.
        AiSurface::Reranking => provider_type == "cohere",
        AiSurface::ImageGeneration
        | AiSurface::ImageEdits
        | AiSurface::ImageVariations
        | AiSurface::AudioTranscription
        | AiSurface::AudioSpeech
        | AiSurface::Moderations
        | AiSurface::Realtime => provider_type == "openai",
        // Not per-model claims; `surface_is_a_model_capability` has
        // already dropped these, and saying no twice is cheaper than
        // relying on the caller's order.
        AiSurface::Models
        | AiSurface::Assistants
        | AiSurface::Threads
        | AiSurface::Batches
        | AiSurface::FineTuning
        | AiSurface::Files
        | AiSurface::Unknown => false,
    }
}

/// The capability names a model listing may publish for `provider`
/// (WOR-2647).
///
/// One source of truth for "what may a listing tell a caller about this
/// entry". Every surface in [`crate::handler::AiSurface::ALL`] that is a
/// per-model claim has to clear two bars, and is then labeled with
/// [`crate::handler::AiSurface::label`]:
///
/// 1. [`provider_supports_surface`], the matrix the dispatch path
///    consults before it answers 501. This is the ceiling, so a caller
///    who reads a listing and sends the request it describes can never
///    be refused by the gateway. It is what the provider catalog's
///    `supports_chat` / `supports_embeddings` booleans used to be
///    missing: they disagreed with the matrix on 43 of the 72 shipped
///    entries, and a bedrock listing advertised the `embeddings`
///    surface the request path answers with 501.
/// 2. `catalog_claims_surface` in this module, the per-vendor
///    evidence. This is the floor, so the listing does not read the
///    format-wide permission as a claim about a specific vendor and
///    invite a 404 instead.
///
/// A locally served (`serve:`) model clears both at once through
/// `modality_serves_surface`: the box is running that model, so its
/// task is the evidence.
///
/// The two bars can disagree, and which way they disagree is the point.
/// The listing is always a subset of the gate, never a superset, so
/// anything named is served and something served may go unnamed. The
/// catalog sweep in this module's tests pins that direction for every
/// shipped entry.
///
/// `streaming` is part of the vocabulary but is not an `AiSurface`. No
/// capability check anywhere refuses a `stream: true` request, so it
/// rides with `chat_completions`, narrowed by the catalog's
/// `supports_streaming` claim about the vendor the same way every other
/// name is.
///
/// Names come back sorted and deduplicated, so two listing surfaces
/// rendering the same provider produce byte-identical arrays.
///
/// Takes the whole config entry and resolves the served modality itself
/// via [`served_provider_modality`], so a caller cannot forget it and
/// quietly under-report a locally served embedder. The catalog is
/// looked up once for the whole entry rather than once per surface,
/// because this runs per provider on a per-request listing path.
pub fn surface_capability_names(provider: &crate::ProviderConfig) -> Vec<&'static str> {
    let provider_type = provider.effective_provider_type();
    let info = crate::providers::get_provider_info(provider_type);
    let format = info.as_ref().map(|info| info.format);
    let served_modality = served_provider_modality(provider);

    let mut names = std::collections::BTreeSet::new();
    for surface in &crate::handler::AiSurface::ALL {
        if !surface_is_a_model_capability(surface) {
            continue;
        }
        let advertisable = modality_serves_surface(served_modality, surface)
            || (provider_supports_surface_with_format(provider_type, surface, format)
                && catalog_claims_surface(provider_type, surface, info.as_ref()));
        if advertisable {
            names.insert(surface.label());
        }
    }
    if names.contains("chat_completions")
        && info.as_ref().is_none_or(|info| info.supports_streaming)
    {
        names.insert("streaming");
    }
    names.into_iter().collect()
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

    fn provider(json: serde_json::Value) -> crate::ProviderConfig {
        serde_json::from_value(json).expect("provider fixture")
    }

    #[test]
    fn served_modality_makes_a_non_chat_surface_legal() {
        use crate::handler::AiSurface;
        use sbproxy_model_host::Modality;
        let local_embedder = provider(serde_json::json!({"name": "local-embedder"}));
        let local_reranker = provider(serde_json::json!({"name": "local-reranker"}));
        let local_chat = provider(serde_json::json!({"name": "local-chat"}));
        // A served provider (unknown to the provider catalog) 501s
        // embeddings by its type alone.
        assert!(!provider_supports_surface_for_modality(
            &local_embedder,
            &AiSurface::Embeddings,
            None
        ));
        // Declaring the served modality lifts exactly its own surface.
        assert!(provider_supports_surface_for_modality(
            &local_embedder,
            &AiSurface::Embeddings,
            Some(Modality::Embedding)
        ));
        assert!(provider_supports_surface_for_modality(
            &local_reranker,
            &AiSurface::Reranking,
            Some(Modality::Rerank)
        ));
        // It does not over-widen: an embedder does not gain reranking.
        assert!(!provider_supports_surface_for_modality(
            &local_embedder,
            &AiSurface::Reranking,
            Some(Modality::Embedding)
        ));
        // A served chat model keeps the type-based default (no embeddings).
        assert!(!provider_supports_surface_for_modality(
            &local_chat,
            &AiSurface::Embeddings,
            Some(Modality::Chat)
        ));
        // Universal surfaces stay universal regardless of modality.
        assert!(provider_supports_surface_for_modality(
            &local_embedder,
            &AiSurface::ChatCompletions,
            Some(Modality::Embedding)
        ));
    }

    // WOR-2485: the config-taking wrappers key on the entry's effective
    // provider type, so a display name neither narrows nor widens the
    // answer.
    #[test]
    fn config_wrappers_key_on_the_effective_provider_type() {
        use crate::handler::AiSurface;
        let renamed_openai = provider(serde_json::json!({
            "name": "team-openai", "provider_type": "openai"
        }));
        assert!(provider_supports_realtime(&renamed_openai));
        assert!(provider_supports_surface_for_modality(
            &renamed_openai,
            &AiSurface::AudioTranscription,
            None
        ));
        // Without a type, the name IS the type key (the built-in
        // spelling keeps working).
        let plain_openai = provider(serde_json::json!({"name": "openai"}));
        assert!(provider_supports_realtime(&plain_openai));
        let plain_anthropic = provider(serde_json::json!({"name": "anthropic"}));
        assert!(!provider_supports_realtime(&plain_anthropic));
        // A renamed non-realtime type stays non-realtime.
        let renamed_anthropic = provider(serde_json::json!({
            "name": "team-claude", "provider_type": "anthropic"
        }));
        assert!(!provider_supports_realtime(&renamed_anthropic));
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
            for surface in &AiSurface::ALL {
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

        const ALL_FORMATS: [ProviderFormat; 5] = [
            ProviderFormat::OpenAi,
            ProviderFormat::Anthropic,
            ProviderFormat::Google,
            ProviderFormat::Bedrock,
            ProviderFormat::Custom,
        ];

        for format in ALL_FORMATS {
            for surface in &AiSurface::ALL {
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

    // --- WOR-2647: a listing is a subset of the enforcer ---

    fn typed_provider(provider_type: &str) -> crate::ProviderConfig {
        provider(serde_json::json!({
            "name": "entry",
            "provider_type": provider_type,
            "api_key": "test",
            "models": ["m"]
        }))
    }

    /// The invariant, over every entry in the shipped catalog: a caller
    /// who reads a listing and sends the request it describes is never
    /// refused by the gateway.
    ///
    /// Sweeping the catalog rather than a handful of names is the point:
    /// the booleans this replaced disagreed with the matrix on 43 of the
    /// 72 entries, and the two that got noticed (bedrock advertising an
    /// embeddings surface it 501s, vertex hiding one it serves) were the
    /// two somebody happened to read.
    ///
    /// One direction only. The matrix is a permission keyed on the wire
    /// format, so it says yes to every surface for 66 of the 72 entries;
    /// equality here would mean publishing `audio_speech` on a
    /// text-only vendor. The listing is the narrower of the two, and
    /// `an_openai_format_vendor_advertises_only_what_the_catalog_claims`
    /// pins that it really is narrower rather than trivially equal.
    #[test]
    fn no_catalog_provider_advertises_a_surface_the_enforcer_refuses() {
        use crate::handler::AiSurface;

        let catalog = crate::providers::list_providers();
        assert!(catalog.len() > 40, "catalog sweep is not empty");
        for provider_type in catalog {
            let entry = typed_provider(&provider_type);
            let names = surface_capability_names(&entry);
            assert!(
                !names.is_empty(),
                "{provider_type}: every catalog entry serves something"
            );
            let mut accounted = 0;
            for surface in &AiSurface::ALL {
                if !names.contains(&surface.label()) {
                    continue;
                }
                assert!(
                    surface_is_a_model_capability(surface),
                    "{provider_type} / {surface:?}: not a per-model claim"
                );
                assert!(
                    provider_supports_surface(&provider_type, surface),
                    "{provider_type} / {surface:?}: listing invites a 501"
                );
                accounted += 1;
            }
            // `streaming` is the only published name that is not a
            // surface label, so everything else has to have been
            // checked above.
            assert_eq!(
                names.len(),
                accounted + usize::from(names.contains(&"streaming")),
                "{provider_type}: published a name that is not a surface: {names:?}"
            );
        }
    }

    /// The two entries the ticket named, pinned by name so a regression
    /// reads as itself rather than as a sweep index.
    #[test]
    fn bedrock_hides_embeddings_and_vertex_publishes_them() {
        use crate::handler::AiSurface;

        // Bedrock's Titan embeddings need the native InvokeModel shape,
        // not the `/v1/embeddings` the gateway forwards, so the gate
        // refuses the surface and the listing must not name it. The
        // catalog's own `supports_embeddings: true` is a claim about
        // the vendor and is not enough on its own.
        assert!(!provider_supports_surface(
            "bedrock",
            &AiSurface::Embeddings
        ));
        assert!(!surface_capability_names(&typed_provider("bedrock")).contains(&"embeddings"));

        // Vertex's OpenAI-compatible endpoint does serve embeddings and
        // the gateway forwards them, so both halves say yes.
        assert!(provider_supports_surface("vertex", &AiSurface::Embeddings));
        assert!(surface_capability_names(&typed_provider("vertex")).contains(&"embeddings"));
    }

    /// The finding-3 regression: a text-only openai-format vendor must
    /// not inherit OpenAI's surface set just because it speaks OpenAI's
    /// wire format.
    ///
    /// Deriving the listing from the matrix alone published thirteen
    /// names for 64 of the 72 catalog entries, so a DeepSeek model
    /// listing offered `audio_speech`, `image_generation`, `realtime`
    /// and `embeddings`. The gateway does forward all four (that is the
    /// assertion at the bottom, and it is deliberate), so the caller was
    /// not 501'd; the request left the building and 404'd at
    /// `api.deepseek.com` instead, on a path our own listing named.
    #[test]
    fn an_openai_format_vendor_advertises_only_what_the_catalog_claims() {
        use crate::handler::AiSurface;

        let names = surface_capability_names(&typed_provider("deepseek"));
        assert_eq!(
            names,
            vec!["chat_completions", "messages", "responses", "streaming"],
            "deepseek serves chat and nothing else the catalog knows of"
        );

        // The gate stays wide on purpose. Narrowing it would 501 an
        // openai-format aggregator that really does serve the surface,
        // which is a worse failure than declining to advertise it.
        for surface in [
            AiSurface::AudioSpeech,
            AiSurface::ImageGeneration,
            AiSurface::Realtime,
            AiSurface::Embeddings,
        ] {
            assert!(
                provider_supports_surface("deepseek", &surface),
                "{surface:?}: the 501 gate is a permission, not an advertisement"
            );
        }
    }

    /// The sharpest case in the finding: an embeddings-only vendor.
    ///
    /// Voyage and Jina carry `supports_chat: false` because they have no
    /// chat endpoint at all. Reading the format-wide matrix as an
    /// advertisement gave them the full thirteen names, starting with
    /// `chat_completions`.
    ///
    /// Mixedbread used to belong here and no longer does: the catalog
    /// refresh found its current API reference documents an
    /// OpenAI-shaped `/v1/chat/completions`, so it is deliberately not
    /// in this list. Keep this loop to vendors whose catalog entry says
    /// `supports_chat: false`, and check that before adding one.
    #[test]
    fn an_embeddings_only_vendor_advertises_only_embeddings() {
        for provider_type in ["voyage", "jina"] {
            let info = crate::providers::get_provider_info(provider_type).expect("catalog entry");
            assert!(!info.supports_chat, "{provider_type} has no chat endpoint");
            // `streaming` rides with chat and is narrowed by the same
            // catalog claim, so a listing cannot pick it up here either.
            assert!(!info.supports_streaming);
            assert_eq!(
                surface_capability_names(&typed_provider(provider_type)),
                vec!["embeddings"],
                "{provider_type} serves embeddings and nothing else"
            );
        }
    }

    /// An account-scoped surface is not a per-model capability, and
    /// neither is an unclassified path. Publishing `files` or `unknown`
    /// on a model entry would invite exactly the misreading this whole
    /// change exists to stop.
    #[test]
    fn capability_names_exclude_account_scoped_surfaces_and_unknown() {
        // openai is the widest row in the matrix: if a name is ever
        // going to leak, it leaks here.
        let names = surface_capability_names(&typed_provider("openai"));
        for excluded in [
            "models",
            "assistants",
            "threads",
            "batches",
            "fine_tuning",
            "files",
            "unknown",
        ] {
            assert!(
                !names.contains(&excluded),
                "{excluded} is not a per-model capability: {names:?}"
            );
        }
        // No `reranking`: OpenAI has no rerank endpoint, so the row is
        // absent from the catalog claims even though the openai-format
        // gate forwards the path.
        assert_eq!(
            names,
            vec![
                "audio_speech",
                "audio_transcription",
                "chat_completions",
                "embeddings",
                "image_edits",
                "image_generation",
                "image_variations",
                "messages",
                "moderations",
                "realtime",
                "responses",
                "streaming",
            ]
        );
    }

    /// `streaming` is not an `AiSurface`; it rides with chat, which the
    /// gateway serves for every wire format. An anthropic entry gets it
    /// without getting any of the openai-only surfaces.
    ///
    /// The literal is written in wire order, so it is also the check
    /// that names come back sorted: a `BTreeSet` compared against its
    /// own sorted copy cannot fail for any input.
    #[test]
    fn streaming_rides_with_chat_and_names_come_back_sorted() {
        assert_eq!(
            surface_capability_names(&typed_provider("anthropic")),
            vec!["chat_completions", "messages", "responses", "streaming"]
        );
        // Cohere reranks, and is the one entry that does, so the name
        // lands in the middle of the sorted array rather than at an end.
        assert_eq!(
            surface_capability_names(&typed_provider("cohere")),
            vec![
                "chat_completions",
                "embeddings",
                "messages",
                "reranking",
                "responses",
                "streaming"
            ]
        );
    }

    /// WOR-1908 through the listing: a locally served embedder is not in
    /// the provider catalog, so the type-keyed matrix alone would hide
    /// the one surface it exists to answer.
    #[test]
    fn a_served_embedder_publishes_the_embeddings_surface() {
        let embedder = provider(serde_json::json!({
            "name": "local-embedder",
            "models": ["e5"],
            "serve": {
                "models": [{
                    "model": "hf:intfloat/e5-large-v2",
                    "name": "e5",
                    "modality": "embedding"
                }]
            }
        }));
        assert_eq!(
            served_provider_modality(&embedder),
            Some(sbproxy_model_host::Modality::Embedding)
        );
        // The served task is the per-vendor evidence: the box is
        // running that model, so `embeddings` clears the advertising
        // floor even though no catalog entry names this provider.
        assert_eq!(
            surface_capability_names(&embedder),
            vec![
                "chat_completions",
                "embeddings",
                "messages",
                "responses",
                "streaming"
            ]
        );

        // A provider that proxies an upstream has no served modality,
        // and an unknown type keeps the restrictive default.
        let proxied = provider(serde_json::json!({"name": "mystery", "api_key": "k"}));
        assert_eq!(served_provider_modality(&proxied), None);
        assert_eq!(
            surface_capability_names(&proxied),
            vec!["chat_completions", "messages", "responses", "streaming"]
        );
    }
}
