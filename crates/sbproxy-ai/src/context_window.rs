//! Known context window sizes, by model name.
//!
//! This is a lookup table and nothing else. The compression pipeline
//! (`crate::compression::window_fit`) reads it to size a model's input
//! budget, and the summary lever reads it to bound the summarizer's own
//! input. Neither one asks this module what to do about an oversized
//! prompt; that decision belongs to the lever that is running.
//!
//! WOR-2309: this file used to carry an overflow decision layer too, a
//! `check_overflow` pair returning an `OverflowAction` of `Error`,
//! `FallbackToLarger`, or `Truncate`. Nothing ever called it, so it was
//! deleted rather than left to look like a feature. Both live actions
//! now have a real caller and a config surface: `Truncate` is the
//! `window_fit` compression lever, and `FallbackToLarger` is the
//! `context_window_fallbacks:` reroute (WOR-2556), whose pre-flight half
//! reads this table through
//! `crate::typed_fallbacks::preflight_context_window_reroute`.

/// Everything this process knows about one model's token limits
/// (WOR-2647).
///
/// Both fields are `None` for a model nothing knows. Absence means "not
/// known here", never "unlimited": a caller that substituted a default
/// would silently truncate a prompt that would have fit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ModelFacts {
    /// Maximum prompt tokens the model accepts.
    pub context_window: Option<u64>,
    /// Maximum completion tokens the model will generate.
    pub max_output_tokens: Option<u64>,
}

/// Resolve one model's token limits across both layers that hold them.
///
/// This is the single resolution the `ai.catalog` routing base data and
/// the `/v1/models` listing both call, so a policy and a client cannot
/// be told two different windows for one model.
///
/// The static table below is the first layer. The operator's rate card
/// (`rate_card:`, the LiteLLM
/// `model_prices_and_context_window.json`) is the second, and it is the
/// only source of `max_output_tokens` in this process: nothing built in
/// carries a completion cap. The static table wins on the context
/// window where both know a model, because it is the value the
/// compression pipeline already sizes prompts against and two answers
/// for one model is the divergence this function exists to prevent.
///
/// A model neither layer knows resolves to two `None`s, and every
/// caller omits the fields rather than guessing.
#[must_use]
pub fn model_facts(model: &str) -> ModelFacts {
    // The price layers match case-insensitively but the static table is
    // exact; fall back to the lowercase form so a mixed-case declared
    // model does not end up priced-but-windowless.
    let window =
        model_context_window(model).or_else(|| model_context_window(&model.to_ascii_lowercase()));
    let limits = crate::budget::catalog_token_limits(model);
    ModelFacts {
        context_window: window.or_else(|| limits.and_then(|limits| limits.max_input_tokens)),
        max_output_tokens: limits.and_then(|limits| limits.max_output_tokens),
    }
}

/// Return the known maximum context window (in tokens) for a model.
///
/// Returns `None` for an unlisted model. Callers treat that as "no budget
/// can be derived from the model name" rather than substituting a default,
/// because guessing low silently truncates a prompt that would have fit.
pub fn model_context_window(model: &str) -> Option<u64> {
    match model {
        // --- OpenAI ---
        "gpt-4o" | "gpt-4o-2024-08-06" | "gpt-4o-2024-05-13" => Some(128_000),
        "gpt-4o-mini" | "gpt-4o-mini-2024-07-18" => Some(128_000),
        "gpt-4-turbo" | "gpt-4-turbo-2024-04-09" | "gpt-4-turbo-preview" => Some(128_000),
        "gpt-4" | "gpt-4-0613" => Some(8_192),
        "gpt-4-32k" | "gpt-4-32k-0613" => Some(32_768),
        "gpt-3.5-turbo" | "gpt-3.5-turbo-0125" => Some(16_385),
        "gpt-3.5-turbo-16k" => Some(16_385),
        "o1" | "o1-2024-12-17" => Some(200_000),
        "o1-mini" | "o1-mini-2024-09-12" => Some(128_000),
        "o3" | "o3-mini" => Some(200_000),

        // --- Anthropic ---
        "claude-opus-4" | "claude-opus-4-5" | "claude-opus-4-20250514" => Some(200_000),
        "claude-sonnet-4-5" | "claude-sonnet-4-5-20250514" => Some(200_000),
        "claude-sonnet-4" | "claude-sonnet-4-20250514" => Some(200_000),
        "claude-haiku-3-5" | "claude-haiku-3-5-20241022" => Some(200_000),
        "claude-3-opus-20240229" => Some(200_000),
        "claude-3-sonnet-20240229" => Some(200_000),
        "claude-3-haiku-20240307" => Some(200_000),
        "claude-2" | "claude-2.1" => Some(200_000),
        "claude-instant-1.2" => Some(100_000),

        // --- Google Gemini ---
        "gemini-2.0-flash" | "gemini-2.0-flash-exp" => Some(1_000_000),
        "gemini-2.0-flash-lite" => Some(1_000_000),
        "gemini-1.5-flash" | "gemini-1.5-flash-002" => Some(1_000_000),
        "gemini-1.5-pro" | "gemini-1.5-pro-002" => Some(2_000_000),
        "gemini-1.0-pro" => Some(32_760),

        // --- Mistral ---
        "mistral-large-latest" | "mistral-large-2411" => Some(128_000),
        "mistral-small-latest" | "mistral-small-2409" => Some(128_000),
        "mistral-medium" => Some(32_000),
        "codestral-latest" => Some(256_000),

        // --- Meta Llama (via Groq/Together/Bedrock) ---
        "llama-3.1-405b-instruct" => Some(128_000),
        "llama-3.1-70b-instruct" => Some(128_000),
        "llama-3.1-8b-instruct" => Some(128_000),
        "llama-3-70b-instruct" => Some(8_192),
        "llama-3-8b-instruct" => Some(8_192),

        // Unknown model
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_openai_models_have_windows() {
        assert_eq!(model_context_window("gpt-4o"), Some(128_000));
        assert_eq!(model_context_window("gpt-4o-mini"), Some(128_000));
        assert_eq!(model_context_window("gpt-3.5-turbo"), Some(16_385));
        assert_eq!(model_context_window("gpt-4"), Some(8_192));
    }

    #[test]
    fn known_anthropic_models_have_windows() {
        assert_eq!(model_context_window("claude-sonnet-4-5"), Some(200_000));
        assert_eq!(model_context_window("claude-opus-4"), Some(200_000));
        assert_eq!(model_context_window("claude-haiku-3-5"), Some(200_000));
    }

    #[test]
    fn known_gemini_models_have_windows() {
        assert_eq!(model_context_window("gemini-2.0-flash"), Some(1_000_000));
        assert_eq!(model_context_window("gemini-1.5-pro"), Some(2_000_000));
    }

    #[test]
    fn unknown_model_returns_none() {
        assert!(model_context_window("made-up-model-v99").is_none());
        assert!(model_context_window("").is_none());
    }
}
