//! Context window overflow detection and handling.
//!
//! Detects when an estimated token count exceeds a model's context window
//! and recommends an appropriate action (error, fallback, or truncate).

/// Return the known maximum context window (in tokens) for a model.
///
/// Returns `None` for unknown models, which means overflow cannot be checked.
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

/// Action to take when context window overflow is detected.
#[derive(Debug, Clone, PartialEq)]
pub enum OverflowAction {
    /// Return an error to the client.
    Error,
    /// Try a model with a larger context window.
    FallbackToLarger(String),
    /// Truncate oldest messages to fit within the context window.
    Truncate,
}

/// Check if the estimated token count exceeds the model's context window.
///
/// Returns `Some(OverflowAction)` if overflow is detected, `None` if within limits.
///
/// Decision logic:
/// - If the model is unknown, returns `None` (cannot assess).
/// - If a `fallback_model` is provided and has a larger context window, returns `FallbackToLarger`.
/// - Otherwise returns `Error`.
pub fn check_overflow(
    model: &str,
    estimated_tokens: u64,
    fallback_model: Option<&str>,
) -> Option<OverflowAction> {
    let context_window = model_context_window(model)?;

    if estimated_tokens <= context_window {
        return None;
    }

    // Overflow detected - check if a fallback model was requested
    if let Some(fallback) = fallback_model {
        // Only use the fallback if it actually has a larger window
        if let Some(fallback_window) = model_context_window(fallback) {
            if fallback_window > context_window && estimated_tokens <= fallback_window {
                return Some(OverflowAction::FallbackToLarger(fallback.to_string()));
            }
        }
    }

    Some(OverflowAction::Error)
}

/// Check for overflow and recommend truncation as an alternative to erroring.
///
/// Same as `check_overflow` but returns `Truncate` instead of `Error`
/// when no suitable fallback is available.
pub fn check_overflow_with_truncate(
    model: &str,
    estimated_tokens: u64,
    fallback_model: Option<&str>,
) -> Option<OverflowAction> {
    let action = check_overflow(model, estimated_tokens, fallback_model)?;
    if action == OverflowAction::Error {
        Some(OverflowAction::Truncate)
    } else {
        Some(action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- model_context_window tests ---

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

    // --- check_overflow tests ---

    #[test]
    fn model_within_window_returns_none() {
        // gpt-4o has 128k context; 10k tokens is fine
        assert!(check_overflow("gpt-4o", 10_000, None).is_none());
    }

    #[test]
    fn model_at_exact_window_returns_none() {
        assert!(check_overflow("gpt-4o", 128_000, None).is_none());
    }

    #[test]
    fn model_over_window_returns_error() {
        // gpt-4o has 128k context; 200k tokens overflows
        assert_eq!(
            check_overflow("gpt-4o", 200_000, None),
            Some(OverflowAction::Error)
        );
    }

    #[test]
    fn fallback_model_returned_when_fits() {
        // gpt-3.5-turbo has 16k context; 50k tokens overflows
        // gpt-4o has 128k context - fits
        assert_eq!(
            check_overflow("gpt-3.5-turbo", 50_000, Some("gpt-4o")),
            Some(OverflowAction::FallbackToLarger("gpt-4o".to_string()))
        );
    }

    #[test]
    fn fallback_model_not_used_if_too_small() {
        // gpt-4o (128k) overflow with 200k tokens
        // Fallback is gpt-3.5-turbo (16k) - also too small
        assert_eq!(
            check_overflow("gpt-4o", 200_000, Some("gpt-3.5-turbo")),
            Some(OverflowAction::Error)
        );
    }

    #[test]
    fn unknown_model_returns_none_cannot_check() {
        assert!(check_overflow("unknown-model-xyz", 999_999, None).is_none());
    }

    #[test]
    fn unknown_fallback_falls_back_to_error() {
        // Known primary overflows, unknown fallback cannot be verified
        assert_eq!(
            check_overflow("gpt-3.5-turbo", 50_000, Some("unknown-model-xyz")),
            Some(OverflowAction::Error)
        );
    }

    #[test]
    fn truncate_action_from_check_overflow_with_truncate() {
        assert_eq!(
            check_overflow_with_truncate("gpt-4o", 200_000, None),
            Some(OverflowAction::Truncate)
        );
    }

    #[test]
    fn truncate_returns_none_when_within_window() {
        assert!(check_overflow_with_truncate("gpt-4o", 10_000, None).is_none());
    }

    #[test]
    fn truncate_prefers_fallback_over_truncate() {
        // Fallback fits -> return FallbackToLarger, not Truncate
        assert_eq!(
            check_overflow_with_truncate("gpt-3.5-turbo", 50_000, Some("gpt-4o")),
            Some(OverflowAction::FallbackToLarger("gpt-4o".to_string()))
        );
    }

    #[test]
    fn large_gemini_window_handles_large_inputs() {
        // gemini-1.5-pro has 2M context - 1.5M tokens should be fine
        assert!(check_overflow("gemini-1.5-pro", 1_500_000, None).is_none());
        // But 3M would overflow
        assert_eq!(
            check_overflow("gemini-1.5-pro", 3_000_000, None),
            Some(OverflowAction::Error)
        );
    }
}
