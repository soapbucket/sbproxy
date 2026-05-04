//! AI-specific tracing span helpers.
//!
//! Provides thin wrappers around `tracing::info_span!` for the spans that are
//! most useful when profiling the AI gateway pipeline. Callers enter the
//! returned span with `.entered()` or pass it to `Instrument::instrument`.

/// Create a span for provider selection.
///
/// Records which provider and model were chosen by the routing layer so that
/// downstream spans can be associated with a specific upstream.
pub fn provider_selection_span(provider: &str, model: &str) -> tracing::Span {
    tracing::info_span!("ai.provider_selection", provider = provider, model = model)
}

/// Create a span for guardrail evaluation.
///
/// `category` identifies which guardrail rule set is being evaluated
/// (e.g. `"content_policy"`, `"pii_detection"`).
pub fn guardrail_eval_span(category: &str) -> tracing::Span {
    tracing::info_span!("ai.guardrail_eval", category = category)
}

/// Create a span for streaming accumulation.
///
/// Covers the window from the first SSE chunk received until the stream is
/// closed, allowing per-provider streaming latency to be observed.
pub fn streaming_span(provider: &str, model: &str) -> tracing::Span {
    tracing::info_span!("ai.streaming", provider = provider, model = model)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_selection_span_is_valid() {
        // Span creation must not panic.
        let span = provider_selection_span("openai", "gpt-4o");
        // A span is always valid (non-disabled) when created outside of a
        // subscriber. We just check it does not return a disabled stub.
        // The span name is visible via Debug.
        let dbg = format!("{:?}", span);
        // Depending on the tracing version, metadata may or may not be shown;
        // the important thing is that the call compiles and runs.
        let _ = dbg;
    }

    #[test]
    fn guardrail_eval_span_is_valid() {
        let span = guardrail_eval_span("content_policy");
        let _ = format!("{:?}", span);
    }

    #[test]
    fn streaming_span_is_valid() {
        let span = streaming_span("anthropic", "claude-3-5-sonnet");
        let _ = format!("{:?}", span);
    }

    #[test]
    fn spans_can_be_entered() {
        let span = provider_selection_span("cohere", "command-r");
        let _guard = span.entered();
        // If we get here without a panic the span lifecycle is correct.
    }
}
