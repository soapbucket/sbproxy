//! Compatibility adapter for deterministic model-window fitting.

use crate::compression::outcome::{LeverKind, SkipReason};
use crate::compression::runner::{CompressionDecision, CompressionLever, CompressionRequest};
use crate::compression::{CompressionBackend, WindowFitConfig};
use async_trait::async_trait;
use serde_json::Value;

/// Stateless adapter over the pre-existing deterministic window-fit function.
#[derive(Debug, Clone)]
pub struct WindowFitLever {
    config: WindowFitConfig,
}

impl WindowFitLever {
    /// Construct the compatibility lever.
    pub const fn new(config: WindowFitConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl CompressionLever for WindowFitLever {
    fn kind(&self) -> LeverKind {
        LeverKind::WindowFit
    }

    fn backend(&self) -> Option<CompressionBackend> {
        None
    }

    async fn compress(
        &self,
        request: &CompressionRequest<'_>,
        messages: &[Value],
    ) -> CompressionDecision {
        if crate::context_overflow::model_context_window(request.model()).is_none() {
            return CompressionDecision::Skipped {
                reason: SkipReason::UnknownModelWindow,
            };
        }
        match crate::context_compress::fit_messages_to_model(
            messages,
            request.model(),
            self.config.completion_reserve_tokens,
        ) {
            Some(messages) => CompressionDecision::Candidate { messages },
            None => CompressionDecision::Skipped {
                reason: SkipReason::NotNeeded,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WindowFitLever;
    use crate::compression::outcome::{LeverKind, SkipReason};
    use crate::compression::runner::{CompressionDecision, CompressionLever, CompressionRequest};
    use crate::compression::WindowFitConfig;
    use crate::context_compress::fit_messages_to_model;
    use serde_json::{json, Value};

    fn user(content: &str) -> Value {
        json!({"role": "user", "content": content})
    }

    #[tokio::test]
    async fn candidate_is_byte_for_byte_legacy_window_fit_output() {
        let large = "x".repeat(4_000);
        let messages = (0..10).map(|_| user(&large)).collect::<Vec<_>>();
        let expected = fit_messages_to_model(&messages, "gpt-4", 1_024)
            .expect("legacy path trims this request");
        let lever = WindowFitLever::new(WindowFitConfig {
            completion_reserve_tokens: 1_024,
        });

        let decision = lever
            .compress(&CompressionRequest::new("gpt-4"), &messages)
            .await;

        assert_eq!(lever.kind(), LeverKind::WindowFit);
        assert!(lever.backend().is_none());
        assert_eq!(
            decision,
            CompressionDecision::Candidate { messages: expected }
        );
    }

    #[tokio::test]
    async fn known_model_that_already_fits_is_not_needed() {
        let lever = WindowFitLever::new(WindowFitConfig::default());
        let decision = lever
            .compress(&CompressionRequest::new("gpt-4"), &[user("small prompt")])
            .await;
        assert_eq!(
            decision,
            CompressionDecision::Skipped {
                reason: SkipReason::NotNeeded
            }
        );
    }

    #[tokio::test]
    async fn unknown_model_window_has_a_closed_skip_reason() {
        let lever = WindowFitLever::new(WindowFitConfig::default());
        let decision = lever
            .compress(
                &CompressionRequest::new("unknown-model"),
                &[user(&"x".repeat(100_000))],
            )
            .await;
        assert_eq!(
            decision,
            CompressionDecision::Skipped {
                reason: SkipReason::UnknownModelWindow
            }
        );
    }
}
