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
        if let Some(input_budget_tokens) = self.config.input_budget_tokens {
            return match crate::context_compress::fit_messages_to_input_budget(
                messages,
                request.model(),
                self.config.completion_reserve_tokens,
                input_budget_tokens,
            ) {
                crate::context_compress::ExplicitBudgetFit::Candidate(messages) => {
                    CompressionDecision::Candidate { messages }
                }
                crate::context_compress::ExplicitBudgetFit::NotNeeded => {
                    CompressionDecision::Skipped {
                        reason: SkipReason::NotNeeded,
                    }
                }
                crate::context_compress::ExplicitBudgetFit::CannotMeetBudget => {
                    CompressionDecision::Skipped {
                        reason: SkipReason::NotEligible,
                    }
                }
            };
        }
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
            input_budget_tokens: None,
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

    #[tokio::test]
    async fn explicit_budget_supports_unknown_target_models() {
        let messages = vec![user(&"old ".repeat(1_000)), user("newest answer")];
        let lever = WindowFitLever::new(WindowFitConfig {
            completion_reserve_tokens: 1_024,
            input_budget_tokens: Some(64),
        });

        let decision = lever
            .compress(&CompressionRequest::new("unknown-model"), &messages)
            .await;

        let CompressionDecision::Candidate { messages } = decision else {
            panic!("explicit budget should fit an unknown model");
        };
        assert_eq!(
            messages
                .last()
                .and_then(|message| message["content"].as_str()),
            Some("newest answer")
        );
        assert!(
            crate::token_estimate::estimate_json_message_tokens("unknown-model", &messages) <= 64
        );
    }

    #[tokio::test]
    async fn explicit_budget_is_capped_by_known_model_capacity() {
        let messages = (0..12)
            .map(|index| user(&format!("message-{index}: {}", "x".repeat(400))))
            .collect::<Vec<_>>();
        let lever = WindowFitLever::new(WindowFitConfig {
            completion_reserve_tokens: 8_000,
            input_budget_tokens: Some(10_000),
        });

        let decision = lever
            .compress(&CompressionRequest::new("gpt-4"), &messages)
            .await;
        let CompressionDecision::Candidate { messages } = decision else {
            panic!("known model capacity should force fitting");
        };
        assert!(
            crate::token_estimate::estimate_json_message_tokens("gpt-4", &messages) <= 192,
            "gpt-4 capacity after reserve is 192 tokens"
        );
    }

    #[tokio::test]
    async fn explicit_budget_skips_when_protected_system_message_exceeds_cap() {
        let messages = vec![
            json!({"role": "system", "content": "x".repeat(4_000)}),
            user("newest"),
        ];
        let lever = WindowFitLever::new(WindowFitConfig {
            completion_reserve_tokens: 0,
            input_budget_tokens: Some(16),
        });

        let decision = lever
            .compress(&CompressionRequest::new("gpt-4"), &messages)
            .await;

        assert_eq!(
            decision,
            CompressionDecision::Skipped {
                reason: SkipReason::NotEligible
            }
        );
    }

    #[tokio::test]
    async fn explicit_budget_keeps_tool_call_and_results_as_one_unit() {
        let input = vec![
            user(&"old context ".repeat(400)),
            json!({
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "lookup", "arguments": "{}"}
                }]
            }),
            json!({"role": "tool", "tool_call_id": "call_1", "content": "result"}),
            user("use the result"),
        ];
        let required = crate::token_estimate::estimate_json_message_tokens("gpt-4", &input[1..]);
        let lever = WindowFitLever::new(WindowFitConfig {
            completion_reserve_tokens: 0,
            input_budget_tokens: Some(required),
        });

        let decision = lever
            .compress(&CompressionRequest::new("gpt-4"), &input)
            .await;
        let CompressionDecision::Candidate { messages } = decision else {
            panic!("explicit budget should trim old context");
        };

        assert_eq!(
            messages,
            vec![
                json!({
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "lookup", "arguments": "{}"}
                    }]
                }),
                json!({"role": "tool", "tool_call_id": "call_1", "content": "result"}),
                user("use the result"),
            ]
        );
    }
}
