//! Deterministic model-window fitting.

use crate::compression::outcome::{LeverKind, SkipReason};
use crate::compression::runner::{CompressionDecision, CompressionLever, CompressionRequest};
use crate::compression::{CompressionBackend, WindowFitConfig};
use async_trait::async_trait;
use serde_json::Value;
use std::ops::Range;

#[derive(Debug, Clone, PartialEq)]
enum ExplicitBudgetFit {
    NotNeeded,
    Candidate(Vec<Value>),
    CannotMeetBudget,
}

fn estimate_message_tokens(message: &Value) -> u64 {
    let content = message.get("content").and_then(Value::as_str).unwrap_or("");
    (content.len() as u64) / 4 + 1
}

fn trim_to_budget(messages: &[Value], max_tokens: u64) -> Vec<Value> {
    let mut result = Vec::new();
    let mut budget = max_tokens;

    if let Some(first) = messages.first() {
        if message_role(first) == Some("system") {
            budget = budget.saturating_sub(estimate_message_tokens(first));
            result.push(first.clone());
        }
    }

    let mut newest_that_fit = Vec::new();
    for message in messages.iter().rev() {
        if message_role(message) == Some("system") {
            continue;
        }
        let tokens = estimate_message_tokens(message);
        if tokens <= budget {
            budget -= tokens;
            newest_that_fit.push(message.clone());
        }
    }
    newest_that_fit.reverse();
    result.extend(newest_that_fit);
    result
}

fn fit_messages_to_model(
    messages: &[Value],
    model: &str,
    completion_reserve_tokens: u64,
) -> Option<Vec<Value>> {
    let window = crate::context_window::model_context_window(model)?;
    let budget = window.saturating_sub(completion_reserve_tokens).max(1);
    let total = messages.iter().map(estimate_message_tokens).sum::<u64>();
    if total <= budget {
        return None;
    }
    Some(trim_to_budget(messages, budget))
}

fn fit_messages_to_input_budget(
    messages: &[Value],
    model: &str,
    completion_reserve_tokens: u64,
    input_budget_tokens: u64,
) -> ExplicitBudgetFit {
    let model_capacity = crate::context_window::model_context_window(model)
        .map(|window| window.saturating_sub(completion_reserve_tokens).max(1));
    let budget = model_capacity.map_or(input_budget_tokens, |capacity| {
        input_budget_tokens.min(capacity)
    });
    let count =
        |candidate: &[Value]| crate::token_estimate::estimate_json_message_tokens(model, candidate);
    let reply_priming = count(&[]);

    if count(messages) <= budget {
        return ExplicitBudgetFit::NotNeeded;
    }

    let protected_prefix_len = messages
        .iter()
        .take_while(|message| matches!(message_role(message), Some("system" | "developer")))
        .count();
    let mut selected_tokens = if protected_prefix_len == 0 {
        reply_priming
    } else {
        count(&messages[..protected_prefix_len])
    };
    if selected_tokens > budget {
        return ExplicitBudgetFit::CannotMeetBudget;
    }

    let units = protocol_units(messages, protected_prefix_len);
    let mut selected = Vec::<Range<usize>>::new();
    let mut units = units.into_iter().rev();

    // The newest protocol unit is the current turn. Dispatching older context
    // without it changes the request's meaning.
    if let Some(newest) = units.next() {
        let newest_tokens = count(&messages[newest.clone()]).saturating_sub(reply_priming);
        selected_tokens = selected_tokens.saturating_add(newest_tokens);
        if selected_tokens > budget {
            return ExplicitBudgetFit::CannotMeetBudget;
        }
        selected.push(newest);
    }

    for unit in units {
        let unit_tokens = count(&messages[unit.clone()]).saturating_sub(reply_priming);
        if selected_tokens.saturating_add(unit_tokens) > budget {
            break;
        }
        selected_tokens += unit_tokens;
        selected.push(unit);
    }

    let candidate = collect_candidate(messages, protected_prefix_len, &selected);
    if count(&candidate) > budget || (candidate.is_empty() && !messages.is_empty()) {
        ExplicitBudgetFit::CannotMeetBudget
    } else {
        ExplicitBudgetFit::Candidate(candidate)
    }
}

fn message_role(message: &Value) -> Option<&str> {
    message.get("role").and_then(Value::as_str)
}

fn protocol_units(messages: &[Value], start: usize) -> Vec<Range<usize>> {
    let mut units = Vec::new();
    let mut index = start;
    while index < messages.len() {
        let unit_start = index;
        index += 1;
        let starts_openai_tool_exchange = message_role(&messages[unit_start]) == Some("assistant")
            && (messages[unit_start]
                .get("tool_calls")
                .and_then(Value::as_array)
                .is_some_and(|calls| !calls.is_empty())
                || messages[unit_start].get("function_call").is_some());
        let starts_anthropic_tool_exchange = message_role(&messages[unit_start])
            == Some("assistant")
            && messages[unit_start]
                .get("content")
                .and_then(Value::as_array)
                .is_some_and(|blocks| {
                    blocks
                        .iter()
                        .any(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))
                });
        if starts_openai_tool_exchange || starts_anthropic_tool_exchange {
            while index < messages.len() && is_tool_result_message(&messages[index]) {
                index += 1;
            }
        }
        units.push(unit_start..index);
    }
    units
}

fn collect_candidate(
    messages: &[Value],
    protected_prefix_len: usize,
    selected_newest_first: &[Range<usize>],
) -> Vec<Value> {
    let selected_len = selected_newest_first.iter().map(Range::len).sum::<usize>();
    let mut candidate = Vec::with_capacity(selected_len + protected_prefix_len);
    candidate.extend(messages[..protected_prefix_len].iter().cloned());
    for range in selected_newest_first.iter().rev() {
        candidate.extend(messages[range.clone()].iter().cloned());
    }
    candidate
}

fn is_tool_result_message(message: &Value) -> bool {
    if matches!(message_role(message), Some("tool" | "function")) {
        return true;
    }
    message_role(message) == Some("user")
        && message
            .get("content")
            .and_then(Value::as_array)
            .is_some_and(|blocks| {
                blocks
                    .iter()
                    .any(|block| block.get("type").and_then(Value::as_str) == Some("tool_result"))
            })
}

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
            return match fit_messages_to_input_budget(
                messages,
                request.model(),
                self.config.completion_reserve_tokens,
                input_budget_tokens,
            ) {
                ExplicitBudgetFit::Candidate(messages) => {
                    CompressionDecision::Candidate { messages }
                }
                ExplicitBudgetFit::NotNeeded => CompressionDecision::Skipped {
                    reason: SkipReason::NotNeeded,
                },
                ExplicitBudgetFit::CannotMeetBudget => CompressionDecision::Skipped {
                    reason: SkipReason::NotEligible,
                },
            };
        }
        if crate::context_window::model_context_window(request.model()).is_none() {
            return CompressionDecision::Skipped {
                reason: SkipReason::UnknownModelWindow,
            };
        }
        match fit_messages_to_model(
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
    use super::{
        fit_messages_to_input_budget, fit_messages_to_model, ExplicitBudgetFit, WindowFitLever,
    };
    use crate::compression::outcome::{LeverKind, SkipReason};
    use crate::compression::runner::{CompressionDecision, CompressionLever, CompressionRequest};
    use crate::compression::WindowFitConfig;
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

    #[test]
    fn explicit_budget_never_drops_an_oversized_newest_turn_for_older_context() {
        let messages = vec![user("old and small"), user(&"newest ".repeat(500))];
        let old_only_budget =
            crate::token_estimate::estimate_json_message_tokens("unknown-model", &messages[..1]);

        assert_eq!(
            fit_messages_to_input_budget(&messages, "unknown-model", 0, old_only_budget),
            ExplicitBudgetFit::CannotMeetBudget
        );
    }

    #[test]
    fn explicit_budget_preserves_contiguous_system_and_developer_prefix() {
        let messages = vec![
            json!({"role": "system", "content": "system rule"}),
            json!({"role": "developer", "content": "developer rule"}),
            user(&"old ".repeat(200)),
            user("newest"),
        ];
        let expected = vec![
            messages[0].clone(),
            messages[1].clone(),
            messages[3].clone(),
        ];
        let budget =
            crate::token_estimate::estimate_json_message_tokens("unknown-model", &expected);

        assert_eq!(
            fit_messages_to_input_budget(&messages, "unknown-model", 0, budget),
            ExplicitBudgetFit::Candidate(expected)
        );
    }

    #[test]
    fn explicit_budget_retains_a_contiguous_newest_suffix() {
        let messages = vec![
            user("old small context"),
            user(&"oversized middle ".repeat(300)),
            user("newest turn"),
        ];
        let non_contiguous = vec![messages[0].clone(), messages[2].clone()];
        let budget =
            crate::token_estimate::estimate_json_message_tokens("unknown-model", &non_contiguous);

        assert_eq!(
            fit_messages_to_input_budget(&messages, "unknown-model", 0, budget),
            ExplicitBudgetFit::Candidate(vec![messages[2].clone()])
        );
    }

    #[test]
    fn explicit_budget_groups_anthropic_tool_use_with_tool_result() {
        let messages = vec![
            user(&"old ".repeat(200)),
            json!({
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "tool-1", "name": "lookup", "input": {}}]
            }),
            json!({
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "tool-1", "content": "ok"}]
            }),
            user("use the result"),
        ];
        let expected = messages[1..].to_vec();
        let budget =
            crate::token_estimate::estimate_json_message_tokens("unknown-model", &expected);

        assert_eq!(
            fit_messages_to_input_budget(&messages, "unknown-model", 0, budget),
            ExplicitBudgetFit::Candidate(expected)
        );
    }

    #[test]
    fn explicit_budget_counts_anthropic_tool_payloads_before_admitting_the_newest_unit() {
        let small = vec![
            json!({
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "id": "tool-1",
                    "name": "lookup",
                    "input": {"query": "small"}
                }]
            }),
            json!({
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": "tool-1",
                    "content": "ok"
                }]
            }),
        ];
        let mut large = small.clone();
        large[1]["content"][0]["content"] = json!("tool payload ".repeat(1_000));
        let budget = crate::token_estimate::estimate_json_message_tokens("unknown-model", &small);

        assert_eq!(
            fit_messages_to_input_budget(&large, "unknown-model", 0, budget),
            ExplicitBudgetFit::CannotMeetBudget
        );
    }

    #[test]
    fn explicit_budget_handles_large_histories_in_one_pass() {
        let messages = (0..10_000)
            .map(|index| user(&format!("message {index}")))
            .collect::<Vec<_>>();
        let expected = messages[messages.len() - 100..].to_vec();
        let budget =
            crate::token_estimate::estimate_json_message_tokens("unknown-model", &expected);

        assert_eq!(
            fit_messages_to_input_budget(&messages, "unknown-model", 0, budget),
            ExplicitBudgetFit::Candidate(expected)
        );
    }
}
