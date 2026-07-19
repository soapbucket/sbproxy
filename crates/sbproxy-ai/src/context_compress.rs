//! Cost-aware context management.
//!
//! Automatically trims a conversation history to fit within a token budget
//! while preserving the system message and the most recent exchanges.

use std::ops::Range;

/// Result of fitting with an explicit, target-model-counted input budget.
#[derive(Debug, Clone, PartialEq)]
pub enum ExplicitBudgetFit {
    /// The original message list already meets the effective budget.
    NotNeeded,
    /// A complete, protocol-safe replacement message list.
    Candidate(Vec<serde_json::Value>),
    /// No valid message list can meet the configured budget.
    CannotMeetBudget,
}

/// Estimate the number of tokens in a single chat message.
///
/// Uses the common approximation of 4 characters per token, with a minimum
/// of 1 token per message.
pub fn estimate_message_tokens(message: &serde_json::Value) -> u64 {
    let content = message
        .get("content")
        .and_then(|c| c.as_str())
        .unwrap_or("");
    (content.len() as u64) / 4 + 1
}

/// Trim a message list to fit within `max_tokens`.
///
/// Rules:
/// 1. The system message (role == `"system"`) is always kept if one is present
///    as the first element.
/// 2. Remaining messages are considered from newest to oldest; a message is
///    included only if its token estimate fits within the remaining budget.
/// 3. The relative order of included messages is preserved in the output.
pub fn trim_to_budget(messages: &[serde_json::Value], max_tokens: u64) -> Vec<serde_json::Value> {
    let mut result: Vec<serde_json::Value> = Vec::new();
    let mut budget = max_tokens;

    // --- Always keep the system message ---
    if let Some(first) = messages.first() {
        if first.get("role").and_then(|r| r.as_str()) == Some("system") {
            let tokens = estimate_message_tokens(first);
            budget = budget.saturating_sub(tokens);
            result.push(first.clone());
        }
    }

    // --- Add messages from newest to oldest until budget is exhausted ---
    // Collect eligible non-system messages in reverse order, then reverse again
    // to restore chronological order in the output.
    let mut to_add: Vec<serde_json::Value> = Vec::new();
    for msg in messages.iter().rev() {
        if msg.get("role").and_then(|r| r.as_str()) == Some("system") {
            continue;
        }
        let tokens = estimate_message_tokens(msg);
        if tokens <= budget {
            budget -= tokens;
            to_add.push(msg.clone());
        }
    }
    to_add.reverse();
    result.extend(to_add);

    result
}

/// Fit a message list to a model's context window (WOR-1545), reserving
/// `completion_reserve_tokens` for the response.
///
/// Returns the trimmed messages when the prompt would overflow the window,
/// so an over-long request can succeed on the same model instead of being
/// rejected with a context-length error. Returns `None` when the model's
/// window is unknown (so the request is left untouched) or the prompt
/// already fits.
pub fn fit_messages_to_model(
    messages: &[serde_json::Value],
    model: &str,
    completion_reserve_tokens: u64,
) -> Option<Vec<serde_json::Value>> {
    let window = crate::context_overflow::model_context_window(model)?;
    let budget = window.saturating_sub(completion_reserve_tokens).max(1);
    let total: u64 = messages.iter().map(estimate_message_tokens).sum();
    if total <= budget {
        return None;
    }
    Some(trim_to_budget(messages, budget))
}

/// Fit messages to an explicit input budget using the target-model counter.
///
/// When the model window is known, the effective budget is capped at the
/// model window minus `completion_reserve_tokens`. Unknown models can still be
/// fitted because the operator supplied an explicit capacity. The contiguous
/// leading system/developer instruction prefix is protected, assistant tool
/// calls remain grouped with their results, and retained history is always a
/// contiguous newest suffix.
pub fn fit_messages_to_input_budget(
    messages: &[serde_json::Value],
    model: &str,
    completion_reserve_tokens: u64,
    input_budget_tokens: u64,
) -> ExplicitBudgetFit {
    let model_capacity = crate::context_overflow::model_context_window(model)
        .map(|window| window.saturating_sub(completion_reserve_tokens).max(1));
    let budget = model_capacity.map_or(input_budget_tokens, |capacity| {
        input_budget_tokens.min(capacity)
    });
    let count = |candidate: &[serde_json::Value]| {
        crate::token_estimate::estimate_json_message_tokens(model, candidate)
    };
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
    // without it changes the request's meaning, so a budget that cannot hold
    // that complete unit is ineligible rather than an invitation to keep
    // smaller, stale units.
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

fn message_role(message: &serde_json::Value) -> Option<&str> {
    message.get("role").and_then(serde_json::Value::as_str)
}

fn protocol_units(messages: &[serde_json::Value], start: usize) -> Vec<Range<usize>> {
    let mut units = Vec::new();
    let mut index = start;
    while index < messages.len() {
        let unit_start = index;
        index += 1;
        let starts_openai_tool_exchange = message_role(&messages[unit_start]) == Some("assistant")
            && (messages[unit_start]
                .get("tool_calls")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|calls| !calls.is_empty())
                || messages[unit_start].get("function_call").is_some());
        let starts_anthropic_tool_exchange = message_role(&messages[unit_start])
            == Some("assistant")
            && messages[unit_start]
                .get("content")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|blocks| {
                    blocks.iter().any(|block| {
                        block.get("type").and_then(serde_json::Value::as_str) == Some("tool_use")
                    })
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
    messages: &[serde_json::Value],
    protected_prefix_len: usize,
    selected_newest_first: &[Range<usize>],
) -> Vec<serde_json::Value> {
    let selected_len = selected_newest_first
        .iter()
        .map(|range| range.len())
        .sum::<usize>();
    let mut candidate = Vec::with_capacity(selected_len + protected_prefix_len);
    candidate.extend(messages[..protected_prefix_len].iter().cloned());
    for range in selected_newest_first.iter().rev() {
        candidate.extend(messages[range.clone()].iter().cloned());
    }
    candidate
}

fn is_tool_result_message(message: &serde_json::Value) -> bool {
    if matches!(message_role(message), Some("tool" | "function")) {
        return true;
    }
    message_role(message) == Some("user")
        && message
            .get("content")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|blocks| {
                blocks.iter().any(|block| {
                    block.get("type").and_then(serde_json::Value::as_str) == Some("tool_result")
                })
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sys() -> serde_json::Value {
        json!({"role": "system", "content": "You are a helpful assistant."})
    }

    fn user(text: &str) -> serde_json::Value {
        json!({"role": "user", "content": text})
    }

    fn assistant(text: &str) -> serde_json::Value {
        json!({"role": "assistant", "content": text})
    }

    #[test]
    fn preserves_system_message() {
        let messages = vec![sys(), user("hello"), assistant("hi")];
        let result = trim_to_budget(&messages, 1000);
        assert_eq!(result[0]["role"], "system");
    }

    #[test]
    fn system_message_always_included_even_with_tight_budget() {
        let messages = vec![sys()];
        let tokens = estimate_message_tokens(&sys());
        let result = trim_to_budget(&messages, tokens);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "system");
    }

    #[test]
    fn trims_oldest_non_system_messages_first() {
        // Build a history with 5 user/assistant pairs.
        let mut messages = vec![sys()];
        for i in 0..5u32 {
            messages.push(user(&format!("user message {}", i)));
            messages.push(assistant(&format!("assistant response {}", i)));
        }

        // Allow enough budget for system + last 2 messages only.
        let sys_tokens = estimate_message_tokens(&sys());
        let msg_tokens = estimate_message_tokens(&messages[messages.len() - 1]);
        let budget = sys_tokens + msg_tokens * 2;

        let result = trim_to_budget(&messages, budget);
        // System message must be present.
        assert_eq!(result[0]["role"], "system");
        // Only the most recent messages should remain.
        let non_sys: Vec<_> = result.iter().skip(1).collect();
        assert!(!non_sys.is_empty());
        // The oldest non-system messages should have been dropped.
        // The last kept message should be the newest one in `messages`.
        let last_kept_content = result.last().unwrap()["content"].as_str().unwrap();
        assert!(
            last_kept_content.contains("4"),
            "newest messages (index 4) should be kept, got: {}",
            last_kept_content
        );
    }

    #[test]
    fn all_messages_fit_within_large_budget() {
        let messages = vec![sys(), user("hi"), assistant("hello"), user("bye")];
        let result = trim_to_budget(&messages, u64::MAX);
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn zero_budget_keeps_only_system_if_free() {
        // System message costs tokens; with budget == 0 it cannot be included.
        let messages = vec![sys(), user("hi")];
        let result = trim_to_budget(&messages, 0);
        // budget=0: system message tokens > 0, so system is included with
        // saturating_sub (budget stays 0 or wraps to 0), then no non-system
        // messages fit.
        // With saturating_sub the system message IS included but the budget
        // goes to 0 (or underflows to 0), so only system remains.
        for msg in &result {
            assert_eq!(
                msg["role"], "system",
                "only system messages should appear with budget=0"
            );
        }
    }

    #[test]
    fn no_system_message_still_works() {
        let messages = vec![user("hello"), assistant("hi"), user("bye")];
        let result = trim_to_budget(&messages, 1000);
        assert_eq!(result.len(), 3);
        // No system message in output.
        assert!(result.iter().all(|m| m["role"] != "system"));
    }

    #[test]
    fn estimate_message_tokens_minimum_one() {
        let msg = json!({"role": "user", "content": ""});
        assert_eq!(estimate_message_tokens(&msg), 1);
    }

    #[test]
    fn estimate_message_tokens_proportional_to_content_length() {
        let msg = json!({"role": "user", "content": "abcdefgh"}); // 8 chars -> 2 + 1 = 3
        assert_eq!(estimate_message_tokens(&msg), 3);
    }

    #[test]
    fn fit_to_model_trims_overflowing_prompt_keeping_system() {
        // gpt-4 has an 8192-token window. Reserve 1024 -> 7168 budget.
        // ~4 chars/token, so a 4000-char message is ~1000 tokens.
        let big = "x".repeat(4000);
        let mut messages = vec![sys()];
        for _ in 0..10 {
            messages.push(user(&big)); // ~10000 tokens total, over budget
        }
        let fitted =
            fit_messages_to_model(&messages, "gpt-4", 1024).expect("overflowing prompt is trimmed");
        assert!(fitted.len() < messages.len(), "messages were dropped");
        assert_eq!(fitted[0]["role"], "system", "system message kept");
        let total: u64 = fitted.iter().map(estimate_message_tokens).sum();
        assert!(total <= 7168, "fitted prompt is within budget: {total}");
    }

    #[test]
    fn fit_to_model_leaves_small_prompt_untouched() {
        let messages = vec![sys(), user("hello"), assistant("hi")];
        assert!(
            fit_messages_to_model(&messages, "gpt-4", 1024).is_none(),
            "a prompt that already fits is not trimmed"
        );
    }

    #[test]
    fn fit_to_model_unknown_model_is_noop() {
        let big = "x".repeat(100_000);
        let messages = vec![user(&big)];
        assert!(
            fit_messages_to_model(&messages, "some-unknown-model", 1024).is_none(),
            "an unknown model window leaves the request untouched"
        );
    }

    #[test]
    fn chronological_order_preserved_in_output() {
        let messages = vec![sys(), user("first"), assistant("second"), user("third")];
        let result = trim_to_budget(&messages, 10000);
        assert_eq!(result[0]["content"], "You are a helpful assistant.");
        assert_eq!(result[1]["content"], "first");
        assert_eq!(result[2]["content"], "second");
        assert_eq!(result[3]["content"], "third");
    }

    #[test]
    fn explicit_budget_never_drops_an_oversized_newest_turn_for_older_context() {
        let messages = vec![user("old and small"), user(&"newest ".repeat(500))];
        let old_only_budget =
            crate::token_estimate::estimate_json_message_tokens("unknown-model", &messages[..1]);

        assert_eq!(
            fit_messages_to_input_budget(&messages, "unknown-model", 0, old_only_budget,),
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
