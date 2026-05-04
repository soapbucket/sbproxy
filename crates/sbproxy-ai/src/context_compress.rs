//! Cost-aware context management.
//!
//! Automatically trims a conversation history to fit within a token budget
//! while preserving the system message and the most recent exchanges.

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
    fn chronological_order_preserved_in_output() {
        let messages = vec![sys(), user("first"), assistant("second"), user("third")];
        let result = trim_to_budget(&messages, 10000);
        assert_eq!(result[0]["content"], "You are a helpful assistant.");
        assert_eq!(result[1]["content"], "first");
        assert_eq!(result[2]["content"], "second");
        assert_eq!(result[3]["content"], "third");
    }
}
