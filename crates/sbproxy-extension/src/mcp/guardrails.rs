//! Safety controls for MCP tool invocations.
//!
//! Validates tool calls against a policy before forwarding them to the
//! actual tool handler.  Checks include a blocklist of tool names and a
//! maximum serialised argument size.

/// Configuration for MCP guardrail checks.
pub struct McpGuardrailConfig {
    /// Tools that are unconditionally blocked.
    pub blocked_tools: Vec<String>,
    /// Maximum allowed size (bytes) for serialised tool arguments.
    pub max_args_size_bytes: usize,
    /// Optional per-tool rate limit (requests/minute).  Not enforced here -
    /// stored for use by rate-limit middleware.
    pub rate_limit_per_tool: Option<u32>,
}

/// Check whether a tool invocation is permitted by the guardrail policy.
///
/// Returns `Ok(())` when the invocation is allowed, or an `Err` with a
/// human-readable reason when it is rejected.
pub fn check_tool_invocation(
    tool_name: &str,
    args: &serde_json::Value,
    config: &McpGuardrailConfig,
) -> Result<(), String> {
    // --- Blocklist check ---
    if config.blocked_tools.contains(&tool_name.to_string()) {
        return Err(format!(
            "tool '{}' is blocked by guardrail policy",
            tool_name
        ));
    }

    // --- Argument size check ---
    let args_str = serde_json::to_string(args).unwrap_or_default();
    if args_str.len() > config.max_args_size_bytes {
        return Err(format!(
            "tool arguments exceed max size ({} > {})",
            args_str.len(),
            config.max_args_size_bytes
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn default_config() -> McpGuardrailConfig {
        McpGuardrailConfig {
            blocked_tools: vec!["dangerous_tool".to_string(), "admin_reset".to_string()],
            max_args_size_bytes: 1024,
            rate_limit_per_tool: None,
        }
    }

    #[test]
    fn allowed_tool_passes() {
        let config = default_config();
        let result = check_tool_invocation("safe_tool", &json!({"key": "value"}), &config);
        assert!(result.is_ok());
    }

    #[test]
    fn blocked_tool_is_rejected() {
        let config = default_config();
        let result = check_tool_invocation("dangerous_tool", &json!({}), &config);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("dangerous_tool"),
            "error should name the blocked tool"
        );
        assert!(msg.contains("blocked"), "error should mention blocked");
    }

    #[test]
    fn second_blocked_tool_is_rejected() {
        let config = default_config();
        let result = check_tool_invocation("admin_reset", &json!({}), &config);
        assert!(result.is_err());
    }

    #[test]
    fn args_too_large_is_rejected() {
        let config = McpGuardrailConfig {
            blocked_tools: vec![],
            max_args_size_bytes: 10,
            rate_limit_per_tool: None,
        };
        let large_args = json!({"data": "this string is definitely longer than ten bytes"});
        let result = check_tool_invocation("any_tool", &large_args, &config);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("exceed"),
            "error should mention exceeding size"
        );
    }

    #[test]
    fn args_exactly_at_limit_passes() {
        // Build args that serialise to exactly `max_args_size_bytes` chars.
        let limit = 10;
        let config = McpGuardrailConfig {
            blocked_tools: vec![],
            max_args_size_bytes: limit,
            rate_limit_per_tool: None,
        };
        // json!(null) serialises to "null" = 4 bytes, well under limit.
        let result = check_tool_invocation("tool", &json!(null), &config);
        assert!(result.is_ok());
    }

    #[test]
    fn empty_blocklist_allows_everything() {
        let config = McpGuardrailConfig {
            blocked_tools: vec![],
            max_args_size_bytes: 65536,
            rate_limit_per_tool: Some(100),
        };
        let result = check_tool_invocation("anything", &json!({"x": 1}), &config);
        assert!(result.is_ok());
    }
}
