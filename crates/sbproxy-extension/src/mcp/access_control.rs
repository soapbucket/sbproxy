//! MCP tool-level access control.
//!
//! `ToolAccessPolicy` maps virtual API keys to the set of MCP tool names
//! they are permitted to invoke. An empty permission list for a key means
//! "allow all tools" (open access). A non-empty list is an allowlist: only
//! the named tools may be called with that key.

use std::collections::HashMap;

use serde::Deserialize;

/// Policy controlling which MCP tools each virtual key may invoke.
///
/// Keys are typically virtual API key identifiers. The `key_permissions` map
/// stores per-key allowlists. An absent or empty allowlist grants access to
/// all tools.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ToolAccessPolicy {
    /// Map of virtual_key -> allowed tool names.
    ///
    /// An empty `Vec` (or absent key) means the key may invoke any tool.
    /// A non-empty `Vec` restricts the key to only those named tools.
    #[serde(default)]
    pub key_permissions: HashMap<String, Vec<String>>,
}

impl ToolAccessPolicy {
    /// Create a new empty `ToolAccessPolicy` (all keys allow all tools).
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether a virtual key is allowed to invoke a given tool.
    ///
    /// Returns `true` when:
    /// - The key is not present in `key_permissions` (allow all), or
    /// - The key's allowlist is empty (allow all), or
    /// - The tool name is in the key's allowlist.
    ///
    /// Returns `false` when the key has a non-empty allowlist that does not
    /// contain `tool_name`.
    pub fn is_tool_allowed(&self, key: &str, tool_name: &str) -> bool {
        match self.key_permissions.get(key) {
            None => true,                            // Unknown key: allow all.
            Some(tools) if tools.is_empty() => true, // Empty list: allow all.
            Some(tools) => tools.iter().any(|t| t == tool_name),
        }
    }

    /// Add or replace the allowlist for a virtual key.
    ///
    /// Passing an empty `Vec` grants the key access to all tools.
    pub fn add_permission(&mut self, key: &str, tools: Vec<String>) {
        self.key_permissions.insert(key.to_string(), tools);
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_policy_allows_all_tools() {
        let policy = ToolAccessPolicy::new();
        // Any key, any tool → allowed.
        assert!(policy.is_tool_allowed("key-abc", "search"));
        assert!(policy.is_tool_allowed("key-abc", "read_file"));
        assert!(policy.is_tool_allowed("unknown-key", "anything"));
    }

    #[test]
    fn specific_tools_allowed_for_key() {
        let mut policy = ToolAccessPolicy::new();
        policy.add_permission("key-1", vec!["search".to_string(), "read_file".to_string()]);

        assert!(policy.is_tool_allowed("key-1", "search"));
        assert!(policy.is_tool_allowed("key-1", "read_file"));
    }

    #[test]
    fn blocked_tool_denied_for_key() {
        let mut policy = ToolAccessPolicy::new();
        policy.add_permission("key-1", vec!["search".to_string()]);

        // "write_file" is not in the allowlist.
        assert!(!policy.is_tool_allowed("key-1", "write_file"));
        assert!(!policy.is_tool_allowed("key-1", "execute_code"));
    }

    #[test]
    fn empty_allowlist_grants_all_tools() {
        let mut policy = ToolAccessPolicy::new();
        // Explicitly set an empty list for a key.
        policy.add_permission("key-open", vec![]);

        assert!(policy.is_tool_allowed("key-open", "any_tool"));
        assert!(policy.is_tool_allowed("key-open", "another_tool"));
    }

    #[test]
    fn unknown_key_allows_all_tools() {
        let mut policy = ToolAccessPolicy::new();
        policy.add_permission("key-restricted", vec!["search".to_string()]);

        // "key-unknown" has no entry → allow all.
        assert!(policy.is_tool_allowed("key-unknown", "write_file"));
        assert!(policy.is_tool_allowed("key-unknown", "delete"));
    }

    #[test]
    fn add_permission_replaces_existing() {
        let mut policy = ToolAccessPolicy::new();
        policy.add_permission("key-1", vec!["search".to_string()]);
        assert!(policy.is_tool_allowed("key-1", "search"));
        assert!(!policy.is_tool_allowed("key-1", "write_file"));

        // Replace with broader allowlist.
        policy.add_permission(
            "key-1",
            vec!["search".to_string(), "write_file".to_string()],
        );
        assert!(policy.is_tool_allowed("key-1", "write_file"));
    }

    #[test]
    fn multiple_keys_independently_scoped() {
        let mut policy = ToolAccessPolicy::new();
        policy.add_permission(
            "admin-key",
            vec![
                "read".to_string(),
                "write".to_string(),
                "delete".to_string(),
            ],
        );
        policy.add_permission("readonly-key", vec!["read".to_string()]);

        // Admin can do everything.
        assert!(policy.is_tool_allowed("admin-key", "delete"));
        // Read-only cannot write or delete.
        assert!(!policy.is_tool_allowed("readonly-key", "write"));
        assert!(!policy.is_tool_allowed("readonly-key", "delete"));
        // But can read.
        assert!(policy.is_tool_allowed("readonly-key", "read"));
    }

    #[test]
    fn deserialize_from_json() {
        let json = serde_json::json!({
            "key_permissions": {
                "key-a": ["search", "read_file"],
                "key-b": []
            }
        });
        let policy: ToolAccessPolicy = serde_json::from_value(json).unwrap();

        assert!(policy.is_tool_allowed("key-a", "search"));
        assert!(!policy.is_tool_allowed("key-a", "write_file"));
        assert!(policy.is_tool_allowed("key-b", "anything")); // empty = allow all
    }
}
