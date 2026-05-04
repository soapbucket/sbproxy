//! Optimize context window usage for MCP tool schemas.
//! Prioritize frequently-used tools, drop rarely-used ones.

use std::collections::HashMap;
use std::sync::Mutex;

/// Tracks how often each MCP tool is invoked so the proxy can
/// prioritise the most-used tools when the context window is limited.
pub struct ToolUsageTracker {
    counts: Mutex<HashMap<String, u64>>,
}

impl ToolUsageTracker {
    /// Create a new tracker with no recorded usage.
    pub fn new() -> Self {
        Self {
            counts: Mutex::new(HashMap::new()),
        }
    }

    /// Record one invocation of `tool_name`.
    pub fn record_use(&self, tool_name: &str) {
        let mut counts = self.counts.lock().unwrap();
        *counts.entry(tool_name.to_string()).or_insert(0) += 1;
    }

    /// Return the number of times `tool_name` has been invoked.
    pub fn get_count(&self, tool_name: &str) -> u64 {
        let counts = self.counts.lock().unwrap();
        counts.get(tool_name).copied().unwrap_or(0)
    }

    /// Return all tools sorted by descending usage count (most used first).
    pub fn ranked_tools(&self) -> Vec<(String, u64)> {
        let counts = self.counts.lock().unwrap();
        let mut ranked: Vec<(String, u64)> = counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        ranked
    }

    /// Filter `tools` to fit within a `max_tokens` budget.
    ///
    /// Token cost is estimated as the length of the JSON-serialised tool
    /// definition divided by 4 (a common rough approximation).
    /// Tools are included in descending usage order; any tool whose
    /// serialised length would exceed the remaining budget is skipped.
    pub fn filter_by_budget(
        &self,
        tools: &[serde_json::Value],
        max_tokens: usize,
    ) -> Vec<serde_json::Value> {
        // Build a map from tool name to index in `tools`.
        let mut name_to_idx: HashMap<String, usize> = HashMap::new();
        for (i, tool) in tools.iter().enumerate() {
            if let Some(name) = tool.get("name").and_then(|n| n.as_str()) {
                name_to_idx.insert(name.to_string(), i);
            }
        }

        // Tools that have usage data are ordered by rank; tools with no usage
        // data are appended at the end in their original order.
        let ranked = self.ranked_tools();
        let ranked_names: Vec<&str> = ranked.iter().map(|(n, _)| n.as_str()).collect();

        let mut ordered: Vec<&serde_json::Value> = Vec::new();
        let mut seen_indices = std::collections::HashSet::new();

        for name in &ranked_names {
            if let Some(&idx) = name_to_idx.get(*name) {
                ordered.push(&tools[idx]);
                seen_indices.insert(idx);
            }
        }
        for (i, tool) in tools.iter().enumerate() {
            if !seen_indices.contains(&i) {
                ordered.push(tool);
            }
        }

        // Apply token budget.
        let mut result = Vec::new();
        let mut remaining = max_tokens;
        for tool in ordered {
            let serialized = serde_json::to_string(tool).unwrap_or_default();
            let tokens = serialized.len() / 4 + 1;
            if tokens <= remaining {
                remaining -= tokens;
                result.push(tool.clone());
            }
        }
        result
    }
}

impl Default for ToolUsageTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_tool(name: &str) -> serde_json::Value {
        json!({
            "name": name,
            "description": format!("Tool {}", name),
            "inputSchema": {"type": "object", "properties": {}}
        })
    }

    #[test]
    fn record_and_get_count() {
        let tracker = ToolUsageTracker::new();
        assert_eq!(tracker.get_count("search"), 0);
        tracker.record_use("search");
        tracker.record_use("search");
        assert_eq!(tracker.get_count("search"), 2);
    }

    #[test]
    fn get_count_unknown_tool_returns_zero() {
        let tracker = ToolUsageTracker::new();
        assert_eq!(tracker.get_count("nonexistent"), 0);
    }

    #[test]
    fn ranking_order_most_used_first() {
        let tracker = ToolUsageTracker::new();
        tracker.record_use("rare");
        tracker.record_use("common");
        tracker.record_use("common");
        tracker.record_use("common");
        tracker.record_use("medium");
        tracker.record_use("medium");

        let ranked = tracker.ranked_tools();
        assert_eq!(ranked[0].0, "common");
        assert_eq!(ranked[1].0, "medium");
        assert_eq!(ranked[2].0, "rare");
    }

    #[test]
    fn budget_filtering_keeps_most_used() {
        let tracker = ToolUsageTracker::new();
        // Record heavy usage of "search" and light usage of "summarize".
        for _ in 0..10 {
            tracker.record_use("search");
        }
        tracker.record_use("summarize");

        let tools = vec![
            make_tool("summarize"),
            make_tool("search"),
            make_tool("translate"),
        ];

        // A very tight budget that can only fit one tool.
        let serialized_len = serde_json::to_string(&make_tool("search")).unwrap().len();
        let single_tool_tokens = serialized_len / 4 + 1;
        let result = tracker.filter_by_budget(&tools, single_tool_tokens);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["name"], "search");
    }

    #[test]
    fn budget_filtering_zero_budget_returns_empty() {
        let tracker = ToolUsageTracker::new();
        tracker.record_use("tool_a");
        let tools = vec![make_tool("tool_a")];
        let result = tracker.filter_by_budget(&tools, 0);
        assert!(result.is_empty());
    }

    #[test]
    fn budget_filtering_large_budget_returns_all() {
        let tracker = ToolUsageTracker::new();
        let tools = vec![make_tool("a"), make_tool("b"), make_tool("c")];
        let result = tracker.filter_by_budget(&tools, usize::MAX);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn tools_without_usage_data_included_after_ranked() {
        let tracker = ToolUsageTracker::new();
        tracker.record_use("known");

        let tools = vec![make_tool("unknown"), make_tool("known")];
        let result = tracker.filter_by_budget(&tools, usize::MAX);
        // "known" should appear first (it has usage data), "unknown" second.
        assert_eq!(result[0]["name"], "known");
        assert_eq!(result[1]["name"], "unknown");
    }
}
