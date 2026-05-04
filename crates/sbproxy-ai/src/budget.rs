//! Budget enforcement for AI gateway usage tracking and limits.

use dashmap::DashMap;
use serde::Deserialize;

/// Budget enforcement configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct BudgetConfig {
    /// Budget limits by scope.
    #[serde(default)]
    pub limits: Vec<BudgetLimit>,
    /// What to do when budget is exceeded.
    #[serde(default)]
    pub on_exceed: OnExceedAction,
}

/// A single budget limit rule.
#[derive(Debug, Clone, Deserialize)]
pub struct BudgetLimit {
    /// The scope this limit applies to.
    pub scope: BudgetScope,
    /// Maximum tokens allowed.
    pub max_tokens: Option<u64>,
    /// Maximum cost in USD.
    pub max_cost_usd: Option<f64>,
    /// Time period: "daily", "monthly", or "total".
    #[serde(default)]
    pub period: Option<String>,
    /// Model to downgrade to when limit is exceeded.
    #[serde(default)]
    pub downgrade_to: Option<String>,
}

/// Scope at which a budget limit is enforced.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BudgetScope {
    /// Limit applies across the entire workspace.
    Workspace,
    /// Limit applies per virtual API key.
    ApiKey,
    /// Limit applies per end-user identifier.
    User,
    /// Limit applies per model name.
    Model,
    /// Limit applies per upstream origin.
    Origin,
    /// Limit applies per metadata tag value.
    Tag,
}

/// Action taken when a budget limit is exceeded.
#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OnExceedAction {
    /// Block the request (default).
    #[default]
    Block,
    /// Log a warning but allow the request.
    Log,
    /// Downgrade to a cheaper model.
    Downgrade,
}

/// Tracks accumulated usage per scope key.
pub struct BudgetTracker {
    usage: DashMap<String, UsageRecord>,
}

/// Accumulated usage for a single scope key.
#[derive(Debug, Clone, Default)]
pub struct UsageRecord {
    /// Total tokens consumed (prompt + completion).
    pub tokens: u64,
    /// Total cost in USD across all requests.
    pub cost_usd: f64,
    /// Total number of recorded requests.
    pub request_count: u64,
}

impl Default for BudgetTracker {
    fn default() -> Self {
        Self {
            usage: DashMap::new(),
        }
    }
}

impl BudgetTracker {
    /// Create a new empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record token usage for a scope.
    ///
    /// Uses `entry().and_modify().or_insert_with()` so the
    /// read-modify-write is atomic under DashMap's per-shard write lock.
    pub fn record_usage(&self, scope_key: &str, tokens: u64, cost: f64) {
        self.usage
            .entry(scope_key.to_string())
            .and_modify(|record| {
                record.tokens += tokens;
                record.cost_usd += cost;
                record.request_count += 1;
            })
            .or_insert_with(|| UsageRecord {
                tokens,
                cost_usd: cost,
                request_count: 1,
            });
    }

    /// Get current usage for a scope.
    pub fn get_usage(&self, scope_key: &str) -> UsageRecord {
        self.usage
            .get(scope_key)
            .map(|r| r.clone())
            .unwrap_or_default()
    }

    /// Check if any budget limit is exceeded. Returns `Some` with details if exceeded.
    pub fn check_limits(
        &self,
        config: &BudgetConfig,
        scope_key: &str,
    ) -> Option<BudgetCheckResult> {
        let usage = self.get_usage(scope_key);
        for limit in &config.limits {
            if let Some(max_tokens) = limit.max_tokens {
                if usage.tokens >= max_tokens {
                    return Some(BudgetCheckResult {
                        exceeded: true,
                        action: config.on_exceed.clone(),
                        downgrade_to: limit.downgrade_to.clone(),
                        reason: format!("token limit exceeded: {} >= {}", usage.tokens, max_tokens),
                        current_tokens: usage.tokens,
                        current_cost_usd: usage.cost_usd,
                    });
                }
            }
            if let Some(max_cost) = limit.max_cost_usd {
                if usage.cost_usd >= max_cost {
                    return Some(BudgetCheckResult {
                        exceeded: true,
                        action: config.on_exceed.clone(),
                        downgrade_to: limit.downgrade_to.clone(),
                        reason: format!(
                            "cost limit exceeded: ${:.4} >= ${:.4}",
                            usage.cost_usd, max_cost
                        ),
                        current_tokens: usage.tokens,
                        current_cost_usd: usage.cost_usd,
                    });
                }
            }
        }
        None
    }

    /// Compose a deterministic scope key for the given limit's scope.
    /// `workspace_id` identifies the AI proxy origin (typically its
    /// hostname), and the optional inputs come from per-request state.
    /// Returns `None` when the request lacks the data the scope keys
    /// off (e.g. `User` with no user header set), in which case the
    /// caller should skip enforcement for that limit.
    pub fn scope_key(
        scope: &BudgetScope,
        workspace_id: &str,
        api_key: Option<&str>,
        user: Option<&str>,
        model: Option<&str>,
        origin: Option<&str>,
        tag: Option<&str>,
    ) -> Option<String> {
        match scope {
            BudgetScope::Workspace => Some(format!("workspace:{}", workspace_id)),
            BudgetScope::ApiKey => api_key.map(|k| format!("api_key:{}:{}", workspace_id, k)),
            BudgetScope::User => user.map(|u| format!("user:{}:{}", workspace_id, u)),
            BudgetScope::Model => model.map(|m| format!("model:{}:{}", workspace_id, m)),
            BudgetScope::Origin => origin.map(|o| format!("origin:{}", o)),
            BudgetScope::Tag => tag.map(|t| format!("tag:{}:{}", workspace_id, t)),
        }
    }

    /// Reset usage for a scope.
    pub fn reset(&self, scope_key: &str) {
        self.usage.remove(scope_key);
    }
}

/// Result of a budget limit check.
#[derive(Debug, Clone)]
pub struct BudgetCheckResult {
    /// Whether the budget was exceeded.
    pub exceeded: bool,
    /// The action to take.
    pub action: OnExceedAction,
    /// Model to downgrade to, if action is Downgrade.
    pub downgrade_to: Option<String>,
    /// Human-readable reason for the exceeded budget.
    pub reason: String,
    /// Current accumulated tokens for the scope at check time.
    pub current_tokens: u64,
    /// Current accumulated cost for the scope at check time.
    pub current_cost_usd: f64,
}

/// Per-million-token pricing for a known model.
///
/// Values are USD per million tokens. The catalog covers the major
/// hosted families that the YAML provider list ships with; unknown
/// models fall back to a conservative default in [`estimate_cost`].
#[derive(Debug, Clone, Copy)]
pub struct ModelPrice {
    /// Cost per million prompt tokens, in USD.
    pub input_per_million: f64,
    /// Cost per million completion tokens, in USD.
    pub output_per_million: f64,
}

/// Built-in price catalog. Numbers are static published list prices
/// at the time of writing; operators that need exact billing should
/// pair this with their own ledger. The default is intentionally
/// pessimistic (assume the more expensive of input/output dominates)
/// so a budget cap fires earlier rather than later when a model is
/// unknown.
fn lookup_price(model: &str) -> Option<ModelPrice> {
    let m = model.to_ascii_lowercase();
    // OpenAI
    if m.starts_with("gpt-4o-mini") {
        return Some(ModelPrice {
            input_per_million: 0.15,
            output_per_million: 0.60,
        });
    }
    if m.starts_with("gpt-4o") {
        return Some(ModelPrice {
            input_per_million: 2.50,
            output_per_million: 10.00,
        });
    }
    if m.starts_with("gpt-4-turbo") {
        return Some(ModelPrice {
            input_per_million: 10.00,
            output_per_million: 30.00,
        });
    }
    if m.starts_with("gpt-4") {
        return Some(ModelPrice {
            input_per_million: 30.00,
            output_per_million: 60.00,
        });
    }
    if m.starts_with("gpt-3.5") {
        return Some(ModelPrice {
            input_per_million: 0.50,
            output_per_million: 1.50,
        });
    }
    // Anthropic
    if m.contains("claude-3-5-haiku") || m.contains("claude-3-haiku") {
        return Some(ModelPrice {
            input_per_million: 0.80,
            output_per_million: 4.00,
        });
    }
    if m.contains("claude-3-5-sonnet") || m.contains("claude-3-sonnet") {
        return Some(ModelPrice {
            input_per_million: 3.00,
            output_per_million: 15.00,
        });
    }
    if m.contains("claude-3-opus") {
        return Some(ModelPrice {
            input_per_million: 15.00,
            output_per_million: 75.00,
        });
    }
    // Google
    if m.contains("gemini-1.5-flash") || m.contains("gemini-flash") {
        return Some(ModelPrice {
            input_per_million: 0.075,
            output_per_million: 0.30,
        });
    }
    if m.contains("gemini-1.5-pro") || m.contains("gemini-pro") {
        return Some(ModelPrice {
            input_per_million: 1.25,
            output_per_million: 5.00,
        });
    }
    None
}

/// Estimate the USD cost of a request given the model name and token
/// counts. Unknown models fall back to a flat $5 per million blended
/// rate so a missing entry never silently zero-rates a request.
pub fn estimate_cost(model: &str, prompt_tokens: u64, completion_tokens: u64) -> f64 {
    let price = lookup_price(model).unwrap_or(ModelPrice {
        input_per_million: 5.0,
        output_per_million: 5.0,
    });
    let prompt_cost = (prompt_tokens as f64) * price.input_per_million / 1_000_000.0;
    let completion_cost = (completion_tokens as f64) * price.output_per_million / 1_000_000.0;
    prompt_cost + completion_cost
}

/// Pick the cheapest model from a list of candidates, using the
/// built-in price catalog. Returns `None` when the list is empty.
/// Models without a known price are scored at the default fallback
/// rate (not cheapest, not most expensive) so they neither dominate
/// nor get silently excluded from the comparison.
pub fn cheapest_model(candidates: &[String]) -> Option<String> {
    let mut best: Option<(f64, &String)> = None;
    for name in candidates {
        let price = lookup_price(name).unwrap_or(ModelPrice {
            input_per_million: 5.0,
            output_per_million: 5.0,
        });
        // Score against a representative 1000-prompt / 500-completion
        // mix so input-heavy and output-heavy models are weighted
        // realistically rather than by either rate in isolation.
        let score = price.input_per_million * 1000.0 + price.output_per_million * 500.0;
        match best {
            None => best = Some((score, name)),
            Some((cur, _)) if score < cur => best = Some((score, name)),
            _ => {}
        }
    }
    best.map(|(_, name)| name.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(
        max_tokens: Option<u64>,
        max_cost: Option<f64>,
        on_exceed: OnExceedAction,
        downgrade_to: Option<String>,
    ) -> BudgetConfig {
        BudgetConfig {
            limits: vec![BudgetLimit {
                scope: BudgetScope::Workspace,
                max_tokens,
                max_cost_usd: max_cost,
                period: None,
                downgrade_to,
            }],
            on_exceed,
        }
    }

    #[test]
    fn record_usage_increments() {
        let tracker = BudgetTracker::new();
        tracker.record_usage("ws:1", 100, 0.01);
        tracker.record_usage("ws:1", 200, 0.02);

        let usage = tracker.get_usage("ws:1");
        assert_eq!(usage.tokens, 300);
        assert!((usage.cost_usd - 0.03).abs() < 1e-10);
        assert_eq!(usage.request_count, 2);
    }

    #[test]
    fn check_limits_under_limit_returns_none() {
        let tracker = BudgetTracker::new();
        tracker.record_usage("ws:1", 50, 0.005);

        let config = make_config(Some(1000), Some(1.0), OnExceedAction::Block, None);
        assert!(tracker.check_limits(&config, "ws:1").is_none());
    }

    #[test]
    fn check_limits_token_exceeded() {
        let tracker = BudgetTracker::new();
        tracker.record_usage("ws:1", 1000, 0.01);

        let config = make_config(Some(1000), None, OnExceedAction::Block, None);
        let result = tracker.check_limits(&config, "ws:1").unwrap();
        assert!(result.exceeded);
        assert_eq!(result.action, OnExceedAction::Block);
        assert!(result.reason.contains("token limit exceeded"));
    }

    #[test]
    fn check_limits_cost_exceeded() {
        let tracker = BudgetTracker::new();
        tracker.record_usage("ws:1", 100, 5.0);

        let config = make_config(None, Some(1.0), OnExceedAction::Log, None);
        let result = tracker.check_limits(&config, "ws:1").unwrap();
        assert!(result.exceeded);
        assert_eq!(result.action, OnExceedAction::Log);
        assert!(result.reason.contains("cost limit exceeded"));
    }

    #[test]
    fn on_exceed_downgrade_with_target() {
        let tracker = BudgetTracker::new();
        tracker.record_usage("ws:1", 5000, 0.0);

        let config = make_config(
            Some(1000),
            None,
            OnExceedAction::Downgrade,
            Some("gpt-3.5-turbo".to_string()),
        );
        let result = tracker.check_limits(&config, "ws:1").unwrap();
        assert!(result.exceeded);
        assert_eq!(result.action, OnExceedAction::Downgrade);
        assert_eq!(result.downgrade_to.as_deref(), Some("gpt-3.5-turbo"));
    }

    #[test]
    fn reset_clears_usage() {
        let tracker = BudgetTracker::new();
        tracker.record_usage("ws:1", 1000, 1.0);
        tracker.reset("ws:1");

        let usage = tracker.get_usage("ws:1");
        assert_eq!(usage.tokens, 0);
        assert_eq!(usage.cost_usd, 0.0);
        assert_eq!(usage.request_count, 0);
    }

    #[test]
    fn unknown_scope_key_returns_default() {
        let tracker = BudgetTracker::new();
        let usage = tracker.get_usage("nonexistent");
        assert_eq!(usage.tokens, 0);
        assert_eq!(usage.cost_usd, 0.0);
        assert_eq!(usage.request_count, 0);
    }

    #[test]
    fn no_limits_configured_returns_none() {
        let tracker = BudgetTracker::new();
        tracker.record_usage("ws:1", 999999, 999.0);

        let config = BudgetConfig {
            limits: vec![],
            on_exceed: OnExceedAction::Block,
        };
        assert!(tracker.check_limits(&config, "ws:1").is_none());
    }

    #[test]
    fn concurrent_record_usage_is_race_correct() {
        use std::sync::Arc;
        use std::thread;

        let tracker = Arc::new(BudgetTracker::new());
        let mut handles = Vec::new();
        for _ in 0..16 {
            let t = Arc::clone(&tracker);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    t.record_usage("ws:concurrent", 1, 0.001);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let usage = tracker.get_usage("ws:concurrent");
        assert_eq!(usage.tokens, 16 * 1000);
        assert_eq!(usage.request_count, 16 * 1000);
    }
}
