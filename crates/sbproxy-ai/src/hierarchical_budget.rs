//! Hierarchical budget tracking: org > team > project > user > model.
//!
//! Each "scope" is a combination of optional identifiers.  Limits and
//! accumulated spend are stored per unique scope key so that a single
//! `HierarchicalBudget` instance can enforce budgets at every level of the
//! organizational hierarchy simultaneously.

use std::collections::HashMap;
use std::sync::Mutex;

/// Identifies a single scope in the budget hierarchy.
///
/// All fields are optional; omitted levels act as wildcards when generating
/// the scope key.
#[derive(Debug, Clone)]
pub struct BudgetScope {
    /// Organization identifier at the top of the hierarchy.
    pub org: Option<String>,
    /// Team identifier within the organization.
    pub team: Option<String>,
    /// Project identifier within the team.
    pub project: Option<String>,
    /// End-user identifier within the project.
    pub user: Option<String>,
    /// Model name leaf scope.
    pub model: Option<String>,
}

/// Result returned by [`HierarchicalBudget::check_budget`].
#[derive(Debug, PartialEq)]
pub enum BudgetCheckResult {
    /// Spend is within the safe zone (< 80% of limit by default).
    Ok,
    /// Spend is in the warning zone (>= 80% of limit).  Contains the current
    /// utilization as a percentage (0.0 – 100.0).
    Warning(f64),
    /// Spend has met or exceeded the limit.  Contains utilization as a
    /// percentage (>= 100.0).
    Exceeded(f64),
}

/// Thread-safe hierarchical budget tracker.
///
/// Each scope key maps to a `(limit, spent)` tuple. If no limit has been
/// set for a scope, [`HierarchicalBudget::check_budget`] returns
/// [`BudgetCheckResult::Ok`].
pub struct HierarchicalBudget {
    /// scope_key -> (limit, spent)
    budgets: Mutex<HashMap<String, (f64, f64)>>,
}

impl HierarchicalBudget {
    /// Create a new, empty `HierarchicalBudget`.
    pub fn new() -> Self {
        Self {
            budgets: Mutex::new(HashMap::new()),
        }
    }

    /// Set the spending limit for the given scope.
    pub fn set_limit(&self, scope: &BudgetScope, limit: f64) {
        let key = Self::scope_key(scope);
        let mut budgets = self.budgets.lock().unwrap();
        let entry = budgets.entry(key).or_insert((0.0, 0.0));
        entry.0 = limit;
    }

    /// Record spend against the given scope.
    ///
    /// If no limit exists yet for this scope, the entry is created with a
    /// limit of 0.0 so that the spend is tracked even before a limit is set.
    pub fn record_spend(&self, scope: &BudgetScope, amount: f64) {
        let key = Self::scope_key(scope);
        let mut budgets = self.budgets.lock().unwrap();
        let entry = budgets.entry(key).or_insert((0.0, 0.0));
        entry.1 += amount;
    }

    /// Check whether the given scope is within budget.
    ///
    /// Returns [`BudgetCheckResult::Ok`] when no limit is set, utilization is
    /// below 80%, in the warning band (80–99.9%), or fully exceeded (>= 100%).
    pub fn check_budget(&self, scope: &BudgetScope) -> BudgetCheckResult {
        let key = Self::scope_key(scope);
        let budgets = self.budgets.lock().unwrap();

        let (limit, spent) = match budgets.get(&key) {
            Some(entry) => *entry,
            None => return BudgetCheckResult::Ok,
        };

        // No limit set yet means unrestricted.
        if limit <= 0.0 {
            return BudgetCheckResult::Ok;
        }

        let utilization = (spent / limit) * 100.0;

        if utilization >= 100.0 {
            BudgetCheckResult::Exceeded(utilization)
        } else if utilization >= 80.0 {
            BudgetCheckResult::Warning(utilization)
        } else {
            BudgetCheckResult::Ok
        }
    }

    /// Return the utilization fraction (0.0 – 1.0) for the given scope.
    ///
    /// Returns 0.0 when no limit is set or the limit is zero.
    pub fn get_utilization(&self, scope: &BudgetScope) -> f64 {
        let key = Self::scope_key(scope);
        let budgets = self.budgets.lock().unwrap();
        match budgets.get(&key) {
            Some((limit, spent)) if *limit > 0.0 => spent / limit,
            _ => 0.0,
        }
    }

    /// Derive a stable string key from a `BudgetScope`.
    fn scope_key(scope: &BudgetScope) -> String {
        format!(
            "org={}:team={}:project={}:user={}:model={}",
            scope.org.as_deref().unwrap_or("*"),
            scope.team.as_deref().unwrap_or("*"),
            scope.project.as_deref().unwrap_or("*"),
            scope.user.as_deref().unwrap_or("*"),
            scope.model.as_deref().unwrap_or("*"),
        )
    }
}

impl Default for HierarchicalBudget {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(org: &str) -> BudgetScope {
        BudgetScope {
            org: Some(org.to_string()),
            team: None,
            project: None,
            user: None,
            model: None,
        }
    }

    fn full_scope(org: &str, team: &str, user: &str) -> BudgetScope {
        BudgetScope {
            org: Some(org.to_string()),
            team: Some(team.to_string()),
            project: None,
            user: Some(user.to_string()),
            model: None,
        }
    }

    #[test]
    fn no_limit_returns_ok() {
        let budget = HierarchicalBudget::new();
        let s = scope("acme");
        assert_eq!(budget.check_budget(&s), BudgetCheckResult::Ok);
    }

    #[test]
    fn set_limit_and_no_spend_returns_ok() {
        let budget = HierarchicalBudget::new();
        let s = scope("acme");
        budget.set_limit(&s, 100.0);
        assert_eq!(budget.check_budget(&s), BudgetCheckResult::Ok);
    }

    #[test]
    fn under_threshold_returns_ok() {
        let budget = HierarchicalBudget::new();
        let s = scope("acme");
        budget.set_limit(&s, 100.0);
        budget.record_spend(&s, 50.0);
        assert_eq!(budget.check_budget(&s), BudgetCheckResult::Ok);
    }

    #[test]
    fn above_warning_threshold_returns_warning() {
        let budget = HierarchicalBudget::new();
        let s = scope("acme");
        budget.set_limit(&s, 100.0);
        budget.record_spend(&s, 85.0);
        match budget.check_budget(&s) {
            BudgetCheckResult::Warning(pct) => {
                assert!((pct - 85.0).abs() < 0.001, "expected ~85%, got {}", pct)
            }
            other => panic!("expected Warning, got {:?}", other),
        }
    }

    #[test]
    fn at_limit_returns_exceeded() {
        let budget = HierarchicalBudget::new();
        let s = scope("acme");
        budget.set_limit(&s, 100.0);
        budget.record_spend(&s, 100.0);
        match budget.check_budget(&s) {
            BudgetCheckResult::Exceeded(pct) => {
                assert!(pct >= 100.0, "expected >= 100%, got {}", pct)
            }
            other => panic!("expected Exceeded, got {:?}", other),
        }
    }

    #[test]
    fn over_limit_returns_exceeded() {
        let budget = HierarchicalBudget::new();
        let s = scope("acme");
        budget.set_limit(&s, 100.0);
        budget.record_spend(&s, 200.0);
        match budget.check_budget(&s) {
            BudgetCheckResult::Exceeded(pct) => assert!(pct >= 200.0),
            other => panic!("expected Exceeded, got {:?}", other),
        }
    }

    #[test]
    fn utilization_fraction_is_correct() {
        let budget = HierarchicalBudget::new();
        let s = scope("acme");
        budget.set_limit(&s, 200.0);
        budget.record_spend(&s, 50.0);
        let u = budget.get_utilization(&s);
        assert!((u - 0.25).abs() < 0.001, "expected 0.25, got {}", u);
    }

    #[test]
    fn distinct_scopes_are_independent() {
        let budget = HierarchicalBudget::new();
        let s1 = scope("org1");
        let s2 = scope("org2");
        budget.set_limit(&s1, 100.0);
        budget.set_limit(&s2, 100.0);
        budget.record_spend(&s1, 95.0);
        budget.record_spend(&s2, 10.0);
        assert!(matches!(
            budget.check_budget(&s1),
            BudgetCheckResult::Warning(_)
        ));
        assert_eq!(budget.check_budget(&s2), BudgetCheckResult::Ok);
    }

    #[test]
    fn full_scope_key_is_distinct_from_partial() {
        let budget = HierarchicalBudget::new();
        let partial = scope("acme");
        let full = full_scope("acme", "eng", "alice");
        budget.set_limit(&partial, 100.0);
        budget.record_spend(&partial, 95.0);
        // Full scope has no limit, should return Ok.
        assert_eq!(budget.check_budget(&full), BudgetCheckResult::Ok);
    }
}
