//! Predictive spend forecasting for AI workload budgeting (WOR-2672 port
//! of `sbproxy-enterprise-ai::billing::forecast`).
//!
//! Uses simple time-series averaging to project future spend and detect
//! whether a given budget will be exceeded within a forecast window.
//!
//! Distinct from [`crate::budget`]'s `soft_landing`: that mechanism warns
//! and downgrades based on how much of the CURRENT period's cap is
//! already used (a fraction-of-cap threshold), evaluated fresh on every
//! request. This module instead extrapolates a trend across `history`
//! (a caller-supplied series of past daily spend) to answer "at this
//! burn rate, when do we run out" - a different question, not a
//! duplicate mechanism, and the two compose: soft-landing can react
//! today while a forecast run periodically over the same cost feed
//! answers "should we raise the budget before that happens."

// --- Types ---

/// A single spend observation at a point in time.
#[derive(Debug, Clone)]
pub struct UsageDataPoint {
    /// Unix timestamp (seconds since epoch) for this observation.
    pub timestamp: u64,
    /// Cost incurred at this data point (in your billing currency).
    pub cost: f64,
}

impl UsageDataPoint {
    /// Create a new data point.
    pub fn new(timestamp: u64, cost: f64) -> Self {
        Self { timestamp, cost }
    }
}

// --- Forecasting ---

/// Forecast future spend over `days_ahead` days using the average daily cost
/// from the provided history.
///
/// Each element of `history` is treated as one day's worth of spend. Returns
/// 0.0 when `history` is empty or `days_ahead` is 0.
pub fn forecast_spend(history: &[UsageDataPoint], days_ahead: u32) -> f64 {
    if history.is_empty() || days_ahead == 0 {
        return 0.0;
    }
    let avg_daily = history.iter().map(|d| d.cost).sum::<f64>() / history.len() as f64;
    avg_daily * days_ahead as f64
}

/// Determine whether the running total plus the forecast will exceed `budget`.
///
/// Returns `true` when the projected total spend exceeds the budget.
pub fn will_exceed_budget(history: &[UsageDataPoint], budget: f64, days_ahead: u32) -> bool {
    let current_total: f64 = history.iter().map(|d| d.cost).sum();
    current_total + forecast_spend(history, days_ahead) > budget
}

/// Return how much budget remains after current spend, or 0.0 if already
/// over budget.
pub fn remaining_budget(history: &[UsageDataPoint], budget: f64) -> f64 {
    let current_total: f64 = history.iter().map(|d| d.cost).sum();
    (budget - current_total).max(0.0)
}

/// Return the number of days until budget exhaustion at the current average
/// daily burn rate. Returns `None` when history is empty or all costs are zero.
pub fn days_until_exhaustion(history: &[UsageDataPoint], budget: f64) -> Option<f64> {
    if history.is_empty() {
        return None;
    }
    let current_total: f64 = history.iter().map(|d| d.cost).sum();
    let avg_daily = current_total / history.len() as f64;
    if avg_daily <= 0.0 {
        return None;
    }
    let remaining = budget - current_total;
    if remaining <= 0.0 {
        return Some(0.0);
    }
    Some(remaining / avg_daily)
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn daily(cost: f64) -> UsageDataPoint {
        UsageDataPoint::new(0, cost)
    }

    #[test]
    fn forecast_spend_empty_history_returns_zero() {
        assert_eq!(forecast_spend(&[], 30), 0.0);
    }

    #[test]
    fn forecast_spend_zero_days_returns_zero() {
        let history = vec![daily(10.0)];
        assert_eq!(forecast_spend(&history, 0), 0.0);
    }

    #[test]
    fn forecast_spend_uniform_history() {
        let history = vec![daily(10.0), daily(10.0), daily(10.0)];
        // avg_daily = 10.0, days_ahead = 7 -> 70.0
        assert!((forecast_spend(&history, 7) - 70.0).abs() < 1e-9);
    }

    #[test]
    fn forecast_spend_variable_history() {
        // avg of [5, 15] = 10 per day, * 3 days = 30
        let history = vec![daily(5.0), daily(15.0)];
        assert!((forecast_spend(&history, 3) - 30.0).abs() < 1e-9);
    }

    #[test]
    fn will_exceed_budget_returns_true_when_over() {
        let history = vec![daily(50.0)]; // already spent 50
                                         // forecast: 50 * 2 = 100 more; total = 150 > 100
        assert!(will_exceed_budget(&history, 100.0, 2));
    }

    #[test]
    fn will_exceed_budget_returns_false_when_under() {
        let history = vec![daily(5.0)]; // spent 5
                                        // forecast: 5 * 10 = 50 more; total = 55 < 1000
        assert!(!will_exceed_budget(&history, 1000.0, 10));
    }

    #[test]
    fn will_exceed_budget_false_for_empty_history() {
        assert!(!will_exceed_budget(&[], 100.0, 30));
    }

    #[test]
    fn remaining_budget_within_limit() {
        let history = vec![daily(30.0), daily(20.0)]; // total 50
        assert!((remaining_budget(&history, 200.0) - 150.0).abs() < 1e-9);
    }

    #[test]
    fn remaining_budget_clamps_to_zero_when_exceeded() {
        let history = vec![daily(300.0)];
        assert_eq!(remaining_budget(&history, 100.0), 0.0);
    }

    #[test]
    fn days_until_exhaustion_returns_correct_value() {
        // spent 60 over 3 days = 20/day avg; budget 200; remaining = 140; 140/20 = 7
        let history = vec![daily(20.0), daily(20.0), daily(20.0)];
        let days = days_until_exhaustion(&history, 200.0).expect("should return value");
        assert!((days - 7.0).abs() < 1e-9);
    }

    #[test]
    fn days_until_exhaustion_zero_when_already_exceeded() {
        let history = vec![daily(200.0)];
        assert_eq!(days_until_exhaustion(&history, 100.0), Some(0.0));
    }

    #[test]
    fn days_until_exhaustion_none_for_empty_history() {
        assert!(days_until_exhaustion(&[], 100.0).is_none());
    }

    #[test]
    fn days_until_exhaustion_none_when_zero_burn_rate() {
        let history = vec![daily(0.0), daily(0.0)];
        assert!(days_until_exhaustion(&history, 100.0).is_none());
    }
}
