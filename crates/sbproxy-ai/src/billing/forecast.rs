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

/// Sum a spend series exactly, refusing a cost that cannot be added.
///
/// The sibling chargeback module refuses this class through
/// `checked_money_add`, and for the same reason: an unchecked `sum()` over
/// a series holding one `f64::NAN` produces a total that makes every later
/// comparison false, so a budget check answers "no" rather than failing.
/// Absorption is refused in both directions too, because a total that
/// silently swallowed a day's spend is not the total anybody asked for.
fn checked_total(history: &[UsageDataPoint]) -> Option<f64> {
    history.iter().try_fold(0.0_f64, |total, point| {
        let sum = total + point.cost;
        if !sum.is_finite()
            || (point.cost > 0.0 && sum == total)
            || (total > 0.0 && sum == point.cost)
        {
            None
        } else {
            Some(sum)
        }
    })
}

/// Forecast future spend over `days_ahead` days using the average daily cost
/// from the provided history.
///
/// Each element of `history` is treated as one day's worth of spend. Returns
/// `Some(0.0)` when `history` is empty or `days_ahead` is 0, and `None` when
/// the series cannot be summed exactly, which is a refusal to answer rather
/// than a projection of zero.
pub fn forecast_spend(history: &[UsageDataPoint], days_ahead: u32) -> Option<f64> {
    if history.is_empty() || days_ahead == 0 {
        return Some(0.0);
    }
    let avg_daily = checked_total(history)? / history.len() as f64;
    let projected = avg_daily * f64::from(days_ahead);
    projected.is_finite().then_some(projected)
}

/// Determine whether the running total plus the forecast will exceed `budget`.
///
/// Returns `Some(true)` when the projected total spend exceeds the budget,
/// and `None` when the series or the budget cannot support the comparison.
pub fn will_exceed_budget(
    history: &[UsageDataPoint],
    budget: f64,
    days_ahead: u32,
) -> Option<bool> {
    if !budget.is_finite() {
        return None;
    }
    let current_total = checked_total(history)?;
    let projected = current_total + forecast_spend(history, days_ahead)?;
    projected.is_finite().then_some(projected > budget)
}

/// Return how much budget remains after current spend, or 0.0 if already
/// over budget. `None` when the series or the budget cannot support the
/// subtraction.
pub fn remaining_budget(history: &[UsageDataPoint], budget: f64) -> Option<f64> {
    if !budget.is_finite() {
        return None;
    }
    let current_total = checked_total(history)?;
    Some((budget - current_total).max(0.0))
}

/// Return the number of days until budget exhaustion at the current average
/// daily burn rate. Returns `None` when history is empty, when all costs are
/// zero, or when the series or the budget cannot support the projection.
pub fn days_until_exhaustion(history: &[UsageDataPoint], budget: f64) -> Option<f64> {
    if history.is_empty() || !budget.is_finite() {
        return None;
    }
    let current_total = checked_total(history)?;
    let avg_daily = current_total / history.len() as f64;
    if avg_daily <= 0.0 {
        return None;
    }
    let remaining = budget - current_total;
    if remaining <= 0.0 {
        return Some(0.0);
    }
    let days = remaining / avg_daily;
    days.is_finite().then_some(days)
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
        assert_eq!(forecast_spend(&[], 30), Some(0.0));
    }

    #[test]
    fn forecast_spend_zero_days_returns_zero() {
        let history = vec![daily(10.0)];
        assert_eq!(forecast_spend(&history, 0), Some(0.0));
    }

    #[test]
    fn forecast_spend_uniform_history() {
        let history = vec![daily(10.0), daily(10.0), daily(10.0)];
        // avg_daily = 10.0, days_ahead = 7 -> 70.0
        assert!((forecast_spend(&history, 7).expect("exact history") - 70.0).abs() < 1e-9);
    }

    #[test]
    fn forecast_spend_variable_history() {
        // avg of [5, 15] = 10 per day, * 3 days = 30
        let history = vec![daily(5.0), daily(15.0)];
        assert!((forecast_spend(&history, 3).expect("exact history") - 30.0).abs() < 1e-9);
    }

    #[test]
    fn will_exceed_budget_returns_true_when_over() {
        let history = vec![daily(50.0)]; // already spent 50
                                         // forecast: 50 * 2 = 100 more; total = 150 > 100
        assert_eq!(will_exceed_budget(&history, 100.0, 2), Some(true));
    }

    #[test]
    fn will_exceed_budget_returns_false_when_under() {
        let history = vec![daily(5.0)]; // spent 5
                                        // forecast: 5 * 10 = 50 more; total = 55 < 1000
        assert_eq!(will_exceed_budget(&history, 1000.0, 10), Some(false));
    }

    #[test]
    fn will_exceed_budget_false_for_empty_history() {
        assert_eq!(will_exceed_budget(&[], 100.0, 30), Some(false));
    }

    #[test]
    fn remaining_budget_within_limit() {
        let history = vec![daily(30.0), daily(20.0)]; // total 50
        assert!((remaining_budget(&history, 200.0).expect("exact history") - 150.0).abs() < 1e-9);
    }

    #[test]
    fn remaining_budget_clamps_to_zero_when_exceeded() {
        let history = vec![daily(300.0)];
        assert_eq!(remaining_budget(&history, 100.0), Some(0.0));
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

    /// WOR-2661: an unchecked `sum()` over a series holding one `NAN`
    /// makes every later comparison false, so the budget check answers
    /// "you will not exceed it" and the exhaustion check hands a caller
    /// comparing `days < 7.0` a `NaN` that reads as "not soon". The
    /// sibling chargeback module refuses exactly this class through
    /// `checked_money_add`.
    #[test]
    fn a_non_finite_cost_refuses_the_forecast_instead_of_answering_no() {
        for poison in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let history = vec![daily(10.0), daily(poison), daily(10.0)];
            assert_eq!(forecast_spend(&history, 30), None, "{poison}");
            assert_eq!(will_exceed_budget(&history, 100.0, 30), None, "{poison}");
            assert_eq!(remaining_budget(&history, 100.0), None, "{poison}");
            assert_eq!(days_until_exhaustion(&history, 100.0), None, "{poison}");
        }

        // A non-finite budget is refused on the same grounds: nothing can
        // be compared against it.
        let history = vec![daily(10.0), daily(10.0)];
        assert_eq!(will_exceed_budget(&history, f64::NAN, 30), None);
        assert_eq!(remaining_budget(&history, f64::NAN), None);
        assert_eq!(days_until_exhaustion(&history, f64::NAN), None);
    }

    /// A total that absorbs a day's spend is not the total anybody asked
    /// for, so it is refused rather than reported.
    #[test]
    fn an_absorbed_daily_total_refuses_the_forecast() {
        let history = vec![daily(f64::MAX), daily(1.0)];
        assert_eq!(forecast_spend(&history, 30), None);
        assert_eq!(remaining_budget(&history, 100.0), None);
    }
}
