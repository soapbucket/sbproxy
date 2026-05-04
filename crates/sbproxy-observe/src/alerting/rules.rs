//! Built-in alert rule evaluators.
//!
//! Each function takes the current metric value(s) and threshold configuration
//! and returns `Some(Alert)` if the condition is met, or `None` if it is not.
//! Callers are responsible for deciding how often to evaluate rules and
//! passing the results to an [`super::channels::AlertDispatcher`].

use super::channels::Alert;
use std::collections::HashMap;

// --- Helper ---

fn now_rfc3339() -> String {
    // Use chrono for a proper RFC 3339 timestamp.
    chrono::Utc::now().to_rfc3339()
}

fn make_alert(
    rule: &str,
    severity: &str,
    message: String,
    labels: HashMap<String, String>,
) -> Alert {
    Alert {
        rule: rule.to_string(),
        severity: severity.to_string(),
        message,
        timestamp: now_rfc3339(),
        labels,
    }
}

// --- Rule: budget exhaustion ---

/// Check whether budget utilization has crossed a warning or critical threshold.
///
/// `utilization` is a value in [0.0, 1.0] representing the fraction of the
/// budget consumed. `thresholds` is an ordered slice of [warning, critical]
/// fractions (e.g. `&[0.80, 0.95]`). The highest breached threshold determines
/// the severity.
///
/// Returns `None` if `utilization` is below all thresholds.
pub fn check_budget_exhaustion(utilization: f64, thresholds: &[f64]) -> Option<Alert> {
    if thresholds.is_empty() {
        return None;
    }

    // Find the highest threshold that has been crossed.
    let mut breached_idx: Option<usize> = None;
    for (i, &threshold) in thresholds.iter().enumerate() {
        if utilization >= threshold {
            breached_idx = Some(i);
        }
    }

    let idx = breached_idx?;

    // Convention: last threshold = critical, everything before = warning.
    let severity = if idx + 1 >= thresholds.len() {
        "critical"
    } else {
        "warning"
    };

    let threshold_pct = (thresholds[idx] * 100.0) as u32;
    let used_pct = (utilization * 100.0) as u32;

    let mut labels = HashMap::new();
    labels.insert("utilization".to_string(), format!("{:.2}", utilization));
    labels.insert("threshold".to_string(), format!("{:.2}", thresholds[idx]));

    Some(make_alert(
        "budget_exhaustion",
        severity,
        format!("Budget utilization {used_pct}% has exceeded the {threshold_pct}% threshold"),
        labels,
    ))
}

// --- Rule: certificate expiry ---

/// Check whether a TLS certificate is approaching expiry.
///
/// `days_remaining` is the number of days until the certificate expires.
/// `warn_days` is an ordered slice of day thresholds from least urgent to
/// most urgent (e.g. `&[30, 7]` means warn at 30 days, critical at 7).
/// The tightest (smallest) breached threshold determines the severity.
///
/// Returns `None` if `days_remaining` is above all thresholds.
pub fn check_cert_expiry(days_remaining: u32, warn_days: &[u32]) -> Option<Alert> {
    if warn_days.is_empty() {
        return None;
    }

    // Find the smallest threshold that days_remaining is still at or below.
    // Iterate all thresholds and track the tightest match.
    let mut breached: Option<u32> = None;
    for &threshold in warn_days.iter() {
        if days_remaining <= threshold {
            breached = Some(match breached {
                None => threshold,
                Some(current) => current.min(threshold),
            });
        }
    }

    let matched_threshold = breached?;

    // The minimum of all thresholds is the most urgent (critical) level.
    let min_threshold = *warn_days.iter().min().unwrap();
    let severity = if matched_threshold == min_threshold {
        "critical"
    } else {
        "warning"
    };

    let mut labels = HashMap::new();
    labels.insert("days_remaining".to_string(), days_remaining.to_string());
    labels.insert("threshold_days".to_string(), matched_threshold.to_string());

    Some(make_alert(
        "cert_expiry",
        severity,
        format!(
            "TLS certificate expires in {days_remaining} days (threshold: {matched_threshold} days)"
        ),
        labels,
    ))
}

// --- Rule: circuit breaker trip ---

/// Generate an alert when a circuit breaker transitions to a new state.
///
/// `origin` is the upstream origin name, `from` is the previous state
/// (e.g. `"closed"`), and `to` is the new state (e.g. `"open"`).
///
/// Always returns `Some(Alert)` because any transition is noteworthy.
/// Severity is `"critical"` when transitioning to `"open"` (upstream down)
/// and `"warning"` for all other transitions.
pub fn check_circuit_breaker_trip(origin: &str, from: &str, to: &str) -> Option<Alert> {
    let severity = if to == "open" { "critical" } else { "warning" };

    let mut labels = HashMap::new();
    labels.insert("origin".to_string(), origin.to_string());
    labels.insert("from_state".to_string(), from.to_string());
    labels.insert("to_state".to_string(), to.to_string());

    Some(make_alert(
        "circuit_breaker_trip",
        severity,
        format!("Circuit breaker for origin '{origin}' transitioned from '{from}' to '{to}'"),
        labels,
    ))
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    // --- Budget exhaustion ---

    #[test]
    fn test_budget_below_all_thresholds_returns_none() {
        assert!(check_budget_exhaustion(0.50, &[0.80, 0.95]).is_none());
    }

    #[test]
    fn test_budget_at_warning_threshold() {
        let alert = check_budget_exhaustion(0.80, &[0.80, 0.95]).unwrap();
        assert_eq!(alert.rule, "budget_exhaustion");
        assert_eq!(alert.severity, "warning");
        assert!(alert.message.contains("80%"));
        assert_eq!(alert.labels["threshold"], "0.80");
    }

    #[test]
    fn test_budget_between_warning_and_critical() {
        let alert = check_budget_exhaustion(0.87, &[0.80, 0.95]).unwrap();
        assert_eq!(alert.severity, "warning");
    }

    #[test]
    fn test_budget_at_critical_threshold() {
        let alert = check_budget_exhaustion(0.95, &[0.80, 0.95]).unwrap();
        assert_eq!(alert.severity, "critical");
        assert!(alert.message.contains("95%"));
    }

    #[test]
    fn test_budget_above_critical_threshold() {
        let alert = check_budget_exhaustion(1.0, &[0.80, 0.95]).unwrap();
        assert_eq!(alert.severity, "critical");
    }

    #[test]
    fn test_budget_empty_thresholds_returns_none() {
        assert!(check_budget_exhaustion(0.99, &[]).is_none());
    }

    #[test]
    fn test_budget_single_threshold_critical() {
        // With one threshold it is always the last = critical.
        let alert = check_budget_exhaustion(0.90, &[0.80]).unwrap();
        assert_eq!(alert.severity, "critical");
    }

    #[test]
    fn test_budget_labels_present() {
        let alert = check_budget_exhaustion(0.82, &[0.80, 0.95]).unwrap();
        assert!(alert.labels.contains_key("utilization"));
        assert!(alert.labels.contains_key("threshold"));
    }

    // --- Certificate expiry ---

    #[test]
    fn test_cert_above_all_thresholds_returns_none() {
        assert!(check_cert_expiry(60, &[30, 7]).is_none());
    }

    #[test]
    fn test_cert_at_warning_threshold() {
        let alert = check_cert_expiry(30, &[30, 7]).unwrap();
        assert_eq!(alert.rule, "cert_expiry");
        assert_eq!(alert.severity, "warning");
        assert!(alert.message.contains("30 days"));
    }

    #[test]
    fn test_cert_between_warning_and_critical() {
        let alert = check_cert_expiry(14, &[30, 7]).unwrap();
        assert_eq!(alert.severity, "warning");
    }

    #[test]
    fn test_cert_at_critical_threshold() {
        let alert = check_cert_expiry(7, &[30, 7]).unwrap();
        assert_eq!(alert.severity, "critical");
        assert!(alert.message.contains("7 days"));
    }

    #[test]
    fn test_cert_below_critical_threshold() {
        let alert = check_cert_expiry(3, &[30, 7]).unwrap();
        assert_eq!(alert.severity, "critical");
    }

    #[test]
    fn test_cert_empty_thresholds_returns_none() {
        assert!(check_cert_expiry(5, &[]).is_none());
    }

    #[test]
    fn test_cert_labels_present() {
        let alert = check_cert_expiry(25, &[30, 7]).unwrap();
        assert!(alert.labels.contains_key("days_remaining"));
        assert!(alert.labels.contains_key("threshold_days"));
        assert_eq!(alert.labels["days_remaining"], "25");
    }

    // --- Circuit breaker ---

    #[test]
    fn test_circuit_breaker_trip_to_open_is_critical() {
        let alert = check_circuit_breaker_trip("api.upstream.com", "closed", "open").unwrap();
        assert_eq!(alert.rule, "circuit_breaker_trip");
        assert_eq!(alert.severity, "critical");
        assert!(alert.message.contains("api.upstream.com"));
        assert!(alert.message.contains("closed"));
        assert!(alert.message.contains("open"));
    }

    #[test]
    fn test_circuit_breaker_trip_to_half_open_is_warning() {
        let alert = check_circuit_breaker_trip("api.upstream.com", "open", "half-open").unwrap();
        assert_eq!(alert.severity, "warning");
    }

    #[test]
    fn test_circuit_breaker_trip_to_closed_is_warning() {
        let alert = check_circuit_breaker_trip("api.upstream.com", "half-open", "closed").unwrap();
        assert_eq!(alert.severity, "warning");
    }

    #[test]
    fn test_circuit_breaker_labels() {
        let alert = check_circuit_breaker_trip("payments.svc", "closed", "open").unwrap();
        assert_eq!(alert.labels["origin"], "payments.svc");
        assert_eq!(alert.labels["from_state"], "closed");
        assert_eq!(alert.labels["to_state"], "open");
    }

    #[test]
    fn test_circuit_breaker_always_returns_some() {
        // Every state transition, regardless of states, produces an alert.
        assert!(check_circuit_breaker_trip("svc", "x", "y").is_some());
    }

    #[test]
    fn test_circuit_breaker_timestamp_present() {
        let alert = check_circuit_breaker_trip("svc", "closed", "open").unwrap();
        assert!(!alert.timestamp.is_empty());
        // Should be a valid RFC 3339 date.
        assert!(alert.timestamp.contains('T'));
    }
}
