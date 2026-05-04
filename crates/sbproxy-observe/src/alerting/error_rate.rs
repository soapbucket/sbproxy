//! Error rate spike alerts.
//!
//! Evaluates whether the observed error rate for an origin has exceeded a
//! configured threshold and returns an [`Alert`] when it has. Error rate is
//! expressed as a value in `[0.0, 1.0]` where `1.0` means 100% errors.

use std::collections::HashMap;

use super::channels::Alert;

/// Configuration for an error rate spike rule.
pub struct ErrorRateRule {
    /// Origin hostname this rule applies to.
    pub origin: String,
    /// Error rate threshold in `[0.0, 1.0]`.  Alerts fire when the observed
    /// rate exceeds this value.
    pub threshold: f64,
}

/// Check whether the observed error rate exceeds the rule threshold.
///
/// Returns `Some(Alert)` when `observed_rate > rule.threshold`.
/// The severity is `"critical"` when the rate exceeds twice the threshold
/// and `"warning"` otherwise.
///
/// Returns `None` when the error rate is within acceptable bounds.
pub fn check_error_rate_spike(rule: &ErrorRateRule, observed_rate: f64) -> Option<Alert> {
    if observed_rate > rule.threshold {
        let severity = if observed_rate > rule.threshold * 2.0 {
            "critical"
        } else {
            "warning"
        };

        let observed_pct = (observed_rate * 100.0) as u32;
        let threshold_pct = (rule.threshold * 100.0) as u32;

        let mut labels = HashMap::new();
        labels.insert("origin".to_string(), rule.origin.clone());
        labels.insert("observed_rate".to_string(), format!("{:.4}", observed_rate));
        labels.insert("threshold".to_string(), format!("{:.4}", rule.threshold));

        Some(Alert {
            rule: "error_rate_spike".to_string(),
            severity: severity.to_string(),
            message: format!(
                "Error rate {observed_pct}% exceeds threshold {threshold_pct}% for origin {}",
                rule.origin
            ),
            timestamp: chrono::Utc::now().to_rfc3339(),
            labels,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(threshold: f64) -> ErrorRateRule {
        ErrorRateRule {
            origin: "api.example.com".to_string(),
            threshold,
        }
    }

    #[test]
    fn no_alert_below_threshold() {
        assert!(check_error_rate_spike(&rule(0.05), 0.03).is_none());
    }

    #[test]
    fn no_alert_at_exact_threshold() {
        assert!(check_error_rate_spike(&rule(0.05), 0.05).is_none());
    }

    #[test]
    fn warning_between_threshold_and_2x() {
        let alert = check_error_rate_spike(&rule(0.05), 0.08).unwrap();
        assert_eq!(alert.rule, "error_rate_spike");
        assert_eq!(alert.severity, "warning");
        assert!(alert.message.contains("api.example.com"));
    }

    #[test]
    fn critical_above_2x_threshold() {
        let alert = check_error_rate_spike(&rule(0.05), 0.15).unwrap();
        assert_eq!(alert.severity, "critical");
    }

    #[test]
    fn labels_contain_origin_and_rates() {
        let alert = check_error_rate_spike(&rule(0.10), 0.20).unwrap();
        assert_eq!(
            alert.labels.get("origin").map(String::as_str),
            Some("api.example.com")
        );
        assert!(alert.labels.contains_key("observed_rate"));
        assert!(alert.labels.contains_key("threshold"));
    }

    #[test]
    fn timestamp_is_set() {
        let alert = check_error_rate_spike(&rule(0.01), 0.50).unwrap();
        assert!(alert.timestamp.contains('T'));
    }

    #[test]
    fn full_error_rate_is_critical() {
        // 100% error rate should always be critical regardless of threshold.
        let alert = check_error_rate_spike(&rule(0.05), 1.0).unwrap();
        assert_eq!(alert.severity, "critical");
    }
}
