//! Latency SLO violation alerts.
//!
//! Evaluates whether observed p99 latency exceeds a configured threshold and
//! returns an [`Alert`] if so. The alert is `"critical"` when the observed
//! value is more than twice the threshold, `"warning"` otherwise.

use std::collections::HashMap;

use super::channels::Alert;

/// Configuration for a single latency SLO rule.
pub struct SloRule {
    /// Origin hostname this rule applies to.
    pub origin: String,
    /// p99 latency threshold in milliseconds.
    pub p99_threshold_ms: f64,
}

/// Check whether observed p99 latency violates the SLO rule.
///
/// Returns `Some(Alert)` when `observed_p99_ms > rule.p99_threshold_ms`.
/// The severity is `"critical"` when the observed value exceeds twice the
/// threshold and `"warning"` when it is between the threshold and 2x.
///
/// Returns `None` when the SLO is satisfied.
pub fn check_slo_violation(rule: &SloRule, observed_p99_ms: f64) -> Option<Alert> {
    if observed_p99_ms > rule.p99_threshold_ms {
        let severity = if observed_p99_ms > rule.p99_threshold_ms * 2.0 {
            "critical"
        } else {
            "warning"
        };

        let mut labels = HashMap::new();
        labels.insert("origin".to_string(), rule.origin.clone());
        labels.insert("observed_p99_ms".to_string(), observed_p99_ms.to_string());
        labels.insert(
            "threshold_ms".to_string(),
            rule.p99_threshold_ms.to_string(),
        );

        Some(Alert {
            rule: "latency_slo".to_string(),
            severity: severity.to_string(),
            message: format!(
                "p99 latency {observed_p99_ms}ms exceeds threshold {}ms for origin {}",
                rule.p99_threshold_ms, rule.origin
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

    fn rule(threshold: f64) -> SloRule {
        SloRule {
            origin: "api.example.com".to_string(),
            p99_threshold_ms: threshold,
        }
    }

    #[test]
    fn no_alert_when_below_threshold() {
        assert!(check_slo_violation(&rule(200.0), 150.0).is_none());
    }

    #[test]
    fn no_alert_when_exactly_at_threshold() {
        assert!(check_slo_violation(&rule(200.0), 200.0).is_none());
    }

    #[test]
    fn warning_when_between_threshold_and_2x() {
        let alert = check_slo_violation(&rule(200.0), 300.0).unwrap();
        assert_eq!(alert.rule, "latency_slo");
        assert_eq!(alert.severity, "warning");
        assert!(alert.message.contains("300"));
        assert!(alert.message.contains("200"));
        assert!(alert.message.contains("api.example.com"));
    }

    #[test]
    fn critical_when_above_2x_threshold() {
        let alert = check_slo_violation(&rule(200.0), 500.0).unwrap();
        assert_eq!(alert.severity, "critical");
    }

    #[test]
    fn alert_labels_contain_origin_and_latency() {
        let alert = check_slo_violation(&rule(100.0), 250.0).unwrap();
        assert_eq!(
            alert.labels.get("origin").map(String::as_str),
            Some("api.example.com")
        );
        assert!(alert.labels.contains_key("observed_p99_ms"));
        assert!(alert.labels.contains_key("threshold_ms"));
    }

    #[test]
    fn timestamp_is_set() {
        let alert = check_slo_violation(&rule(100.0), 200.0).unwrap();
        assert!(alert.timestamp.contains('T'));
    }
}
