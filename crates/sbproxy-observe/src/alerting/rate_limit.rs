//! Rate limit utilization alerts.
//!
//! Fires an alert when rate limit consumption for an origin or provider exceeds
//! a configured fraction of the allowed limit. The default warning threshold
//! is 80% utilization.

use std::collections::HashMap;

use super::channels::Alert;

/// The default warning threshold: alert when 80% of the rate limit is used.
pub const DEFAULT_WARN_THRESHOLD: f64 = 0.80;

/// Configuration for a rate limit utilization rule.
pub struct RateLimitRule {
    /// Origin or provider this rule applies to.
    pub origin: String,
    /// Utilization fraction `[0.0, 1.0]` at which to fire a warning alert.
    pub warn_threshold: f64,
}

impl Default for RateLimitRule {
    fn default() -> Self {
        Self {
            origin: String::new(),
            warn_threshold: DEFAULT_WARN_THRESHOLD,
        }
    }
}

/// Check whether rate limit utilization exceeds the warning threshold.
///
/// `utilization` is a value in `[0.0, 1.0]` representing the fraction of the
/// rate limit currently consumed. Returns `Some(Alert)` when the utilization
/// exceeds `rule.warn_threshold`. The severity is `"critical"` when at or
/// above 95% and `"warning"` otherwise.
///
/// Returns `None` when utilization is within acceptable bounds.
pub fn check_rate_limit_approaching(rule: &RateLimitRule, utilization: f64) -> Option<Alert> {
    if utilization > rule.warn_threshold {
        let severity = if utilization >= 0.95 {
            "critical"
        } else {
            "warning"
        };
        let used_pct = (utilization * 100.0) as u32;
        let threshold_pct = (rule.warn_threshold * 100.0) as u32;

        let mut labels = HashMap::new();
        labels.insert("origin".to_string(), rule.origin.clone());
        labels.insert("utilization".to_string(), format!("{:.4}", utilization));
        labels.insert(
            "threshold".to_string(),
            format!("{:.4}", rule.warn_threshold),
        );

        Some(Alert {
            rule: "rate_limit_approaching".to_string(),
            severity: severity.to_string(),
            message: format!(
                "Rate limit utilization {used_pct}% exceeds threshold {threshold_pct}% for origin {}",
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

    fn rule(threshold: f64) -> RateLimitRule {
        RateLimitRule {
            origin: "api.example.com".to_string(),
            warn_threshold: threshold,
        }
    }

    #[test]
    fn no_alert_below_threshold() {
        assert!(check_rate_limit_approaching(&rule(0.80), 0.70).is_none());
    }

    #[test]
    fn no_alert_at_exact_threshold() {
        assert!(check_rate_limit_approaching(&rule(0.80), 0.80).is_none());
    }

    #[test]
    fn warning_between_80_and_95() {
        let alert = check_rate_limit_approaching(&rule(0.80), 0.90).unwrap();
        assert_eq!(alert.rule, "rate_limit_approaching");
        assert_eq!(alert.severity, "warning");
        assert!(alert.message.contains("api.example.com"));
        assert!(alert.message.contains("90%"));
        assert!(alert.message.contains("80%"));
    }

    #[test]
    fn critical_at_or_above_95() {
        let alert = check_rate_limit_approaching(&rule(0.80), 0.95).unwrap();
        assert_eq!(alert.severity, "critical");
    }

    #[test]
    fn critical_at_100_percent() {
        let alert = check_rate_limit_approaching(&rule(0.80), 1.0).unwrap();
        assert_eq!(alert.severity, "critical");
    }

    #[test]
    fn labels_contain_origin_and_utilization() {
        let alert = check_rate_limit_approaching(&rule(0.80), 0.85).unwrap();
        assert_eq!(
            alert.labels.get("origin").map(String::as_str),
            Some("api.example.com")
        );
        assert!(alert.labels.contains_key("utilization"));
        assert!(alert.labels.contains_key("threshold"));
    }

    #[test]
    fn default_rule_has_80_percent_threshold() {
        let rule = RateLimitRule::default();
        assert_eq!(rule.warn_threshold, DEFAULT_WARN_THRESHOLD);
    }

    #[test]
    fn timestamp_is_set() {
        let alert = check_rate_limit_approaching(&rule(0.50), 0.80).unwrap();
        assert!(alert.timestamp.contains('T'));
    }
}
