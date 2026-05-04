//! AI provider degradation alerts.
//!
//! Detects when a provider's current latency significantly exceeds its baseline
//! and emits a structured alert. A provider is considered degraded when the
//! observed latency is greater than 2x the baseline.

use std::collections::HashMap;

/// A provider degradation alert payload.
#[derive(Debug, Clone)]
pub struct Alert {
    /// The rule name that generated this alert.
    pub rule: String,
    /// Alert severity: `"warning"` or `"critical"`.
    pub severity: String,
    /// Human-readable description.
    pub message: String,
    /// RFC 3339 timestamp.
    pub timestamp: String,
    /// Structured labels for routing and grouping.
    pub labels: HashMap<String, String>,
}

/// Check whether a provider's current latency indicates degradation.
///
/// Returns `Some(Alert)` when `current_latency_ms > baseline_latency_ms * 2.0`.
/// Severity is `"critical"` when latency exceeds 5x baseline, `"warning"`
/// otherwise.
///
/// Returns `None` when the provider is performing within acceptable bounds.
pub fn check_provider_degradation(
    provider: &str,
    current_latency_ms: f64,
    baseline_latency_ms: f64,
) -> Option<Alert> {
    if baseline_latency_ms <= 0.0 {
        return None;
    }

    let ratio = current_latency_ms / baseline_latency_ms;

    if ratio > 2.0 {
        let severity = if ratio > 5.0 { "critical" } else { "warning" };

        let mut labels = HashMap::new();
        labels.insert("provider".to_string(), provider.to_string());
        labels.insert(
            "current_latency_ms".to_string(),
            current_latency_ms.to_string(),
        );
        labels.insert(
            "baseline_latency_ms".to_string(),
            baseline_latency_ms.to_string(),
        );
        labels.insert("ratio".to_string(), format!("{:.2}", ratio));

        Some(Alert {
            rule: "provider_degradation".to_string(),
            severity: severity.to_string(),
            message: format!(
                "Provider '{provider}' latency {current_latency_ms}ms is {ratio:.1}x baseline \
                 {baseline_latency_ms}ms"
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

    #[test]
    fn no_alert_below_2x() {
        assert!(check_provider_degradation("openai", 150.0, 100.0).is_none());
    }

    #[test]
    fn no_alert_at_exactly_2x() {
        assert!(check_provider_degradation("openai", 200.0, 100.0).is_none());
    }

    #[test]
    fn warning_between_2x_and_5x() {
        let alert = check_provider_degradation("openai", 350.0, 100.0).unwrap();
        assert_eq!(alert.rule, "provider_degradation");
        assert_eq!(alert.severity, "warning");
        assert!(alert.message.contains("openai"));
        assert!(alert.message.contains("350"));
    }

    #[test]
    fn critical_above_5x() {
        let alert = check_provider_degradation("anthropic", 600.0, 100.0).unwrap();
        assert_eq!(alert.severity, "critical");
    }

    #[test]
    fn labels_contain_provider_and_latencies() {
        let alert = check_provider_degradation("cohere", 400.0, 80.0).unwrap();
        assert_eq!(
            alert.labels.get("provider").map(String::as_str),
            Some("cohere")
        );
        assert!(alert.labels.contains_key("current_latency_ms"));
        assert!(alert.labels.contains_key("baseline_latency_ms"));
        assert!(alert.labels.contains_key("ratio"));
    }

    #[test]
    fn zero_baseline_returns_none() {
        // Avoid division by zero.
        assert!(check_provider_degradation("openai", 100.0, 0.0).is_none());
    }

    #[test]
    fn timestamp_is_set() {
        let alert = check_provider_degradation("openai", 500.0, 100.0).unwrap();
        assert!(alert.timestamp.contains('T'));
    }
}
