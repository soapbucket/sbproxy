//! Route low-priority requests to cheaper models.
//!
//! When a request carries a priority header whose numeric value is at or above
//! a configured threshold, it is considered "low priority" and should be
//! redirected to a cheaper model instead of the requested one.

/// Configuration for request degradation.
pub struct DegradationConfig {
    /// Name of the HTTP header used to signal request priority.
    /// Default: `"X-Priority"`.
    pub priority_header: String,
    /// Model identifier to route low-priority requests to.
    pub low_priority_model: String,
    /// Numeric priority value at or above which a request is degraded.
    /// Higher numbers = lower priority (e.g. 5 = background, 1 = urgent).
    pub threshold: u8,
}

impl Default for DegradationConfig {
    fn default() -> Self {
        Self {
            priority_header: "X-Priority".to_string(),
            low_priority_model: "gpt-3.5-turbo".to_string(),
            threshold: 5,
        }
    }
}

/// Return `true` when the request should be degraded to the cheap model.
///
/// Looks up `config.priority_header` (case-insensitive) in `headers` and
/// parses its value as a `u8`.  Returns `true` when the parsed value is
/// greater than or equal to `config.threshold`.
///
/// Returns `false` when the header is absent, unparseable, or below the
/// threshold.
pub fn should_degrade(headers: &[(String, String)], config: &DegradationConfig) -> bool {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(&config.priority_header))
        .and_then(|(_, v)| v.parse::<u8>().ok())
        .map(|p| p >= config.threshold)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> DegradationConfig {
        DegradationConfig {
            priority_header: "X-Priority".to_string(),
            low_priority_model: "gpt-3.5-turbo".to_string(),
            threshold: 5,
        }
    }

    fn header(k: &str, v: &str) -> (String, String) {
        (k.to_string(), v.to_string())
    }

    #[test]
    fn degrade_when_priority_at_threshold() {
        let headers = vec![header("X-Priority", "5")];
        assert!(should_degrade(&headers, &config()));
    }

    #[test]
    fn degrade_when_priority_above_threshold() {
        let headers = vec![header("X-Priority", "10")];
        assert!(should_degrade(&headers, &config()));
    }

    #[test]
    fn no_degrade_when_priority_below_threshold() {
        let headers = vec![header("X-Priority", "1")];
        assert!(!should_degrade(&headers, &config()));
    }

    #[test]
    fn no_degrade_when_header_missing() {
        let headers: Vec<(String, String)> = vec![];
        assert!(!should_degrade(&headers, &config()));
    }

    #[test]
    fn no_degrade_when_header_unparseable() {
        let headers = vec![header("X-Priority", "high")];
        assert!(!should_degrade(&headers, &config()));
    }

    #[test]
    fn header_name_comparison_is_case_insensitive() {
        let headers = vec![header("x-priority", "7")];
        assert!(should_degrade(&headers, &config()));
    }

    #[test]
    fn other_headers_are_ignored() {
        let headers = vec![
            header("Content-Type", "application/json"),
            header("Authorization", "Bearer tok"),
            header("X-Priority", "3"),
        ];
        assert!(!should_degrade(&headers, &config()));
    }

    #[test]
    fn default_config_has_sensible_values() {
        let cfg = DegradationConfig::default();
        assert_eq!(cfg.priority_header, "X-Priority");
        assert_eq!(cfg.threshold, 5);
    }
}
