//! Hedged requests - sends a duplicate request after a delay if the first
//! has not responded, returning whichever completes first.

use serde::Deserialize;
use std::time::Duration;

/// Configuration for hedged request behavior.
#[derive(Debug, Clone, Deserialize)]
pub struct HedgingConfig {
    /// Delay before sending the hedge request (milliseconds).
    pub delay_ms: u64,

    /// Maximum number of concurrent requests (including the original).
    #[serde(default = "default_max_hedges")]
    pub max_hedges: u32,
}

fn default_max_hedges() -> u32 {
    2
}

impl HedgingConfig {
    /// Return the delay before sending a hedge request.
    pub fn delay(&self) -> Duration {
        Duration::from_millis(self.delay_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_returns_correct_duration() {
        let config = HedgingConfig {
            delay_ms: 150,
            max_hedges: 2,
        };
        assert_eq!(config.delay(), Duration::from_millis(150));
    }

    #[test]
    fn delay_zero_is_valid() {
        let config = HedgingConfig {
            delay_ms: 0,
            max_hedges: 2,
        };
        assert_eq!(config.delay(), Duration::ZERO);
    }

    #[test]
    fn deserialize_with_defaults() {
        let json = r#"{"delay_ms": 200}"#;
        let config: HedgingConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.delay_ms, 200);
        assert_eq!(config.max_hedges, 2);
    }

    #[test]
    fn deserialize_full_config() {
        let json = r#"{"delay_ms": 100, "max_hedges": 3}"#;
        let config: HedgingConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.delay_ms, 100);
        assert_eq!(config.max_hedges, 3);
    }
}
