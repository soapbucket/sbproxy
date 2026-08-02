//! WOR-1130: `rate_limit_budget` policy.
//!
//! Per-origin configuration for the process-wide workspace rate-limit
//! budget. The soft / throttle / auto-suspend state machine driven by
//! the top-level `rate_limits:` block lives in this module beside the
//! policy config; `sbproxy-core` only adapts its decisions to HTTP.

use serde::Deserialize;

mod runtime;

pub use runtime::{
    install_registry, registry, AuditRow, BudgetDecision, RateLimitBudgetRegistry, Tier,
    WorkspaceStatus,
};

/// RFC 9239 header emission preferences for a throttled response.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitBudgetHeaders {
    /// Emit the `RateLimit-Limit` / `-Remaining` / `-Reset` set on 429.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Also emit `Retry-After` on 429.
    #[serde(default = "default_true")]
    pub include_retry_after: bool,
    /// Also emit `RateLimit-Policy: <limit>;w=<window>`.
    #[serde(default = "default_true")]
    pub include_ratelimit_policy: bool,
}

impl Default for RateLimitBudgetHeaders {
    fn default() -> Self {
        Self {
            enabled: true,
            include_retry_after: true,
            include_ratelimit_policy: true,
        }
    }
}

fn default_true() -> bool {
    true
}

/// Parsed `rate_limit_budget` policy config.
#[derive(Debug, Clone)]
pub struct RateLimitBudgetPolicy {
    /// RFC 9239 header preferences for throttled responses.
    pub headers: RateLimitBudgetHeaders,
}

impl RateLimitBudgetPolicy {
    /// Build from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            #[serde(rename = "type")]
            _policy_type: Option<String>,
            #[serde(default)]
            headers: RateLimitBudgetHeaders,
        }

        anyhow::ensure!(
            value.get("per_route_rps").is_none(),
            "rate_limit_budget.per_route_rps is unsupported: no per-route budget is enforced"
        );
        let raw: Raw = serde_json::from_value(value)?;
        Ok(Self {
            headers: raw.headers,
        })
    }

    /// True when RFC 9239 headers should be emitted on a 429.
    pub fn headers_enabled(&self) -> bool {
        self.headers.enabled
    }

    /// True when `Retry-After` should accompany the 429.
    pub fn include_retry_after(&self) -> bool {
        self.headers.include_retry_after
    }

    /// True when `RateLimit-Policy` should accompany the 429.
    pub fn include_ratelimit_policy(&self) -> bool {
        self.headers.include_ratelimit_policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_config::types::{
        RateLimitClockMode, RateLimitEscalationConfig, RateLimitsConfig, WorkspaceBudgetConfig,
    };

    #[test]
    fn parses_full_header_config() {
        let v = serde_json::json!({
            "type": "rate_limit_budget",
            "headers": {"enabled": true, "include_retry_after": true, "include_ratelimit_policy": true}
        });
        let p = RateLimitBudgetPolicy::from_config(v).unwrap();
        assert!(p.headers_enabled() && p.include_retry_after() && p.include_ratelimit_policy());
    }

    #[test]
    fn defaults_are_lenient() {
        let p =
            RateLimitBudgetPolicy::from_config(serde_json::json!({"type": "rate_limit_budget"}))
                .unwrap();
        assert!(p.headers_enabled());
    }

    #[test]
    fn rejects_unimplemented_per_route_rps_instead_of_ignoring_it() {
        let error = RateLimitBudgetPolicy::from_config(serde_json::json!({
            "type": "rate_limit_budget",
            "per_route_rps": 100
        }))
        .expect_err("per_route_rps has no runtime owner");

        assert!(
            error.to_string().contains("per_route_rps"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn state_machine_exercises_soft_throttle_suspend_and_cooldown() {
        let registry = RateLimitBudgetRegistry::new(&RateLimitsConfig {
            workspace_default: WorkspaceBudgetConfig {
                http_rps_sustained: 2,
                http_rps_burst: 3,
                soft_threshold_rps: Some(2),
            },
            escalation: RateLimitEscalationConfig {
                abuse_threshold_throttle_to_suspend: 2,
                auto_suspend_cooldown_secs: 10,
            },
            clock: RateLimitClockMode::Manual,
        });

        assert_eq!(registry.check("workspace").tier, Tier::Normal);
        assert_eq!(registry.check("workspace").tier, Tier::Soft);
        assert_eq!(registry.check("workspace").tier, Tier::Soft);

        let throttled = registry.check("workspace");
        assert!(!throttled.allowed);
        assert_eq!(throttled.tier, Tier::Throttle);

        let suspended = registry.check("workspace");
        assert!(!suspended.allowed);
        assert_eq!(suspended.tier, Tier::AutoSuspend);
        assert_eq!(suspended.limit, 1);

        assert!(registry.advance_clock(std::time::Duration::from_secs(10)));
        assert_eq!(registry.effective("workspace"), (2, Tier::Throttle));
    }
}
