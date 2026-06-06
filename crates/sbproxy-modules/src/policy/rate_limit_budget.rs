//! WOR-1130: `rate_limit_budget` policy.
//!
//! A thin per-origin marker that opts the origin into the process-wide
//! workspace rate-limit budget (the soft / throttle / auto-suspend state
//! machine installed from the top-level `rate_limits:` block). The
//! actual budget check + the RFC 9239 header emission live binary-side
//! in `sbproxy-core` (which owns the budget registry + the response
//! path); this struct just carries the per-origin header preferences and
//! the per-route inner cap so the enforcer can read them.

use serde::Deserialize;

/// RFC 9239 header emission preferences for a throttled response.
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitBudgetPolicy {
    /// Per-(workspace, route) inner cap from A2.5 § "Hot-key
    /// complement". The workspace ceiling is the primary constraint; the
    /// per-route cap guards a single hot route from consuming the whole
    /// workspace budget.
    #[serde(default)]
    pub per_route_rps: Option<u32>,
    /// RFC 9239 header preferences for throttled responses.
    #[serde(default)]
    pub headers: RateLimitBudgetHeaders,
}

impl RateLimitBudgetPolicy {
    /// Build from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
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

    #[test]
    fn parses_full_config() {
        let v = serde_json::json!({
            "per_route_rps": 100,
            "headers": {"enabled": true, "include_retry_after": true, "include_ratelimit_policy": true}
        });
        let p = RateLimitBudgetPolicy::from_config(v).unwrap();
        assert_eq!(p.per_route_rps, Some(100));
        assert!(p.headers_enabled() && p.include_retry_after() && p.include_ratelimit_policy());
    }

    #[test]
    fn defaults_are_lenient() {
        let p =
            RateLimitBudgetPolicy::from_config(serde_json::json!({"type": "rate_limit_budget"}))
                .unwrap();
        assert!(p.headers_enabled());
        assert_eq!(p.per_route_rps, None);
    }
}
