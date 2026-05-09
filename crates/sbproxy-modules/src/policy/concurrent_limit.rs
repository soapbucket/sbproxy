//! Concurrent (in-flight) limit policy.
//!
//! Caps the number of concurrent requests per route, IP, or API key.
//! Distinct from `RateLimitPolicy`, which controls *rate* (RPS).

use serde::Deserialize;

/// Caps in-flight requests per key, returning a configurable status
/// code (default 503) when the limit is reached.
///
/// Distinct from `RateLimitPolicy`, which controls *rate* (RPS).
/// Concurrent limits protect backends with low concurrency budgets:
/// legacy SOAP services, DB-bound endpoints, GPU inference workers.
///
/// Keys are derived per request by `key`:
///   * `origin` (default): one global counter for the whole route;
///   * `ip`: one counter per client IP;
///   * `api_key`: one counter per `X-Api-Key` header value (or
///     `Authorization: Bearer …` when api-key auth is not used).
///
/// Each accepted request takes a permit; the permit is released in
/// the response phase. If acquisition would exceed `max`, the
/// request is rejected immediately.
pub struct ConcurrentLimitPolicy {
    /// Maximum concurrent requests per key.
    pub max: u32,
    /// Key strategy: `origin`, `ip`, or `api_key`.
    pub key: String,
    /// HTTP status returned when the limit is exceeded. Default 503.
    pub status: u16,
    /// Optional response body for rejections.
    pub error_body: Option<String>,
    /// Counters keyed by the resolved key string.
    counters: std::sync::Arc<dashmap::DashMap<String, std::sync::atomic::AtomicU32>>,
}

impl std::fmt::Debug for ConcurrentLimitPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConcurrentLimitPolicy")
            .field("max", &self.max)
            .field("key", &self.key)
            .field("status", &self.status)
            .field("active_keys", &self.counters.len())
            .finish()
    }
}

impl ConcurrentLimitPolicy {
    /// Build from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        struct Raw {
            max: u32,
            #[serde(default = "default_key")]
            key: String,
            #[serde(default = "default_status")]
            status: u16,
            #[serde(default)]
            error_body: Option<String>,
        }
        fn default_key() -> String {
            "origin".to_string()
        }
        fn default_status() -> u16 {
            503
        }

        let raw: Raw = serde_json::from_value(value)?;
        anyhow::ensure!(raw.max > 0, "concurrent_limit.max must be > 0");
        match raw.key.as_str() {
            "origin" | "ip" | "api_key" => {}
            other => anyhow::bail!(
                "concurrent_limit.key must be 'origin', 'ip', or 'api_key' (got '{other}')"
            ),
        }
        Ok(Self {
            max: raw.max,
            key: raw.key,
            status: raw.status,
            error_body: raw.error_body,
            counters: std::sync::Arc::new(dashmap::DashMap::new()),
        })
    }

    /// Resolve the bucket key for a request given the client IP and
    /// request headers, plus an origin identifier used as the bucket
    /// when `key = "origin"`.
    pub fn resolve_key(
        &self,
        origin_id: &str,
        client_ip: Option<&str>,
        headers: &http::HeaderMap,
    ) -> String {
        match self.key.as_str() {
            "ip" => client_ip.unwrap_or("0.0.0.0").to_string(),
            "api_key" => {
                if let Some(v) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
                    return v.to_string();
                }
                if let Some(v) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
                    return v.trim_start_matches("Bearer ").to_string();
                }
                "anon".to_string()
            }
            _ => origin_id.to_string(),
        }
    }

    /// Try to acquire a permit. Returns `Some(guard)` when the
    /// permit was issued; the caller must keep the guard alive for
    /// the lifetime of the request, since dropping it releases the slot.
    /// Returns `None` when the limit is already saturated; the
    /// caller should reject the request with `self.status`.
    pub fn try_acquire(&self, key: &str) -> Option<ConcurrentLimitGuard> {
        use std::sync::atomic::Ordering;
        let entry = self
            .counters
            .entry(key.to_string())
            .or_insert_with(|| std::sync::atomic::AtomicU32::new(0));
        let prev = entry.value().fetch_add(1, Ordering::AcqRel);
        if prev >= self.max {
            // Roll back the increment.
            entry.value().fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(ConcurrentLimitGuard {
            counters: std::sync::Arc::clone(&self.counters),
            key: key.to_string(),
        })
    }
}

/// RAII handle that releases a concurrent-limit permit when dropped.
pub struct ConcurrentLimitGuard {
    counters: std::sync::Arc<dashmap::DashMap<String, std::sync::atomic::AtomicU32>>,
    key: String,
}

impl Drop for ConcurrentLimitGuard {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        if let Some(entry) = self.counters.get(&self.key) {
            entry.value().fetch_sub(1, Ordering::AcqRel);
        }
    }
}
