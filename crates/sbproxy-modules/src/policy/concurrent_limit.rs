//! Concurrent (in-flight) limit policy.
//!
//! Caps the number of concurrent requests globally or per route, IP,
//! API key, or header value.
//! Distinct from `RateLimitPolicy`, which controls *rate* (RPS).

use serde::Deserialize;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;

/// Caps in-flight requests per key, returning a configurable status
/// code (default 503) when the limit is reached.
///
/// Distinct from `RateLimitPolicy`, which controls *rate* (RPS).
/// Concurrent limits protect backends with low concurrency budgets:
/// legacy SOAP services, DB-bound endpoints, GPU inference workers.
///
/// Keys are derived per request by `key_by`:
///   * `global` (default): one counter for the policy mount;
///   * `ip`: one counter per client IP;
///   * `api_key`: one counter per `X-Api-Key` header value (or
///     `Authorization: Bearer …` when api-key auth is not used).
///   * `route`: one counter per request path;
///   * `header:<name>`: one counter per value of the named header.
///
/// The legacy `key` field and its `origin` value remain accepted.
///
/// Each accepted request takes a permit; the permit is released in
/// the response phase. If acquisition would exceed `max`, the
/// request is rejected immediately.
pub struct ConcurrentLimitPolicy {
    /// Maximum concurrent requests per key.
    pub max: u32,
    /// Key strategy. `key_by` is the preferred config spelling;
    /// legacy `key` remains accepted.
    pub key: String,
    /// HTTP status returned when the limit is exceeded. Default 503.
    pub status: u16,
    /// Optional response body for rejections.
    pub error_body: Option<String>,
    /// Counters keyed by the resolved key string.
    counters: Arc<dashmap::DashMap<String, Arc<AtomicU32>>>,
    selector: ConcurrentLimitKey,
}

#[derive(Clone, Debug)]
enum ConcurrentLimitKey {
    Global,
    Origin,
    Ip,
    ApiKey,
    Route,
    Header(http::HeaderName),
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
            #[serde(default)]
            key: Option<String>,
            #[serde(default)]
            key_by: Option<String>,
            #[serde(default = "default_status")]
            status: u16,
            #[serde(default)]
            error_body: Option<String>,
        }
        fn default_status() -> u16 {
            503
        }

        let raw: Raw = serde_json::from_value(value)?;
        anyhow::ensure!(raw.max > 0, "concurrent_limit.max must be > 0");
        anyhow::ensure!(
            raw.key.is_none() || raw.key_by.is_none(),
            "concurrent_limit cannot set both legacy 'key' and 'key_by'"
        );
        let key = raw.key_by.or(raw.key).unwrap_or_else(|| "global".into());
        let selector = parse_key_selector(&key)?;
        Ok(Self {
            max: raw.max,
            key,
            status: raw.status,
            error_body: raw.error_body,
            counters: Arc::new(dashmap::DashMap::new()),
            selector,
        })
    }

    /// Resolve the bucket key for a request given the client IP and
    /// request headers, plus origin and route identifiers.
    pub fn resolve_key(
        &self,
        origin_id: &str,
        route_id: &str,
        client_ip: Option<&str>,
        headers: &http::HeaderMap,
    ) -> String {
        match &self.selector {
            ConcurrentLimitKey::Global => "global".to_string(),
            ConcurrentLimitKey::Origin => origin_id.to_string(),
            ConcurrentLimitKey::Ip => client_ip.unwrap_or("0.0.0.0").to_string(),
            ConcurrentLimitKey::ApiKey => {
                if let Some(v) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
                    return v.to_string();
                }
                if let Some(v) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
                    return v.trim_start_matches("Bearer ").to_string();
                }
                "anon".to_string()
            }
            ConcurrentLimitKey::Route => route_id.to_string(),
            ConcurrentLimitKey::Header(name) => headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("missing")
                .to_string(),
        }
    }

    /// Try to acquire a permit. Returns `Some(guard)` when the
    /// permit was issued; the caller must keep the guard alive for
    /// the lifetime of the request, since dropping it releases the slot.
    /// Returns `None` when the limit is already saturated; the
    /// caller should reject the request with `self.status`.
    pub fn try_acquire(&self, key: &str) -> Option<ConcurrentLimitGuard> {
        use std::sync::atomic::Ordering;
        let counter = Arc::clone(
            self.counters
                .entry(key.to_string())
                .or_insert_with(|| Arc::new(AtomicU32::new(0)))
                .value(),
        );
        if counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < self.max).then_some(current + 1)
            })
            .is_err()
        {
            return None;
        }
        Some(ConcurrentLimitGuard {
            counters: Arc::clone(&self.counters),
            key: key.to_string(),
            counter,
        })
    }
}

fn parse_key_selector(value: &str) -> anyhow::Result<ConcurrentLimitKey> {
    match value {
        "global" => Ok(ConcurrentLimitKey::Global),
        "origin" => Ok(ConcurrentLimitKey::Origin),
        "ip" => Ok(ConcurrentLimitKey::Ip),
        "api_key" => Ok(ConcurrentLimitKey::ApiKey),
        "route" => Ok(ConcurrentLimitKey::Route),
        _ => {
            let Some(name) = value.strip_prefix("header:") else {
                anyhow::bail!(
                    "concurrent_limit.key_by must be 'global', 'ip', 'api_key', 'route', or 'header:<name>' (got '{value}')"
                );
            };
            anyhow::ensure!(
                !name.is_empty(),
                "concurrent_limit.key_by header name cannot be empty"
            );
            let name = http::HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                anyhow::anyhow!("invalid concurrent_limit.key_by header '{name}': {error}")
            })?;
            Ok(ConcurrentLimitKey::Header(name))
        }
    }
}

/// RAII handle that releases a concurrent-limit permit when dropped.
pub struct ConcurrentLimitGuard {
    counters: Arc<dashmap::DashMap<String, Arc<AtomicU32>>>,
    key: String,
    counter: Arc<AtomicU32>,
}

impl Drop for ConcurrentLimitGuard {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        let previous = self.counter.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "concurrent-limit guard underflow");
        if previous == 1 {
            self.counters.remove_if(&self.key, |_, candidate| {
                Arc::ptr_eq(candidate, &self.counter) && candidate.load(Ordering::Acquire) == 0
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(config: serde_json::Value) -> ConcurrentLimitPolicy {
        ConcurrentLimitPolicy::from_config(config).expect("valid concurrent limit")
    }

    fn resolved(
        policy: &ConcurrentLimitPolicy,
        origin: &str,
        route: &str,
        client_ip: Option<&str>,
        headers: &http::HeaderMap,
    ) -> String {
        policy.resolve_key(origin, route, client_ip, headers)
    }

    #[test]
    fn omitted_selector_preserves_one_shared_budget() {
        let policy = policy(serde_json::json!({"max": 1}));
        let headers = http::HeaderMap::new();
        let first_key = resolved(&policy, "origin-a", "/one", Some("192.0.2.1"), &headers);
        let second_key = resolved(&policy, "origin-b", "/two", Some("192.0.2.2"), &headers);

        assert_eq!(first_key, second_key);
        let _guard = policy.try_acquire(&first_key).expect("first permit");
        assert!(policy.try_acquire(&second_key).is_none());
    }

    #[test]
    fn header_selector_gives_distinct_clients_independent_budgets() {
        let policy = policy(serde_json::json!({
            "max": 1,
            "key_by": "header:x-tenant"
        }));
        let mut alpha_headers = http::HeaderMap::new();
        alpha_headers.insert("x-tenant", "alpha".parse().unwrap());
        let mut beta_headers = http::HeaderMap::new();
        beta_headers.insert("x-tenant", "beta".parse().unwrap());
        let alpha = resolved(&policy, "origin", "/", None, &alpha_headers);
        let beta = resolved(&policy, "origin", "/", None, &beta_headers);

        let _alpha_guard = policy.try_acquire(&alpha).expect("alpha permit");
        assert!(policy.try_acquire(&alpha).is_none());
        let _beta_guard = policy.try_acquire(&beta).expect("beta permit");
    }

    #[test]
    fn vocabulary_resolves_ip_api_key_route_and_global() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-api-key", "key-123".parse().unwrap());

        let ip = policy(serde_json::json!({"max": 1, "key_by": "ip"}));
        assert_eq!(
            resolved(&ip, "origin", "/v1/items", Some("192.0.2.9"), &headers),
            "192.0.2.9"
        );

        let api_key = policy(serde_json::json!({"max": 1, "key_by": "api_key"}));
        assert_eq!(
            resolved(&api_key, "origin", "/v1/items", Some("192.0.2.9"), &headers),
            "key-123"
        );

        let route = policy(serde_json::json!({"max": 1, "key_by": "route"}));
        assert_eq!(
            resolved(&route, "origin", "/v1/items", Some("192.0.2.9"), &headers),
            "/v1/items"
        );

        let global = policy(serde_json::json!({"max": 1, "key_by": "global"}));
        assert_eq!(
            resolved(&global, "origin", "/v1/items", Some("192.0.2.9"), &headers),
            "global"
        );
    }

    #[test]
    fn legacy_key_field_remains_supported() {
        let policy = policy(serde_json::json!({"max": 1, "key": "origin"}));
        assert_eq!(
            resolved(&policy, "legacy-origin", "/", None, &http::HeaderMap::new()),
            "legacy-origin"
        );
    }

    #[test]
    fn idle_keys_are_removed_under_high_cardinality_churn() {
        let policy = policy(serde_json::json!({"max": 1, "key_by": "ip"}));

        for index in 0..10_000 {
            let key = format!("192.0.2.{index}");
            let guard = policy.try_acquire(&key).expect("permit");
            drop(guard);
        }

        assert!(
            policy.counters.is_empty(),
            "idle key map retained {} entries",
            policy.counters.len()
        );
    }

    #[test]
    fn guard_releases_during_unwind() {
        let policy = policy(serde_json::json!({"max": 1}));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = policy.try_acquire("global").expect("permit");
            panic!("simulated request panic");
        }));

        assert!(result.is_err());
        assert!(policy.try_acquire("global").is_some());
    }

    #[test]
    fn invalid_or_ambiguous_selectors_fail_compilation() {
        let invalid = ConcurrentLimitPolicy::from_config(serde_json::json!({
            "max": 1,
            "key_by": "header:not a header"
        }))
        .unwrap_err();
        assert!(invalid.to_string().contains("header"));

        let ambiguous = ConcurrentLimitPolicy::from_config(serde_json::json!({
            "max": 1,
            "key": "ip",
            "key_by": "route"
        }))
        .unwrap_err();
        assert!(ambiguous.to_string().contains("both"));
    }
}
