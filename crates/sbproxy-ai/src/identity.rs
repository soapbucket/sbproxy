//! Virtual API key management and per-key rate limiting.

use parking_lot::Mutex;
use serde::Deserialize;
use std::collections::HashMap;

/// Virtual API key configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct VirtualKeyConfig {
    /// The virtual key string used for authentication.
    pub key: String,
    /// Human-readable name for this key.
    #[serde(default)]
    pub name: Option<String>,
    /// Models this key is allowed to use (empty = all).
    #[serde(default)]
    pub allowed_models: Vec<String>,
    /// Models this key is explicitly blocked from using.
    #[serde(default)]
    pub blocked_models: Vec<String>,
    /// Providers this key is allowed to use (empty = all).
    #[serde(default)]
    pub allowed_providers: Vec<String>,
    /// Maximum tokens per minute for this key.
    #[serde(default)]
    pub max_tokens_per_minute: Option<u64>,
    /// Maximum requests per minute for this key.
    #[serde(default)]
    pub max_requests_per_minute: Option<u64>,
    /// Per-key budget limits.
    #[serde(default)]
    pub budget: Option<KeyBudget>,
    /// Tags for grouping and tracking.
    #[serde(default)]
    pub tags: Vec<String>,
    /// WOR-894: project this key belongs to. Surfaced on run-metadata
    /// (access log) so reports can group spend / usage by project.
    #[serde(default)]
    pub project: Option<String>,
    /// WOR-894: user (or principal) this key belongs to. Same path as
    /// [`Self::project`] for per-user breakdowns.
    #[serde(default)]
    pub user: Option<String>,
    /// WOR-894: arbitrary string-keyed metadata. Surfaced on the access
    /// log as a JSON object so reports can group by a custom dimension.
    /// Kept off metric labels to avoid cardinality blow-up.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    /// WOR-893: pin a specific model for requests authenticated by this
    /// key. When set, the gateway overwrites the request body's `model`
    /// field with this value before the routing / model-gate / dispatch
    /// runs - the client cannot pick a different model. Composes with
    /// the existing `allowed_models` / `blocked_models` gates: if the
    /// pinned model is itself blocked or not allow-listed, the request
    /// is rejected with the same 403 a direct client request would
    /// receive. `None` keeps the client's `model` field unchanged.
    #[serde(default)]
    pub route_to_model: Option<String>,
    /// Whether this key is active.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Skip the body-aware `prompt_injection_v2` scan for requests
    /// that authenticate with this virtual key. Defaults to `false`,
    /// meaning every key is scanned by default. Set to `true` for
    /// trusted internal callers (eval pipelines, red-team tooling)
    /// that legitimately submit injection-shaped prompts and would
    /// otherwise self-flag.
    #[serde(default)]
    pub bypass_prompt_injection: bool,
}

fn default_true() -> bool {
    true
}

/// Per-key budget limits.
#[derive(Debug, Clone, Deserialize)]
pub struct KeyBudget {
    /// Maximum total tokens for this key.
    pub max_tokens: Option<u64>,
    /// Maximum total cost in USD for this key.
    pub max_cost_usd: Option<f64>,
}

/// Virtual key store - validates and looks up keys.
pub struct KeyStore {
    keys: HashMap<String, VirtualKeyConfig>,
}

impl KeyStore {
    /// Build a key store from a list of virtual key configs.
    pub fn new(configs: Vec<VirtualKeyConfig>) -> Self {
        let keys = configs.into_iter().map(|k| (k.key.clone(), k)).collect();
        Self { keys }
    }

    /// Look up a key and return its config if it exists and is enabled.
    pub fn validate_key(&self, key: &str) -> Option<&VirtualKeyConfig> {
        self.keys.get(key).filter(|k| k.enabled)
    }

    /// Check if a model is allowed for a given virtual key.
    pub fn is_model_allowed(&self, key: &str, model: &str) -> bool {
        match self.keys.get(key) {
            Some(config) => {
                if !config.blocked_models.is_empty()
                    && config.blocked_models.iter().any(|m| m == model)
                {
                    return false;
                }
                if !config.allowed_models.is_empty() {
                    return config.allowed_models.iter().any(|m| m == model);
                }
                true
            }
            None => false,
        }
    }

    /// Return the number of keys in the store.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

/// Rate limiter per virtual key.
pub struct KeyRateLimiter {
    state: Mutex<HashMap<String, KeyRateState>>,
}

#[derive(Debug, Default)]
struct KeyRateState {
    tokens_this_minute: u64,
    requests_this_minute: u64,
    minute_start: Option<std::time::Instant>,
}

impl Default for KeyRateLimiter {
    fn default() -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
        }
    }
}

impl KeyRateLimiter {
    /// Create a new rate limiter.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a request is within rate limits for a key. Returns true if allowed.
    pub fn check_rate(&self, key: &str, config: &VirtualKeyConfig) -> bool {
        let mut state = self.state.lock();
        let entry = state.entry(key.to_string()).or_default();

        let now = std::time::Instant::now();

        // Reset if minute has elapsed.
        if let Some(start) = entry.minute_start {
            if now.duration_since(start).as_secs() >= 60 {
                *entry = KeyRateState::default();
            }
        }
        if entry.minute_start.is_none() {
            entry.minute_start = Some(now);
        }

        // Check requests per minute.
        if let Some(max_rpm) = config.max_requests_per_minute {
            if entry.requests_this_minute >= max_rpm {
                return false;
            }
        }

        entry.requests_this_minute += 1;
        true
    }

    /// Record token usage for rate tracking.
    pub fn record_tokens(&self, key: &str, tokens: u64) {
        let mut state = self.state.lock();
        if let Some(entry) = state.get_mut(key) {
            entry.tokens_this_minute += tokens;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(key: &str, enabled: bool) -> VirtualKeyConfig {
        VirtualKeyConfig {
            key: key.to_string(),
            name: None,
            allowed_models: vec![],
            blocked_models: vec![],
            allowed_providers: vec![],
            max_tokens_per_minute: None,
            max_requests_per_minute: None,
            budget: None,
            tags: vec![],
            project: None,
            user: None,
            metadata: HashMap::new(),
            route_to_model: None,
            enabled,
            bypass_prompt_injection: false,
        }
    }

    fn make_key_with_models(key: &str, allowed: Vec<&str>, blocked: Vec<&str>) -> VirtualKeyConfig {
        VirtualKeyConfig {
            key: key.to_string(),
            name: None,
            allowed_models: allowed.into_iter().map(String::from).collect(),
            blocked_models: blocked.into_iter().map(String::from).collect(),
            allowed_providers: vec![],
            max_tokens_per_minute: None,
            max_requests_per_minute: None,
            budget: None,
            tags: vec![],
            project: None,
            user: None,
            metadata: HashMap::new(),
            route_to_model: None,
            enabled: true,
            bypass_prompt_injection: false,
        }
    }

    // --- KeyStore tests ---

    #[test]
    fn validate_key_found() {
        let store = KeyStore::new(vec![make_key("sk-test-1", true)]);
        assert!(store.validate_key("sk-test-1").is_some());
    }

    #[test]
    fn validate_key_not_found() {
        let store = KeyStore::new(vec![make_key("sk-test-1", true)]);
        assert!(store.validate_key("sk-unknown").is_none());
    }

    #[test]
    fn validate_key_disabled() {
        let store = KeyStore::new(vec![make_key("sk-disabled", false)]);
        assert!(store.validate_key("sk-disabled").is_none());
    }

    #[test]
    fn is_model_allowed_unrestricted() {
        let store = KeyStore::new(vec![make_key("sk-1", true)]);
        assert!(store.is_model_allowed("sk-1", "gpt-4"));
        assert!(store.is_model_allowed("sk-1", "claude-3"));
    }

    #[test]
    fn is_model_allowed_with_allowlist() {
        let store = KeyStore::new(vec![make_key_with_models(
            "sk-1",
            vec!["gpt-4", "gpt-3.5-turbo"],
            vec![],
        )]);
        assert!(store.is_model_allowed("sk-1", "gpt-4"));
        assert!(store.is_model_allowed("sk-1", "gpt-3.5-turbo"));
        assert!(!store.is_model_allowed("sk-1", "claude-3"));
    }

    #[test]
    fn is_model_blocked() {
        let store = KeyStore::new(vec![make_key_with_models("sk-1", vec![], vec!["gpt-4"])]);
        assert!(!store.is_model_allowed("sk-1", "gpt-4"));
        assert!(store.is_model_allowed("sk-1", "gpt-3.5-turbo"));
    }

    #[test]
    fn is_model_allowed_unknown_key() {
        let store = KeyStore::new(vec![]);
        assert!(!store.is_model_allowed("unknown", "gpt-4"));
    }

    #[test]
    fn key_count() {
        let store = KeyStore::new(vec![make_key("a", true), make_key("b", true)]);
        assert_eq!(store.key_count(), 2);
    }

    // --- KeyRateLimiter tests ---

    #[test]
    fn rate_limiter_within_limit() {
        let limiter = KeyRateLimiter::new();
        let config = VirtualKeyConfig {
            max_requests_per_minute: Some(10),
            ..make_key("sk-1", true)
        };
        assert!(limiter.check_rate("sk-1", &config));
        assert!(limiter.check_rate("sk-1", &config));
    }

    #[test]
    fn rate_limiter_exceeds_rpm() {
        let limiter = KeyRateLimiter::new();
        let config = VirtualKeyConfig {
            max_requests_per_minute: Some(2),
            ..make_key("sk-1", true)
        };
        assert!(limiter.check_rate("sk-1", &config));
        assert!(limiter.check_rate("sk-1", &config));
        // Third request should be blocked.
        assert!(!limiter.check_rate("sk-1", &config));
    }

    #[test]
    fn rate_limiter_no_limit_always_passes() {
        let limiter = KeyRateLimiter::new();
        let config = make_key("sk-1", true);
        for _ in 0..100 {
            assert!(limiter.check_rate("sk-1", &config));
        }
    }

    #[test]
    fn rate_limiter_record_tokens() {
        let limiter = KeyRateLimiter::new();
        let config = make_key("sk-1", true);
        limiter.check_rate("sk-1", &config);
        limiter.record_tokens("sk-1", 500);
        // Just verify it doesn't panic; token tracking is internal state.
    }

    #[test]
    fn deserialization_defaults() {
        let json = serde_json::json!({
            "key": "sk-virtual-1"
        });
        let config: VirtualKeyConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.key, "sk-virtual-1");
        assert!(config.enabled);
        assert!(config.allowed_models.is_empty());
        assert!(config.tags.is_empty());
        assert!(config.budget.is_none());
        // WOR-894 defaults.
        assert!(config.project.is_none());
        assert!(config.user.is_none());
        assert!(config.metadata.is_empty());
        // WOR-893 default.
        assert!(config.route_to_model.is_none());
    }

    #[test]
    fn deserialization_carries_route_to_model() {
        let json = serde_json::json!({
            "key": "sk-routed",
            "route_to_model": "gpt-4o-mini"
        });
        let config: VirtualKeyConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.route_to_model.as_deref(), Some("gpt-4o-mini"));
    }

    #[test]
    fn deserialization_carries_project_user_metadata() {
        let json = serde_json::json!({
            "key": "sk-virtual-2",
            "project": "alpha",
            "user": "alice",
            "metadata": { "team": "research", "cost_center": "R-12" }
        });
        let config: VirtualKeyConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.project.as_deref(), Some("alpha"));
        assert_eq!(config.user.as_deref(), Some("alice"));
        assert_eq!(
            config.metadata.get("team").map(String::as_str),
            Some("research")
        );
        assert_eq!(
            config.metadata.get("cost_center").map(String::as_str),
            Some("R-12")
        );
    }
}
