//! Virtual API key management and per-key rate limiting.

use parking_lot::Mutex;
use sbproxy_plugin::Principal;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};

/// Provider tool-JSON shape for federation-sourced injection
/// (WOR-1646). Defined here (in `sbproxy-ai`) so it lives with the
/// virtual-key config; `sbproxy-modules` reads it when resolving the
/// injected catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum McpToolFormat {
    /// OpenAI `{"type":"function","function":{...}}`.
    #[default]
    Openai,
    /// Anthropic `{"name":...,"input_schema":...}`.
    Anthropic,
}

/// Reference from a virtual key to a federated MCP gateway whose live
/// catalogue is injected as the key's tool surface (WOR-1646).
#[derive(Debug, Clone, Deserialize)]
pub struct InjectMcpRef {
    /// The target gateway's `server_info.name`, as registered by its
    /// `mcp` action.
    #[serde(rename = "ref")]
    pub reference: String,
    /// Provider tool-JSON shape to emit. Defaults to OpenAI.
    #[serde(default)]
    pub format: McpToolFormat,
    /// Optional tool-name filter (trailing-`*` glob or exact). Empty
    /// injects every allowed tool.
    #[serde(default)]
    pub filter: Vec<String>,
}

/// A virtual key's SLO priority lane (WOR-1679). Bound to the key, never
/// to a client-settable header, so a caller cannot self-promote. Drives
/// the served-lane admission queue (interactive wakes before standard,
/// standard before batch) and the spill decision (an interactive request
/// spills to the next provider sooner than it queues behind batch work).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyPriority {
    /// Latency-critical interactive traffic (chat UIs, agents).
    Interactive,
    /// The default lane.
    Standard,
    /// Best-effort bulk work; yields to everything above.
    Batch,
}

impl KeyPriority {
    /// Parse the lowercase lane name; `None` for anything else.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "interactive" => Some(Self::Interactive),
            "standard" => Some(Self::Standard),
            "batch" => Some(Self::Batch),
            _ => None,
        }
    }

    /// The lowercase lane name (the wire and ledger spelling).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::Standard => "standard",
            Self::Batch => "batch",
        }
    }
}

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
    /// Inbound principal selectors allowed to use this key. Empty
    /// means the key is available to every inbound principal.
    #[serde(default)]
    pub principal_selectors: Vec<PrincipalSelectorConfig>,
    /// Named PII redaction rules that must be active on request
    /// bodies before this key can dispatch upstream.
    #[serde(default)]
    pub require_pii_redaction: Vec<String>,
    /// Maximum requests per minute for this key.
    #[serde(default)]
    pub max_requests_per_minute: Option<u64>,
    /// Maximum tokens (input + output) per minute for this key
    /// (WOR-1833). Enforced as a sliding one-minute window like
    /// [`Self::max_requests_per_minute`]: a request is rejected with
    /// 429 when the key's window has already consumed the cap. Usage
    /// lands in the window when the response's token counts are
    /// extracted, so the check is against completed spend, not an
    /// estimate.
    #[serde(default)]
    pub max_tokens_per_minute: Option<u64>,
    /// SLO priority lane for the served-model admission queue
    /// (WOR-1679). `None` behaves as [`KeyPriority::Standard`].
    #[serde(default)]
    pub priority: Option<KeyPriority>,
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
    /// WOR-893: tools injected into the request `body["tools"]` when this
    /// key authenticates the request. Each entry is an opaque JSON
    /// object (the provider's tool-definition shape: OpenAI
    /// `{"type":"function","function":{...}}`, Anthropic
    /// `{"name":...,"input_schema":...}`, etc.) so the gateway stays
    /// provider-agnostic. Empty (default) leaves the request's `tools`
    /// untouched. When non-empty the key's set REPLACES any client-
    /// supplied tools, so the key fully owns the tool surface the
    /// caller exposes - matching the "key = model + tools" framing.
    #[serde(default)]
    pub inject_tools: Vec<serde_json::Value>,
    /// WOR-1646: inject the live catalogue of a federated MCP gateway
    /// instead of (or alongside) the static `inject_tools` JSON. The
    /// injected set is resolved from the referenced gateway's current
    /// `tools/list` at request time and RBAC-filtered by this key's
    /// principal, so it tracks upstream changes without a config
    /// reload and never exposes a tool the MCP action would refuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inject_mcp: Option<InjectMcpRef>,
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

impl VirtualKeyConfig {
    /// Whether this key's principal selectors allow the inbound
    /// principal. An empty selector list is intentionally allow-all.
    pub fn matches_principal(&self, principal: &Principal) -> bool {
        self.principal_selectors.is_empty()
            || self
                .principal_selectors
                .iter()
                .any(|selector| selector.matches(principal))
    }
}

/// Principal selector lowered from the unified `credentials:`
/// block. Fields OR together inside a selector; selector rows OR
/// together on [`VirtualKeyConfig`].
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PrincipalSelectorConfig {
    /// Glob against `Principal.virtual_key.name`.
    #[serde(default)]
    pub virtual_key: Option<String>,
    /// Exact match against `Principal.attrs.team`.
    #[serde(default)]
    pub team: Option<String>,
    /// Exact match against `Principal.attrs.project`.
    #[serde(default)]
    pub project: Option<String>,
    /// Exact match against `Principal.attrs.user`.
    #[serde(default)]
    pub user: Option<String>,
    /// Exact match against any role in `Principal.attrs.roles`.
    #[serde(default)]
    pub role: Option<String>,
    /// Exact key/value match against `Principal.attrs.claims`.
    #[serde(default)]
    pub claim: BTreeMap<String, String>,
}

impl PrincipalSelectorConfig {
    fn is_empty(&self) -> bool {
        self.virtual_key.is_none()
            && self.team.is_none()
            && self.project.is_none()
            && self.user.is_none()
            && self.role.is_none()
            && self.claim.is_empty()
    }

    fn matches(&self, principal: &Principal) -> bool {
        if self.is_empty() {
            return false;
        }
        if let Some(pattern) = self.virtual_key.as_deref() {
            if principal
                .virtual_key
                .as_ref()
                .is_some_and(|vk| sbproxy_util::prefix_glob_match(pattern, &vk.name))
            {
                return true;
            }
        }
        if self
            .team
            .as_deref()
            .is_some_and(|team| principal.attrs.team.as_deref() == Some(team))
        {
            return true;
        }
        if self
            .project
            .as_deref()
            .is_some_and(|project| principal.attrs.project.as_deref() == Some(project))
        {
            return true;
        }
        if self
            .user
            .as_deref()
            .is_some_and(|user| principal.attrs.user.as_deref() == Some(user))
        {
            return true;
        }
        if self
            .role
            .as_deref()
            .is_some_and(|role| principal.attrs.roles.iter().any(|r| r == role))
        {
            return true;
        }
        if let Some(claims) = principal.attrs.claims.as_ref() {
            if self.claim.iter().any(|(key, expected)| {
                claims
                    .get(key)
                    .is_some_and(|actual| claim_value_matches(actual, expected))
            }) {
                return true;
            }
        }
        false
    }
}

fn claim_value_matches(actual: &serde_json::Value, expected: &str) -> bool {
    if let Some(actual) = actual.as_str() {
        return actual == expected;
    }
    serde_json::from_str::<serde_json::Value>(expected).is_ok_and(|expected| *actual == expected)
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
    requests_this_minute: u64,
    tokens_this_minute: u64,
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
        // WOR-1691: allocate the key only on the first-seen miss instead
        // of `entry(key.to_string())` cloning it on every request for a
        // key that already exists after the first.
        if !state.contains_key(key) {
            state.insert(key.to_string(), KeyRateState::default());
        }
        let entry = state.get_mut(key).expect("inserted above if absent");

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

        // Check tokens per minute (WOR-1833). The window holds tokens
        // already consumed by completed responses; a request is refused
        // once the cap is spent. Deliberately no pre-charge estimate:
        // the first request of a window always passes, and heavy usage
        // shuts the window for the remainder of the minute.
        if let Some(max_tpm) = config.max_tokens_per_minute {
            if entry.tokens_this_minute >= max_tpm {
                return false;
            }
        }

        entry.requests_this_minute += 1;
        true
    }

    /// Add a completed response's token usage to the key's one-minute
    /// window (WOR-1833). Called from the usage-extraction path with
    /// input + output tokens; a no-op for keys without a TPM cap is
    /// avoided by callers checking the cap first, but recording for an
    /// uncapped key is harmless (the window resets each minute).
    pub fn record_tokens(&self, key: &str, tokens: u64) {
        if tokens == 0 {
            return;
        }
        let mut state = self.state.lock();
        if !state.contains_key(key) {
            state.insert(key.to_string(), KeyRateState::default());
        }
        let entry = state.get_mut(key).expect("inserted above if absent");
        let now = std::time::Instant::now();
        if let Some(start) = entry.minute_start {
            if now.duration_since(start).as_secs() >= 60 {
                *entry = KeyRateState::default();
            }
        }
        if entry.minute_start.is_none() {
            entry.minute_start = Some(now);
        }
        entry.tokens_this_minute = entry.tokens_this_minute.saturating_add(tokens);
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
            principal_selectors: vec![],
            require_pii_redaction: vec![],
            max_requests_per_minute: None,
            max_tokens_per_minute: None,
            priority: None,
            budget: None,
            tags: vec![],
            project: None,
            user: None,
            metadata: HashMap::new(),
            route_to_model: None,
            inject_tools: vec![],
            inject_mcp: None,
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
            principal_selectors: vec![],
            require_pii_redaction: vec![],
            max_requests_per_minute: None,
            max_tokens_per_minute: None,
            priority: None,
            budget: None,
            tags: vec![],
            project: None,
            user: None,
            metadata: HashMap::new(),
            route_to_model: None,
            inject_tools: vec![],
            inject_mcp: None,
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

    #[test]
    fn virtual_key_with_empty_principal_selectors_matches_everyone() {
        let key = make_key("sk-1", true);
        let principal = Principal::anonymous();
        assert!(key.matches_principal(&principal));
    }

    #[test]
    fn virtual_key_principal_selector_fields_or_together() {
        let key = VirtualKeyConfig {
            principal_selectors: vec![PrincipalSelectorConfig {
                team: Some("frontend".to_string()),
                role: Some("admin".to_string()),
                ..PrincipalSelectorConfig::default()
            }],
            ..make_key("sk-1", true)
        };
        let principal = Principal {
            attrs: sbproxy_plugin::PrincipalAttrs {
                team: Some("backend".to_string()),
                roles: vec!["admin".to_string()],
                ..sbproxy_plugin::PrincipalAttrs::default()
            },
            ..Principal::anonymous()
        };

        assert!(key.matches_principal(&principal));
    }

    #[test]
    fn virtual_key_principal_selector_miss_blocks_match() {
        let key = VirtualKeyConfig {
            principal_selectors: vec![PrincipalSelectorConfig {
                team: Some("frontend".to_string()),
                ..PrincipalSelectorConfig::default()
            }],
            ..make_key("sk-1", true)
        };
        let principal = Principal {
            attrs: sbproxy_plugin::PrincipalAttrs {
                team: Some("backend".to_string()),
                ..sbproxy_plugin::PrincipalAttrs::default()
            },
            ..Principal::anonymous()
        };

        assert!(!key.matches_principal(&principal));
    }

    #[test]
    fn virtual_key_selector_matches_virtual_key_glob_and_claims() {
        let key = VirtualKeyConfig {
            principal_selectors: vec![PrincipalSelectorConfig {
                virtual_key: Some("team-*".to_string()),
                claim: [("org".to_string(), "acme".to_string())]
                    .into_iter()
                    .collect(),
                ..PrincipalSelectorConfig::default()
            }],
            ..make_key("sk-1", true)
        };
        let principal = Principal {
            virtual_key: Some(sbproxy_plugin::VirtualKeyRef {
                name: "team-alpha".to_string(),
                allowed_providers: vec![],
            }),
            attrs: sbproxy_plugin::PrincipalAttrs {
                claims: Some(
                    [(
                        "org".to_string(),
                        serde_json::Value::String("wrong".to_string()),
                    )]
                    .into_iter()
                    .collect(),
                ),
                ..sbproxy_plugin::PrincipalAttrs::default()
            },
            ..Principal::anonymous()
        };

        assert!(key.matches_principal(&principal));
    }

    #[test]
    fn virtual_key_selector_matches_json_claim_values() {
        let key = VirtualKeyConfig {
            principal_selectors: vec![PrincipalSelectorConfig {
                claim: [("quota".to_string(), "7".to_string())]
                    .into_iter()
                    .collect(),
                ..PrincipalSelectorConfig::default()
            }],
            ..make_key("sk-1", true)
        };
        let principal = Principal {
            attrs: sbproxy_plugin::PrincipalAttrs {
                claims: Some(
                    [(
                        "quota".to_string(),
                        serde_json::Value::Number(serde_json::Number::from(7)),
                    )]
                    .into_iter()
                    .collect(),
                ),
                ..sbproxy_plugin::PrincipalAttrs::default()
            },
            ..Principal::anonymous()
        };

        assert!(key.matches_principal(&principal));
    }

    // --- KeyRateLimiter tests ---

    #[test]
    fn rate_limiter_within_limit() {
        let limiter = KeyRateLimiter::new();
        let config = VirtualKeyConfig {
            max_requests_per_minute: Some(10),
            max_tokens_per_minute: None,
            priority: None,
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
            max_tokens_per_minute: None,
            priority: None,
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
        // WOR-893 defaults.
        assert!(config.route_to_model.is_none());
        assert!(config.inject_tools.is_empty());
    }

    #[test]
    fn deserialization_carries_inject_tools() {
        let json = serde_json::json!({
            "key": "sk-tools",
            "inject_tools": [
                { "type": "function", "function": { "name": "search_docs" } },
                { "type": "function", "function": { "name": "query_db" } }
            ]
        });
        let config: VirtualKeyConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.inject_tools.len(), 2);
        assert_eq!(
            config.inject_tools[0]["function"]["name"], "search_docs",
            "tool 0 deserializes verbatim"
        );
        assert_eq!(config.inject_tools[1]["function"]["name"], "query_db");
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
