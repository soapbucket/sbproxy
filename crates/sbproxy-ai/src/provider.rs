//! Provider trait and configuration.

use serde::Deserialize;
use std::collections::HashMap;

use crate::providers::get_provider_info;

/// Provider configuration from YAML/JSON.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderConfig {
    /// Unique provider name used to reference this provider.
    pub name: String,
    /// Optional provider type (e.g. "openai", "anthropic"); inferred from name if absent.
    #[serde(default)]
    pub provider_type: Option<String>,
    /// API key used to authenticate with the upstream provider.
    pub api_key: Option<String>,
    /// Override the upstream base URL (defaults to the provider's well-known URL).
    #[serde(default)]
    pub base_url: Option<String>,
    /// Models served by this provider; empty defers to the provider catalog.
    #[serde(default)]
    pub models: Vec<String>,
    /// Default model used when the request omits an explicit model.
    #[serde(default)]
    pub default_model: Option<String>,
    /// Per-provider mapping from logical model name to upstream model name.
    #[serde(default)]
    pub model_map: HashMap<String, String>,
    /// Weight used by weighted routing strategies.
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Priority used by priority-based routing (lower runs first).
    #[serde(default)]
    pub priority: Option<u32>,
    /// Whether this provider is eligible for routing.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Maximum retry attempts on transient upstream failures.
    #[serde(default)]
    pub max_retries: Option<u32>,
    /// Request timeout in milliseconds.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Organization identifier (used by providers that scope keys per org).
    #[serde(default)]
    pub organization: Option<String>,
    /// API version header value (used by Anthropic and Azure OpenAI).
    #[serde(default)]
    pub api_version: Option<String>,
    /// Override the `Host` header sent to the AI provider. Defaults to the
    /// provider's base URL hostname (api.openai.com, api.anthropic.com, ...).
    /// Set this when fronting the provider through a custom domain.
    #[serde(default)]
    pub host_override: Option<String>,
    /// When true, suppress the `X-Forwarded-Host` header that the proxy
    /// would otherwise set to the client's original `Host` whenever it
    /// rewrites the upstream `Host`.
    #[serde(default)]
    pub disable_forwarded_host_header: bool,
}

fn default_weight() -> u32 {
    1
}

fn default_true() -> bool {
    true
}

impl ProviderConfig {
    /// Get the effective base URL for this provider.
    ///
    /// Priority: explicit `base_url` > registry default > fallback localhost.
    pub fn effective_base_url(&self) -> String {
        if let Some(ref url) = self.base_url {
            return url.clone();
        }
        let ptype = self.provider_type.as_deref().unwrap_or(&self.name);
        get_provider_info(ptype)
            .map(|info| info.default_base_url)
            .unwrap_or_else(|| "http://localhost:8080/v1".to_string())
    }

    /// Get the auth header name and formatted value for this provider.
    ///
    /// Returns `(header_name, header_value)` where header_value includes
    /// any required prefix (e.g. "Bearer sk-xxx" or raw "sk-xxx").
    /// The header name and value are owned because the registry now
    /// holds YAML-loaded strings rather than `&'static` constants.
    pub fn auth_header(&self) -> (String, String) {
        let ptype = self.provider_type.as_deref().unwrap_or(&self.name);
        let info = get_provider_info(ptype);
        let header = info
            .as_ref()
            .map(|i| i.auth_header.clone())
            .unwrap_or_else(|| "Authorization".to_string());
        let prefix = info
            .as_ref()
            .map(|i| i.auth_prefix.clone())
            .unwrap_or_else(|| "Bearer ".to_string());
        let key = self.api_key.as_deref().unwrap_or("");
        (header, format!("{}{}", prefix, key))
    }

    /// Map a requested model to the provider's model name.
    pub fn map_model(&self, model: &str) -> String {
        self.model_map
            .get(model)
            .cloned()
            .unwrap_or_else(|| model.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_provider(name: &str) -> ProviderConfig {
        ProviderConfig {
            name: name.to_string(),
            provider_type: None,
            api_key: None,
            base_url: None,
            models: Vec::new(),
            default_model: None,
            model_map: HashMap::new(),
            weight: 1,
            priority: None,
            enabled: true,
            max_retries: None,
            timeout_ms: None,
            organization: None,
            api_version: None,
            host_override: None,
            disable_forwarded_host_header: false,
        }
    }

    #[test]
    fn effective_base_url_openai() {
        let p = make_provider("openai");
        assert_eq!(p.effective_base_url(), "https://api.openai.com/v1");
    }

    #[test]
    fn effective_base_url_anthropic() {
        let p = make_provider("anthropic");
        assert_eq!(p.effective_base_url(), "https://api.anthropic.com/v1");
    }

    #[test]
    fn effective_base_url_gemini() {
        let p = make_provider("gemini");
        assert_eq!(
            p.effective_base_url(),
            "https://generativelanguage.googleapis.com/v1beta"
        );
    }

    #[test]
    fn effective_base_url_unknown_provider() {
        let p = make_provider("local-llm");
        assert_eq!(p.effective_base_url(), "http://localhost:8080/v1");
    }

    #[test]
    fn effective_base_url_custom_override() {
        let mut p = make_provider("openai");
        p.base_url = Some("https://custom.proxy.com/v1".to_string());
        assert_eq!(p.effective_base_url(), "https://custom.proxy.com/v1");
    }

    #[test]
    fn effective_base_url_provider_type_override() {
        let mut p = make_provider("my-openai");
        p.provider_type = Some("openai".to_string());
        assert_eq!(p.effective_base_url(), "https://api.openai.com/v1");
    }

    #[test]
    fn map_model_passthrough() {
        let p = make_provider("openai");
        assert_eq!(p.map_model("gpt-4"), "gpt-4");
    }

    #[test]
    fn map_model_mapped() {
        let mut p = make_provider("openai");
        p.model_map
            .insert("fast".to_string(), "gpt-3.5-turbo".to_string());
        assert_eq!(p.map_model("fast"), "gpt-3.5-turbo");
        assert_eq!(p.map_model("gpt-4"), "gpt-4");
    }

    #[test]
    fn provider_config_from_json() {
        let json = serde_json::json!({
            "name": "openai",
            "api_key": "sk-test",
            "models": ["gpt-4", "gpt-3.5-turbo"],
            "default_model": "gpt-4",
            "weight": 5,
            "priority": 1
        });
        let p: ProviderConfig = serde_json::from_value(json).unwrap();
        assert_eq!(p.name, "openai");
        assert_eq!(p.api_key.as_deref(), Some("sk-test"));
        assert_eq!(p.models.len(), 2);
        assert_eq!(p.weight, 5);
        assert_eq!(p.priority, Some(1));
        assert!(p.enabled);
    }

    #[test]
    fn provider_config_defaults() {
        let json = serde_json::json!({"name": "test"});
        let p: ProviderConfig = serde_json::from_value(json).unwrap();
        assert_eq!(p.weight, 1);
        assert!(p.enabled);
        assert!(p.api_key.is_none());
        assert!(p.base_url.is_none());
        assert!(p.models.is_empty());
    }

    // --- auth_header tests ---

    #[test]
    fn auth_header_openai_bearer() {
        let mut p = make_provider("openai");
        p.api_key = Some("sk-test123".to_string());
        let (header, value) = p.auth_header();
        assert_eq!(header, "Authorization");
        assert_eq!(value, "Bearer sk-test123");
    }

    #[test]
    fn auth_header_anthropic_x_api_key() {
        let mut p = make_provider("anthropic");
        p.api_key = Some("sk-ant-test".to_string());
        let (header, value) = p.auth_header();
        assert_eq!(header, "x-api-key");
        assert_eq!(value, "sk-ant-test");
    }

    #[test]
    fn auth_header_azure_api_key() {
        let mut p = make_provider("azure");
        p.api_key = Some("az-key-123".to_string());
        let (header, value) = p.auth_header();
        assert_eq!(header, "api-key");
        assert_eq!(value, "az-key-123");
    }

    #[test]
    fn auth_header_unknown_defaults_to_bearer() {
        let mut p = make_provider("custom-llm");
        p.api_key = Some("mykey".to_string());
        let (header, value) = p.auth_header();
        assert_eq!(header, "Authorization");
        assert_eq!(value, "Bearer mykey");
    }

    #[test]
    fn auth_header_no_key() {
        let p = make_provider("openai");
        let (header, value) = p.auth_header();
        assert_eq!(header, "Authorization");
        assert_eq!(value, "Bearer ");
    }

    #[test]
    fn auth_header_respects_provider_type() {
        let mut p = make_provider("my-custom-name");
        p.provider_type = Some("anthropic".to_string());
        p.api_key = Some("key123".to_string());
        let (header, value) = p.auth_header();
        assert_eq!(header, "x-api-key");
        assert_eq!(value, "key123");
    }

    // --- Registry-backed base URL tests ---

    #[test]
    fn effective_base_url_groq() {
        let p = make_provider("groq");
        assert_eq!(p.effective_base_url(), "https://api.groq.com/openai/v1");
    }

    #[test]
    fn effective_base_url_mistral() {
        let p = make_provider("mistral");
        assert_eq!(p.effective_base_url(), "https://api.mistral.ai/v1");
    }

    #[test]
    fn effective_base_url_together() {
        let p = make_provider("together");
        assert_eq!(p.effective_base_url(), "https://api.together.xyz/v1");
    }

    #[test]
    fn effective_base_url_deepseek() {
        let p = make_provider("deepseek");
        assert_eq!(p.effective_base_url(), "https://api.deepseek.com/v1");
    }

    #[test]
    fn effective_base_url_ollama() {
        let p = make_provider("ollama");
        assert_eq!(p.effective_base_url(), "http://localhost:11434/v1");
    }
}
