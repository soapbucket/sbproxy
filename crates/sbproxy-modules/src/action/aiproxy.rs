//! AI proxy action - routes requests through the AI gateway.

use serde::Deserialize;

/// AI proxy action configuration.
#[derive(Debug, Deserialize)]
pub struct AiProxyAction {
    /// Compiled AI gateway configuration (provider, routing, budgets, etc.).
    pub config: sbproxy_ai::AiHandlerConfig,
}

impl AiProxyAction {
    /// Build an AiProxyAction from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let config = sbproxy_ai::AiHandlerConfig::from_config(value)?;
        Ok(Self { config })
    }
}
