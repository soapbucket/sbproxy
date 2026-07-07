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
        let mut config = sbproxy_ai::AiHandlerConfig::from_config(value)?;
        // WOR-1767: resolve provider-URI secret references (`secret://`,
        // `secretfile://`, `vault://`, ...) in each provider's api_key
        // against the process secret resolver. An unresolved reference is a
        // hard error so it never reaches the wire verbatim as a bearer
        // token. When no resolver is installed (the validate/plan
        // subcommands, unit tests), references are left as-is; those paths
        // never make an upstream request.
        if let Some(resolver) = sbproxy_vault::process_resolver() {
            for provider in &mut config.providers {
                if let Some(key) = provider.api_key.take() {
                    let resolved = resolver.resolve(&key).map_err(|e| {
                        anyhow::anyhow!("resolving api_key for provider {:?}: {e}", provider.name)
                    })?;
                    provider.api_key = Some(resolved);
                }
            }
        }
        Ok(Self { config })
    }
}
