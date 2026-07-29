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
            if let Some(guardrails) = config.guardrails.as_mut() {
                for guardrail in &mut guardrails.external {
                    let name = guardrail.name.clone();
                    if let Some(reference) = guardrail.credential_reference_mut() {
                        let resolved = resolver.resolve(reference).map_err(|error| {
                            let detail = if error.to_string().contains("secret not found") {
                                "secret not found"
                            } else {
                                "credential resolution failed"
                            };
                            anyhow::anyhow!(
                                "resolving credential for external guardrail '{name}': {detail}"
                            )
                        })?;
                        *reference = resolved;
                    }
                }
            }
        }
        Ok(Self { config })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::AiProxyAction;

    fn install_fixture_resolver() {
        let vault = sbproxy_vault::LocalVault::new();
        vault
            .set_secret("credential", "resolved-guardrail-value")
            .expect("fixture secret");
        let mut manager = sbproxy_vault::VaultManager::new();
        manager.register("fixture-guardrail", Box::new(vault));
        sbproxy_vault::install_process_resolver(Arc::new(
            sbproxy_vault::SecretResolver::new().with_manager(Arc::new(manager)),
        ));
    }

    #[test]
    fn resolves_external_guardrail_credentials_without_exposing_the_reference() {
        install_fixture_resolver();
        let action = AiProxyAction::from_config(serde_json::json!({
            "providers": [],
            "guardrails": {
                "external": [{
                    "name": "customer-policy",
                    "url": "https://8.8.8.8/check",
                    "mode": "pre_call",
                    "api_key": "secret://fixture-guardrail/credential"
                }]
            }
        }))
        .expect("external guardrail credential resolves");

        assert_eq!(
            action.config.guardrails.unwrap().external[0]
                .api_key
                .as_deref(),
            Some("resolved-guardrail-value")
        );
    }

    #[test]
    fn external_guardrail_resolution_error_names_the_guardrail_not_the_reference() {
        install_fixture_resolver();
        let error = AiProxyAction::from_config(serde_json::json!({
            "providers": [],
            "guardrails": {
                "external": [{
                    "name": "customer-policy",
                    "url": "https://8.8.8.8/check",
                    "mode": "pre_call",
                    "api_key": "secret://fixture-guardrail/missing"
                }]
            }
        }))
        .expect_err("missing guardrail credential must fail configuration");
        let message = error.to_string();
        assert!(message.contains("external guardrail 'customer-policy'"));
        assert!(!message.contains("secret://fixture-guardrail/missing"));
        assert!(!message.contains("resolved-guardrail-value"));
    }
}
