//! AI proxy action - routes requests through the AI gateway.

use serde::Deserialize;

/// AI proxy action configuration.
#[derive(Debug, Deserialize)]
pub struct AiProxyAction {
    /// Compiled AI gateway configuration (provider, routing, budgets, etc.).
    pub config: sbproxy_ai::AiHandlerConfig,
}

impl AiProxyAction {
    /// Build a runtime AiProxyAction from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Self::from_config_with_runtime(value, true)
    }

    /// Build an AiProxyAction for structural validation only.
    ///
    /// Validation deliberately does not resolve credentials, perform DNS, or
    /// publish prepared HTTP clients into the configuration.
    pub fn from_config_for_validation(value: serde_json::Value) -> anyhow::Result<Self> {
        Self::from_config_with_runtime(value, false)
    }

    fn from_config_with_runtime(
        value: serde_json::Value,
        prepare_runtime: bool,
    ) -> anyhow::Result<Self> {
        let mut config = sbproxy_ai::AiHandlerConfig::from_config(value)?;
        if !prepare_runtime {
            return Ok(Self { config });
        }

        // WOR-1767: resolve provider-URI secret references (`secret://`,
        // `secretfile://`, `vault://`, ...) in each provider's api_key
        // against the process secret resolver. An unresolved reference is a
        // hard error so it never reaches the wire verbatim as a bearer token.
        // A runtime without configured secret backends still uses a temporary
        // resolver so `file:` works and provider URIs fail closed.
        let resolver = sbproxy_vault::process_resolver();
        for provider in &mut config.providers {
            if let Some(key) = provider.api_key.take() {
                let resolved =
                    resolve_runtime_credential(resolver.as_deref(), &key).map_err(|e| {
                        anyhow::anyhow!("resolving api_key for provider {:?}: {e}", provider.name)
                    })?;
                provider.api_key = Some(resolved);
            }
        }
        if let Some(guardrails) = config.guardrails.as_mut() {
            for guardrail in &mut guardrails.external {
                let name = guardrail.name.clone();
                if let Some(reference) = guardrail.credential_reference_mut() {
                    let resolved = resolve_runtime_credential(resolver.as_deref(), reference)
                        .map_err(|error| {
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
        if let Some(guardrails) = config.guardrails.as_ref() {
            for guardrail in &guardrails.external {
                let name = &guardrail.name;
                guardrail.prepare().map_err(|error| {
                    anyhow::anyhow!("preparing external guardrail '{name}': {}", error)
                })?;
            }
        }
        Ok(Self { config })
    }
}

fn resolve_runtime_credential(
    resolver: Option<&sbproxy_vault::SecretResolver>,
    value: &str,
) -> anyhow::Result<String> {
    match resolver {
        Some(resolver) => resolver.resolve(value),
        None => sbproxy_vault::SecretResolver::new().resolve(value),
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

        let guardrail = &action.config.guardrails.unwrap().external[0];
        assert_eq!(
            guardrail.api_key.as_deref(),
            Some("resolved-guardrail-value")
        );
        assert!(
            guardrail.is_prepared(),
            "runtime must be compiled only after the credential is resolved"
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

    #[test]
    fn literal_external_guardrail_is_prepared_without_needing_a_credential() {
        let action = AiProxyAction::from_config(serde_json::json!({
            "providers": [],
            "guardrails": {
                "external": [{
                    "name": "credential-free-policy",
                    "url": "https://8.8.8.8/check",
                    "mode": "pre_call"
                }]
            }
        }))
        .expect("literal external guardrail prepares");

        assert!(
            action.config.guardrails.unwrap().external[0].is_prepared(),
            "literal and credential-free guards must publish prepared runtime state"
        );
    }

    #[test]
    fn validation_does_not_prepare_literal_external_guardrails() {
        let action = AiProxyAction::from_config_for_validation(serde_json::json!({
            "providers": [],
            "guardrails": {
                "external": [{
                    "name": "credential-free-policy",
                    "url": "https://8.8.8.8/check",
                    "mode": "pre_call"
                }]
            }
        }))
        .expect("literal external guardrail validates structurally");

        assert!(
            !action.config.guardrails.unwrap().external[0].is_prepared(),
            "validate/plan must not perform DNS or publish runtime clients"
        );
    }

    #[test]
    fn no_backend_runtime_resolver_reads_file_references() {
        let path = std::env::temp_dir().join(format!(
            "sbproxy-guardrail-credential-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::write(&path, "file-credential\n").expect("write credential fixture");
        let reference = format!("file:{}", path.display());

        let resolved =
            super::resolve_runtime_credential(None, &reference).expect("resolve file reference");
        let _ = std::fs::remove_file(path);

        assert_eq!(resolved, "file-credential");
    }

    #[test]
    fn unresolved_whole_value_environment_reference_cannot_be_prepared() {
        let error = AiProxyAction::from_config_for_validation(serde_json::json!({
            "providers": [],
            "guardrails": {
                "external": [{
                    "name": "environment-policy",
                    "url": "https://8.8.8.8/check",
                    "mode": "pre_call",
                    "api_key": "${SBPROXY_TEST_UNRESOLVED_GUARDRAIL_KEY}"
                }]
            }
        }))
        .expect_err("unresolved environment reference must fail structural validation");

        assert!(error.to_string().contains("unresolved variable reference"));
    }
}
