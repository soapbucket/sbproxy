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
        // A validation-only compile must not install the candidate's price
        // table into the process-global cost-accounting table; a rejected
        // candidate would otherwise leave live billing on its prices.
        let mut config = if prepare_runtime {
            sbproxy_ai::AiHandlerConfig::from_config(value)?
        } else {
            sbproxy_ai::AiHandlerConfig::from_config_for_validation(value)?
        };
        if !prepare_runtime {
            // WOR-2098: validate and plan construction resolve RAG
            // credential references too when a process resolver is
            // installed, so a bad reference fails at plan time instead of
            // at first boot. Without a resolver the references stay
            // intact; the RAG registry is then built in validation mode,
            // which never dials.
            resolve_rag_credentials(&mut config)?;
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
        // WOR-2098: resolve RAG credential references beside the provider
        // credentials above. The same hook runs for validation
        // construction; see `resolve_rag_credentials`.
        resolve_rag_credentials(&mut config)?;
        Ok(Self { config })
    }
}

/// Resolve `rag:` credential references (`secret://`, `vault://`, `${ENV}`,
/// `file:`) through the process secret resolver (WOR-2098).
///
/// Mirrors the provider api_key loop with one deliberate difference: when no
/// process resolver is installed (the `validate` and `plan` subcommands, unit
/// tests), `secret://` references are left intact rather than failing loud,
/// because a validation pipeline never sends them to the wire. A resolution
/// error names the configuration field but never the reference or a resolved
/// value.
fn resolve_rag_credentials(config: &mut sbproxy_ai::AiHandlerConfig) -> anyhow::Result<()> {
    if let (Some(resolver), Some(rag)) = (sbproxy_vault::process_resolver(), config.rag.as_mut()) {
        rag.try_visit_credentials_mut(|field, value| {
            *value = resolver.resolve(value).map_err(|error| {
                // Same sanitization as the external-guardrail path: a
                // resolver error can embed the reference, so collapse it
                // to a class the operator can act on.
                let detail = if error.to_string().contains("secret not found") {
                    "secret not found"
                } else {
                    "credential resolution failed"
                };
                anyhow::anyhow!("resolving {field}: {detail}")
            })?;
            Ok::<_, anyhow::Error>(())
        })?;
    }
    Ok(())
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
        // One process-wide resolver serves every test in this module (the
        // install is first-wins), so the RAG fixture backend registers
        // beside the guardrail one.
        let rag_vault = sbproxy_vault::LocalVault::new();
        rag_vault
            .set_secret("embedding", "resolved-embedding")
            .expect("fixture secret");
        rag_vault
            .set_secret("vector", "resolved-vector")
            .expect("fixture secret");
        let mut manager = sbproxy_vault::VaultManager::new();
        manager.register("fixture-guardrail", Box::new(vault));
        manager.register("fixture-rag", Box::new(rag_vault));
        sbproxy_vault::install_process_resolver(Arc::new(
            sbproxy_vault::SecretResolver::new().with_manager(Arc::new(manager)),
        ));
    }

    /// Snapshot every RAG credential field through the same visitor the
    /// resolver hook uses, so assertions cover the full credential set.
    fn rag_credentials(action: &mut AiProxyAction) -> Vec<(&'static str, String)> {
        let mut seen = Vec::new();
        if let Some(rag) = action.config.rag.as_mut() {
            rag.try_visit_credentials_mut(|field, value| {
                seen.push((field, value.clone()));
                Ok::<_, std::convert::Infallible>(())
            })
            .expect("collecting credentials is infallible");
        }
        seen
    }

    fn rag_action_config(embedding_key: &str, vector_key: &str) -> serde_json::Value {
        serde_json::json!({
            "providers": [],
            "rag": {
                "embedding": {
                    "provider": "openai",
                    "api_key": embedding_key,
                },
                "vector_store": {
                    "provider": "qdrant",
                    "base_url": "http://127.0.0.1:6333",
                    "collection": "support_docs",
                    "api_key": vector_key,
                    "allow_private_url": true,
                }
            }
        })
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

    #[test]
    fn rag_secret_references_resolve_without_exposing_the_reference() {
        install_fixture_resolver();
        let mut action = AiProxyAction::from_config(rag_action_config(
            "secret://fixture-rag/embedding",
            "secret://fixture-rag/vector",
        ))
        .expect("rag credential references resolve");

        let credentials = rag_credentials(&mut action);
        assert_eq!(
            credentials.len(),
            2,
            "unexpected credential set: {credentials:?}"
        );
        for (field, value) in &credentials {
            assert!(
                !value.contains("secret://"),
                "{field} kept its reference: {value}"
            );
        }
        let value_of = |name: &str| {
            credentials
                .iter()
                .find(|(field, _)| *field == name)
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(
            value_of("rag.embedding.api_key"),
            Some("resolved-embedding")
        );
        assert_eq!(
            value_of("rag.vector_store.api_key"),
            Some("resolved-vector")
        );
    }

    #[test]
    fn rag_secret_references_resolve_for_validation_construction_too() {
        // `compile_action_for_origin` does not receive the pipeline
        // construction mode, so validate and plan run the same resolver
        // path as runtime construction whenever a resolver is installed.
        install_fixture_resolver();
        let mut action = AiProxyAction::from_config_for_validation(rag_action_config(
            "secret://fixture-rag/embedding",
            "secret://fixture-rag/vector",
        ))
        .expect("validation construction resolves rag credentials");

        let credentials = rag_credentials(&mut action);
        assert_eq!(
            credentials.len(),
            2,
            "unexpected credential set: {credentials:?}"
        );
        assert!(
            credentials
                .iter()
                .all(|(_, value)| !value.contains("secret://")),
            "validation left a reference unresolved: {credentials:?}"
        );
    }

    #[test]
    fn rag_secret_resolution_error_names_the_field_not_the_reference() {
        install_fixture_resolver();
        let error = AiProxyAction::from_config(rag_action_config(
            "secret://fixture-rag/missing",
            "secret://fixture-rag/vector",
        ))
        .expect_err("a missing rag credential must fail configuration");

        let message = format!("{error:#}");
        assert!(message.contains("rag.embedding.api_key"), "{message}");
        assert!(
            !message.contains("secret://fixture-rag/missing"),
            "{message}"
        );
        assert!(!message.contains("resolved-embedding"), "{message}");
        assert!(!message.contains("resolved-vector"), "{message}");
    }

    #[test]
    fn rag_secret_references_stay_intact_without_a_process_resolver() {
        // Under nextest this test gets its own process and no fixture
        // resolver has ever been installed. Plain `cargo test` (the
        // release-checks single-threaded lane) runs every test in this
        // file in one process instead, so a sibling test's
        // install_fixture_resolver() call would otherwise latch a resolver
        // in ahead of this one (WOR-2298). Reset explicitly so this
        // construction sees no resolver regardless of test order.
        sbproxy_vault::reset_process_resolver_for_test();
        let mut action = AiProxyAction::from_config(rag_action_config(
            "secret://fixture-rag/embedding",
            "secret://fixture-rag/vector",
        ))
        .expect("rag references pass through without a resolver");

        let credentials = rag_credentials(&mut action);
        assert_eq!(
            credentials.len(),
            2,
            "unexpected credential set: {credentials:?}"
        );
        assert!(
            credentials
                .iter()
                .all(|(_, value)| value.starts_with("secret://fixture-rag/")),
            "a reference was rewritten without a resolver: {credentials:?}"
        );
    }
}
