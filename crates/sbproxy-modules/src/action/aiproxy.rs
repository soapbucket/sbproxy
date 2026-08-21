//! AI proxy action - routes requests through the AI gateway.

use sbproxy_extension::bundle::{build_wasm_ai_routing, BundleRegistry};
use serde::Deserialize;

/// AI proxy action configuration.
#[derive(Debug, Deserialize)]
pub struct AiProxyAction {
    /// Compiled AI gateway configuration (provider, routing, budgets, etc.).
    pub config: sbproxy_ai::AiHandlerConfig,
}

impl AiProxyAction {
    /// Build a runtime AiProxyAction from a generic JSON config value.
    ///
    /// Carries no extension-bundle registry, so an `ai_routing_policy`
    /// with `engine: wasm` refuses the config. The pipeline reaches the
    /// registry-aware path through [`Self::from_config_with_registry`].
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Self::from_config_with_runtime(value, true, None)
    }

    /// Build a runtime AiProxyAction, resolving an `ai_routing_policy`
    /// `engine: wasm` hook against the extension-bundle registry.
    ///
    /// The registry is only visible at action-compile time (WOR-2366),
    /// so the wasm routing hook resolves here and the prepared program
    /// is handed down into the AI handler configuration.
    pub fn from_config_with_registry(
        value: serde_json::Value,
        registry: Option<&dyn BundleRegistry>,
    ) -> anyhow::Result<Self> {
        Self::from_config_with_runtime(value, true, registry)
    }

    /// Build an AiProxyAction for structural validation only.
    ///
    /// Validation deliberately does not resolve credentials, perform DNS, or
    /// publish prepared HTTP clients into the configuration.
    pub fn from_config_for_validation(value: serde_json::Value) -> anyhow::Result<Self> {
        Self::from_config_with_runtime(value, false, None)
    }

    /// Build an AiProxyAction for structural validation, resolving an
    /// `ai_routing_policy` `engine: wasm` hook against the
    /// extension-bundle registry.
    ///
    /// The hook lookup runs in validation too, so `sbproxy validate`
    /// refuses a typo'd hook type at plan time instead of at first boot.
    /// It stops at the lookup: validation proves the hook is reachable,
    /// and only a runtime compile prepares it. A `vars` document that
    /// fails the hook's own `config_schema` is therefore caught at boot
    /// rather than at plan time, because preparing resolves the hook's
    /// declared `secret_vars` and validation must not reach a secret
    /// backend.
    pub fn from_config_for_validation_with_registry(
        value: serde_json::Value,
        registry: Option<&dyn BundleRegistry>,
    ) -> anyhow::Result<Self> {
        Self::from_config_with_runtime(value, false, registry)
    }

    fn from_config_with_runtime(
        value: serde_json::Value,
        prepare_runtime: bool,
        registry: Option<&dyn BundleRegistry>,
    ) -> anyhow::Result<Self> {
        // WOR-2366: the wasm routing hook resolves against the bundle
        // registry here, before the handler config parses, because the
        // registry does not exist below the action-compile layer. The two
        // compiles split at the program build and not at the lookup:
        // validation proves the hook is reachable, only a runtime compile
        // prepares it.
        let wasm_routing = prepare_wasm_routing(&value, registry, prepare_runtime)?;
        // A validation-only compile must not install the candidate's price
        // table into the process-global cost-accounting table; a rejected
        // candidate would otherwise leave live billing on its prices.
        let mut config = if prepare_runtime {
            sbproxy_ai::AiHandlerConfig::from_config_with_wasm_routing(value, wasm_routing)?
        } else {
            sbproxy_ai::AiHandlerConfig::from_config_for_validation_with_wasm_routing(
                value,
                wasm_routing,
            )?
        };
        // WOR-2648: refuse an `aws_sigv4:` block that cannot produce a
        // signature here, above the validation-mode early return, so
        // `sbproxy validate` and config load both catch it. `AiClient`
        // re-checks before it builds a signer, so a bad block fails
        // closed on the request path either way; this is the only place
        // that turns it into a message an operator can act on.
        for provider in &config.providers {
            provider.validate_aws_sigv4().map_err(|error| {
                anyhow::anyhow!("ai provider {:?} aws_sigv4: {error}", provider.name)
            })?;
        }
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
            // WOR-2648: the AWS signing block carries its own
            // credentials (`secret_access_key`, `session_token`,
            // `external_id`), and they get the same treatment as
            // `api_key`. An unresolved `vault://` would otherwise become
            // the signing key itself and come back from AWS as
            // `SignatureDoesNotMatch`, which reads like a wrong key
            // rather than like a reference nobody dereferenced. The
            // error names the provider and the field, never the
            // reference and never the value.
            let provider_name = provider.name.to_string();
            if let Some(sigv4) = provider.aws_sigv4.as_mut() {
                for secret in sigv4.credential_secrets_mut() {
                    let resolved = resolve_runtime_credential(resolver.as_deref(), secret.expose())
                        .map_err(|error| {
                            let detail = if error.to_string().contains("secret not found") {
                                "secret not found"
                            } else {
                                "credential resolution failed"
                            };
                            anyhow::anyhow!(
                                "aws_sigv4 credential for provider {provider_name:?}: {detail}"
                            )
                        })?;
                    secret.set_resolved(&resolved);
                }
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

/// Resolve the `ai_routing_policy` `engine: wasm` form against the
/// extension-bundle registry (WOR-2366).
///
/// The registry only exists at action-compile time, so the wasm routing
/// hook is resolved here and the prepared program is handed down into
/// the handler configuration. An absent or non-wasm routing policy
/// returns `None`; sbproxy-ai validates those forms on its own.
///
/// `prepare_runtime` splits the runtime and validation compiles at the
/// program build rather than at the lookup. Both prove the hook is
/// reachable: the policy names a `type:`, a registry is in scope, and
/// the registry answers with an `ai_routing` hook of that name. Only a
/// runtime compile goes on to build the program, because building it
/// applies the hook's `config_schema` defaults, resolves its declared
/// `secret_vars` (reading environment variables and files and calling
/// the installed vault resolver), validates the resolved document, and
/// attaches the bundle's WASM runtime. None of that belongs in
/// validation: `sbproxy validate` runs in CI and on planning machines
/// with no secret backend configured, and hard-failing a valid config
/// there is worse than deferring the `vars` check to first boot. A
/// validation compile therefore returns `None` once the hook resolves.
fn prepare_wasm_routing(
    value: &serde_json::Value,
    registry: Option<&dyn BundleRegistry>,
    prepare_runtime: bool,
) -> anyhow::Result<Option<sbproxy_ai::ai_routing_policy::WasmRoutingResolution>> {
    let Some(policy) = value.get("ai_routing_policy") else {
        return Ok(None);
    };
    // Trimmed, because the policy compiler trims before matching the
    // engine name. If the two disagreed, `engine: " wasm"` would resolve
    // to no program here and still take the wasm arm there, refusing a
    // config whose bundle is loaded and correct.
    if policy
        .get("engine")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        != Some("wasm")
    {
        return Ok(None);
    }
    let type_name = policy
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "ai_routing_policy `engine: wasm` requires `type:` naming a bundle \
                 `ai_routing` hook"
            )
        })?;
    let Some(registry) = registry else {
        anyhow::bail!(
            "ai_routing_policy `engine: wasm` requires a loaded extension bundle (an \
             `extensions:` block naming a bundle with an `ai_routing` hook)"
        );
    };
    let Some(hook) = registry.ai_routing(type_name) else {
        // The registry trait exposes no ai_routing enumeration
        // (`ai_hooks()` deliberately excludes attach-by-type kinds), so
        // the miss names the type and the class of the problem instead
        // of listing loaded hook names.
        anyhow::bail!(
            "ai_routing_policy names hook type {type_name:?}, but no loaded extension \
             bundle declares an `ai_routing` hook with that type"
        );
    };
    if !prepare_runtime {
        // The hook is reachable, which is everything validation can prove
        // without touching a secret backend. Preparing the program is a
        // runtime-only step; see this function's documentation. Report it
        // as resolved so the policy still compiles and every other
        // refusal in sbproxy-ai still runs; a `None` here would fail
        // validation with the requires-a-bundle error for a config whose
        // bundle is loaded and correct.
        return Ok(Some(
            sbproxy_ai::ai_routing_policy::WasmRoutingResolution::ValidatedOnly,
        ));
    }
    let vars = policy
        .get("vars")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let program = build_wasm_ai_routing(hook, vars).map_err(|error| {
        anyhow::anyhow!("preparing wasm ai_routing hook {type_name:?}: {error}")
    })?;
    Ok(Some(
        sbproxy_ai::ai_routing_policy::WasmRoutingResolution::Prepared(Box::new(program)),
    ))
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

    /// WOR-2648: the AWS signing block's credentials are references
    /// like any other, and the signer would otherwise use the reference
    /// text as the secret key.
    #[test]
    fn resolves_aws_sigv4_credential_references() {
        install_fixture_resolver();
        let action = AiProxyAction::from_config(serde_json::json!({
            "providers": [{
                "name": "bedrock",
                "provider_type": "bedrock",
                "aws_sigv4": {
                    "region": "us-east-1",
                    "credentials": {
                        "source": "static",
                        "access_key_id": "AKIDEXAMPLE",
                        "secret_access_key": "secret://fixture-guardrail/credential",
                    }
                }
            }]
        }))
        .expect("aws_sigv4 credential reference resolves");

        let sigv4 = action.config.providers[0]
            .aws_sigv4
            .as_ref()
            .expect("the signing block survives construction");
        let secret = sigv4
            .credentials
            .as_ref()
            .and_then(|credentials| credentials.secret_access_key.as_ref())
            .expect("the secret survives construction");
        assert_eq!(
            secret.expose(),
            "resolved-guardrail-value",
            "the reference must be dereferenced, not handed to the signer verbatim"
        );
    }

    #[test]
    fn an_unresolvable_aws_sigv4_reference_fails_closed_without_naming_it() {
        install_fixture_resolver();
        let error = AiProxyAction::from_config(serde_json::json!({
            "providers": [{
                "name": "bedrock",
                "provider_type": "bedrock",
                "aws_sigv4": {
                    "region": "us-east-1",
                    "credentials": {
                        "source": "static",
                        "access_key_id": "AKIDEXAMPLE",
                        "secret_access_key": "secret://fixture-guardrail/missing",
                    }
                }
            }]
        }))
        .expect_err("a missing secret must fail configuration, not sign with the reference");
        let message = error.to_string();
        assert!(message.contains("bedrock"), "{message}");
        assert!(
            !message.contains("secret://fixture-guardrail/missing"),
            "{message}"
        );
        assert!(!message.contains("resolved-guardrail-value"), "{message}");
    }

    /// WOR-2648: an unusable signing block is refused at config load,
    /// not on the first request. This runs in validation mode too, so
    /// `sbproxy validate` catches it before a deploy.
    #[test]
    fn an_unusable_aws_sigv4_block_is_refused_at_config_load() {
        let error = AiProxyAction::from_config(serde_json::json!({
            "providers": [{
                "name": "bedrock",
                "provider_type": "bedrock",
                "api_key": "Bearer leftover",
                "aws_sigv4": {"region": "us-east-1"}
            }]
        }))
        .expect_err("api_key alongside aws_sigv4 is refused");
        assert!(error.to_string().contains("mutually exclusive"), "{error}");

        let error = AiProxyAction::from_config(serde_json::json!({
            "providers": [{
                "name": "bedrock",
                "provider_type": "bedrock",
                "aws_sigv4": {
                    "region": "us-east-1",
                    "credentials": {"source": "static", "access_key_id": "AKIDEXAMPLE"}
                }
            }]
        }))
        .expect_err("a static source with no secret is refused");
        assert!(error.to_string().contains("secret_access_key"), "{error}");
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
        // The RAG resolver hook does not branch on construction mode, so
        // validate and plan run the same resolver path as runtime
        // construction whenever a resolver is installed.
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

    #[test]
    fn wasm_routing_without_a_registry_names_the_extensions_requirement() {
        // WOR-2366: only the action-compile layer can see the bundle
        // registry, and plain `from_config` carries none. An `engine:
        // wasm` routing policy must refuse loud here instead of booting
        // with the policy silently absent.
        let error = AiProxyAction::from_config(serde_json::json!({
            "providers": [],
            "ai_routing_policy": {"engine": "wasm", "type": "cost_router"}
        }))
        .expect_err("a wasm routing hook without a bundle registry must refuse");

        let message = format!("{error:#}");
        assert!(
            message.contains("requires a loaded extension bundle"),
            "{message}"
        );
        assert!(message.contains("`extensions:` block"), "{message}");
    }

    #[test]
    fn non_wasm_routing_policy_compiles_without_a_registry() {
        // The `None` registry threading must stay inert for inline
        // engines: a CEL routing policy neither needs nor sees a bundle.
        let action = AiProxyAction::from_config(serde_json::json!({
            "providers": [],
            "ai_routing_policy": {"expression": "null"}
        }))
        .expect("an inline routing policy must compile with no registry");

        assert!(
            action.config.ai_routing_policy.is_some(),
            "the inline routing policy must survive the registry-less path"
        );
    }

    /// A registry with no bundles loaded.
    ///
    /// Enough to prove the lookup runs on the validation path; not
    /// enough to answer with a hook, because a real `LoadedBundleHook`
    /// needs a bundle directory and a compiled artifact on disk. The
    /// resolves-and-prepares path is covered end to end by
    /// `e2e/tests/ai_routing_policy.rs`.
    fn empty_registry() -> std::sync::Arc<sbproxy_extension::bundle::DynamicBundleRegistry> {
        sbproxy_extension::bundle::DynamicBundleRegistry::load(
            &sbproxy_config::ExtensionBundlesConfig::default(),
            std::path::Path::new("."),
            &std::collections::BTreeSet::new(),
        )
        .expect("an empty extension bundle configuration is valid")
    }

    #[test]
    fn wasm_routing_validation_without_a_registry_names_the_extensions_requirement() {
        // Validation makes the same reachability demand the runtime
        // compile makes. Only the program build is runtime-only, so a
        // wasm form with nowhere to resolve against still refuses here.
        let error = AiProxyAction::from_config_for_validation(serde_json::json!({
            "providers": [],
            "ai_routing_policy": {"engine": "wasm", "type": "cost_router"}
        }))
        .expect_err("validating a wasm routing hook with no registry must refuse");

        // The `extensions:` fragment is what separates this refusal from
        // sbproxy-ai's own missing-program bail, which shares the leading
        // phrase: validation must stop at the action-compile layer.
        let message = format!("{error:#}");
        assert!(
            message.contains("requires a loaded extension bundle"),
            "{message}"
        );
        assert!(message.contains("`extensions:` block"), "{message}");
    }

    #[test]
    fn wasm_routing_validation_requires_a_hook_type() {
        // Config-shape errors are validation's job whether or not a
        // registry is in scope: an unnamed hook can never resolve.
        let error = AiProxyAction::from_config_for_validation(serde_json::json!({
            "providers": [],
            "ai_routing_policy": {"engine": "wasm"}
        }))
        .expect_err("a wasm routing policy with no `type` must refuse in validation");

        let message = format!("{error:#}");
        assert!(message.contains("requires `type:`"), "{message}");
    }

    #[test]
    fn wasm_routing_validation_resolves_the_hook_without_preparing_it() {
        // The split this test pins: validation looks the hook up, so a
        // typo'd `type:` refuses at plan time, and stops there. Preparing
        // is the step that applies the hook's schema defaults and
        // resolves its declared `secret_vars` through the process vault
        // resolver, and it names itself in its errors; that string must
        // never appear on a validation compile, whatever backends the
        // planning machine does or does not have. The `vars` document
        // below carries a reference nothing in this test can resolve, and
        // the refusal is the hook-lookup miss rather than a credential
        // failure.
        let registry = empty_registry();
        let error = AiProxyAction::from_config_for_validation_with_registry(
            serde_json::json!({
                "providers": [],
                "ai_routing_policy": {
                    "engine": "wasm",
                    "type": "cost_router",
                    "vars": {"api_key": "vault://no-such-backend/key"}
                }
            }),
            Some(registry.as_ref()),
        )
        .expect_err("an empty registry declares no `ai_routing` hook of that type");

        let message = format!("{error:#}");
        assert!(
            message.contains("no loaded extension bundle declares an `ai_routing` hook"),
            "{message}"
        );
        assert!(
            !message.contains("preparing wasm ai_routing hook"),
            "validation must not build the program: {message}"
        );
        assert!(!message.contains("vault://"), "{message}");
    }
}
