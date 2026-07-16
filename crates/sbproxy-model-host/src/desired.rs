// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Normalization of canonical and legacy local-model desired state.

use std::collections::BTreeMap;

use sbproxy_config::{
    ManagedColdStartPolicy, ManagedDeploymentConfig, ManagedEngineChoice, ManagedPullPolicy,
    ManagedRolloutPolicy, ModelHostAuthority, ModelHostControlConfig,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    Catalog, DeploymentRevisionDraft, DeploymentSourceMode, EngineChoice, EngineKind,
    EngineProvisioning, EvictionPolicy, ModelDeployment, ModelHostConfig, PullPolicy,
    RolloutPolicy, ServeEntry,
};

/// Canonical provider reference collected from one configured origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedProviderInput {
    /// Origin containing the provider.
    pub origin: String,
    /// Provider name used by the routing action.
    pub provider: String,
    /// Canonical deployment ID.
    pub deployment: String,
    /// Public model names exposed by this provider.
    pub models: Vec<String>,
}

/// Legacy `serve:` block collected from one configured origin.
#[derive(Debug, Clone, PartialEq)]
pub struct LegacyServeInput {
    /// Origin containing the provider.
    pub origin: String,
    /// Provider name used by the routing action.
    pub provider: String,
    /// Complete legacy model-host block.
    pub config: ModelHostConfig,
}

/// Every desired-state source collected from one configuration snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeDesiredInput {
    /// Immutable identity of the source configuration snapshot.
    pub source_revision: String,
    /// Canonical model-host configuration, when declared.
    pub canonical: Option<ModelHostControlConfig>,
    /// Canonical provider references from every origin.
    pub managed_providers: Vec<ManagedProviderInput>,
    /// Legacy `serve:` blocks from every origin.
    pub legacy_providers: Vec<LegacyServeInput>,
}

/// Source syntax from which a compiled deployment originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesiredDeploymentOrigin {
    /// Stable `proxy.model_host` syntax.
    Canonical,
    /// Compatibility lowering from a provider `serve:` block.
    LegacyServe,
}

/// Runtime detail retained alongside the canonical revision entry.
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledDeployment {
    /// Canonical lifecycle desired state.
    pub desired: ModelDeployment,
    /// Configuration syntax that produced this deployment.
    pub origin: DesiredDeploymentOrigin,
    /// Full legacy entry needed by compatibility engine planning.
    pub legacy_entry: Option<ServeEntry>,
}

/// One origin/provider/model route to a canonical deployment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeploymentRoute {
    /// Origin on which this route is active.
    pub origin: String,
    /// Configured provider name.
    pub provider: String,
    /// Public request model.
    pub model: String,
    /// Canonical deployment ID.
    pub deployment: String,
}

/// Host-wide policy retained while legacy syntax remains supported.
#[derive(Debug, Clone, PartialEq)]
pub struct LegacyHostPolicy {
    /// Optional catalog override.
    pub catalog_file: Option<String>,
    /// Optional model cache directory.
    pub cache_dir: Option<String>,
    /// Optional model cache budget in GiB.
    pub cache_budget_gib: Option<f64>,
    /// Idle model eviction behavior.
    pub eviction: EvictionPolicy,
    /// Per-engine legacy provisioning.
    pub engines: BTreeMap<EngineKind, EngineProvisioning>,
    /// Legacy process-wide admission cap.
    pub max_concurrent_requests: Option<usize>,
    /// Legacy queue timeout in milliseconds.
    pub queue_timeout_ms: Option<u64>,
}

impl From<&ModelHostConfig> for LegacyHostPolicy {
    fn from(config: &ModelHostConfig) -> Self {
        Self {
            catalog_file: config.catalog_file.clone(),
            cache_dir: config.cache_dir.clone(),
            cache_budget_gib: config.cache_budget_gib,
            eviction: config.eviction,
            engines: config.engines.clone(),
            max_concurrent_requests: config.max_concurrent_requests,
            queue_timeout_ms: config.queue_timeout_ms,
        }
    }
}

/// Fully validated process-wide desired state.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeDesiredState {
    /// Canonical immutable revision candidate.
    pub revision: DeploymentRevisionDraft,
    /// Runtime detail keyed by canonical deployment ID.
    pub deployments: BTreeMap<String, CompiledDeployment>,
    /// Deterministic route table retaining every configured origin.
    pub routes: Vec<DeploymentRoute>,
    /// Stable model-host policy, or defaults for legacy-only input.
    pub control: ModelHostControlConfig,
    /// One coherent compatibility policy for every legacy block.
    pub legacy_host_policy: Option<LegacyHostPolicy>,
}

impl RuntimeDesiredState {
    /// Find the deployment route for an exact origin, provider, and public model.
    pub fn route_for(&self, origin: &str, provider: &str, model: &str) -> Option<&DeploymentRoute> {
        self.routes.iter().find(|route| {
            route.origin == origin && route.provider == provider && route.model == model
        })
    }

    /// Stable SHA-256 identity of the complete global desired revision.
    pub fn revision_digest(&self) -> Result<String, DesiredStateError> {
        let bytes = serde_json::to_vec(&self.revision)
            .map_err(|error| DesiredStateError::Invalid(error.to_string()))?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

/// Complete-revision validation or normalization failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DesiredStateError {
    /// Public or legacy configuration is invalid.
    #[error("invalid desired state: {0}")]
    Invalid(String),
    /// A requested logical model or variant is absent from the catalog.
    #[error("catalog validation failed: {0}")]
    Catalog(String),
    /// A provider references no declared canonical deployment.
    #[error("provider {provider:?} references undeclared deployment {deployment:?}")]
    UndeclaredDeployment {
        /// Provider carrying the invalid reference.
        provider: String,
        /// Missing deployment ID.
        deployment: String,
    },
    /// Two complete inputs assign incompatible values to one stable field.
    #[error("conflicting {field}: {first}; {second}")]
    Conflict {
        /// Stable field or route identity.
        field: String,
        /// First complete value.
        first: String,
        /// Conflicting complete value.
        second: String,
    },
}

/// Compile canonical and compatibility configuration into one atomic desired state.
pub fn compile_desired_state(
    input: RuntimeDesiredInput,
    catalog: &Catalog,
) -> Result<RuntimeDesiredState, DesiredStateError> {
    if catalog.catalog_revision.trim().is_empty() {
        return Err(DesiredStateError::Catalog(
            "catalog revision must not be empty".to_string(),
        ));
    }

    let control = input.canonical.unwrap_or_default();
    control
        .validate()
        .map_err(|error| DesiredStateError::Invalid(error.to_string()))?;

    let mut revision_deployments = BTreeMap::new();
    let mut compiled_deployments = BTreeMap::new();
    for (id, deployment) in &control.deployments {
        validate_catalog_deployment(id, deployment, catalog)?;
        validate_canonical_engine_tuning(id, deployment)?;
        validate_canonical_engine_pin(id, deployment)?;
        let desired = lower_canonical_deployment(deployment);
        revision_deployments.insert(id.clone(), desired.clone());
        compiled_deployments.insert(
            id.clone(),
            CompiledDeployment {
                desired,
                origin: DesiredDeploymentOrigin::Canonical,
                legacy_entry: None,
            },
        );
    }

    let mut routes = Vec::new();
    let mut public_routes = BTreeMap::<(String, String), String>::new();
    for provider in &input.managed_providers {
        validate_route_identity(&provider.origin, &provider.provider)?;
        if !control.deployments.contains_key(&provider.deployment)
            && control.authority != ModelHostAuthority::AdminManaged
        {
            return Err(DesiredStateError::UndeclaredDeployment {
                provider: provider.provider.clone(),
                deployment: provider.deployment.clone(),
            });
        }
        let models = if provider.models.is_empty() {
            vec![provider.deployment.clone()]
        } else {
            provider.models.clone()
        };
        for model in models {
            insert_route(
                &mut routes,
                &mut public_routes,
                DeploymentRoute {
                    origin: provider.origin.clone(),
                    provider: provider.provider.clone(),
                    model,
                    deployment: provider.deployment.clone(),
                },
            )?;
        }
    }

    let mut legacy_host_policy = None;
    for legacy in &input.legacy_providers {
        validate_route_identity(&legacy.origin, &legacy.provider)?;
        legacy
            .config
            .validate()
            .map_err(DesiredStateError::Invalid)?;
        let policy = LegacyHostPolicy::from(&legacy.config);
        match &legacy_host_policy {
            None => legacy_host_policy = Some(policy),
            Some(first) if first == &policy => {}
            Some(first) => {
                return Err(DesiredStateError::Conflict {
                    field: "legacy host policy".to_string(),
                    first: format!("{first:?}"),
                    second: format!("{policy:?}"),
                });
            }
        }

        for entry in &legacy.config.models {
            validate_legacy_managed_compatibility(entry, None)
                .map_err(DesiredStateError::Invalid)?;
            validate_legacy_catalog_entry(entry, catalog)?;
            let public_model = entry.effective_name().map_err(DesiredStateError::Invalid)?;
            let deployment_id = legacy_deployment_id(&legacy.provider, &public_model, entry)?;
            let desired = lower_legacy_deployment(entry, &legacy.config, catalog)?;
            let compiled = CompiledDeployment {
                desired: desired.clone(),
                origin: DesiredDeploymentOrigin::LegacyServe,
                legacy_entry: Some(entry.clone()),
            };
            match compiled_deployments.get(&deployment_id) {
                None => {
                    revision_deployments.insert(deployment_id.clone(), desired);
                    compiled_deployments.insert(deployment_id.clone(), compiled);
                }
                Some(existing) if existing == &compiled => {}
                Some(existing) => {
                    return Err(DesiredStateError::Conflict {
                        field: format!("deployment {deployment_id}"),
                        first: format!("{existing:?}"),
                        second: format!("{compiled:?}"),
                    });
                }
            }

            insert_route(
                &mut routes,
                &mut public_routes,
                DeploymentRoute {
                    origin: legacy.origin.clone(),
                    provider: legacy.provider.clone(),
                    model: public_model,
                    deployment: deployment_id.clone(),
                },
            )?;
            for adapter in &entry.lora_adapters {
                insert_route(
                    &mut routes,
                    &mut public_routes,
                    DeploymentRoute {
                        origin: legacy.origin.clone(),
                        provider: legacy.provider.clone(),
                        model: adapter.name.clone(),
                        deployment: deployment_id.clone(),
                    },
                )?;
            }
        }
    }

    routes.sort();
    routes.dedup();
    let revision = DeploymentRevisionDraft {
        source_mode: lower_authority(control.authority),
        source_revision: input.source_revision,
        catalog_revision: catalog.catalog_revision.clone(),
        deployments: revision_deployments,
    };
    revision
        .validate()
        .map_err(|error| DesiredStateError::Invalid(error.to_string()))?;

    Ok(RuntimeDesiredState {
        revision,
        deployments: compiled_deployments,
        routes,
        control,
        legacy_host_policy,
    })
}

fn validate_route_identity(origin: &str, provider: &str) -> Result<(), DesiredStateError> {
    if origin.trim().is_empty() {
        return Err(DesiredStateError::Invalid(
            "route origin must not be empty".to_string(),
        ));
    }
    if provider.trim().is_empty() {
        return Err(DesiredStateError::Invalid(
            "route provider must not be empty".to_string(),
        ));
    }
    Ok(())
}

fn insert_route(
    routes: &mut Vec<DeploymentRoute>,
    public_routes: &mut BTreeMap<(String, String), String>,
    route: DeploymentRoute,
) -> Result<(), DesiredStateError> {
    if route.model.trim().is_empty() {
        return Err(DesiredStateError::Invalid(
            "public route model must not be empty".to_string(),
        ));
    }
    let key = (route.provider.clone(), route.model.clone());
    if let Some(existing) = public_routes.get(&key) {
        if existing != &route.deployment {
            return Err(DesiredStateError::Conflict {
                field: format!("route {}/{}", route.provider, route.model),
                first: existing.clone(),
                second: route.deployment,
            });
        }
    } else {
        public_routes.insert(key, route.deployment.clone());
    }
    routes.push(route);
    Ok(())
}

fn validate_catalog_deployment(
    id: &str,
    deployment: &ManagedDeploymentConfig,
    catalog: &Catalog,
) -> Result<(), DesiredStateError> {
    let entry = catalog.get(&deployment.model).ok_or_else(|| {
        DesiredStateError::Catalog(format!(
            "deployment {id:?} model {:?} is not in the catalog",
            deployment.model
        ))
    })?;
    if let Some(variant) = deployment.variant.as_deref() {
        if !entry
            .variants
            .iter()
            .any(|candidate| candidate.id == variant)
        {
            return Err(DesiredStateError::Catalog(format!(
                "deployment {id:?} model {:?} has no variant {variant:?}",
                deployment.model
            )));
        }
    }
    Ok(())
}

fn validate_legacy_catalog_entry(
    entry: &ServeEntry,
    catalog: &Catalog,
) -> Result<(), DesiredStateError> {
    if entry.model.starts_with("hf:") {
        catalog
            .resolve(&entry.model)
            .map_err(|error| DesiredStateError::Catalog(error.to_string()))?;
        return Ok(());
    }
    let catalog_entry = catalog.get(&entry.model).ok_or_else(|| {
        DesiredStateError::Catalog(format!("model {:?} is not in the catalog", entry.model))
    })?;
    if let Some(variant) = entry.variant.as_deref() {
        if !catalog_entry
            .variants
            .iter()
            .any(|candidate| candidate.id == variant)
        {
            return Err(DesiredStateError::Catalog(format!(
                "model {:?} has no variant {variant:?}",
                entry.model
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_legacy_managed_compatibility(
    entry: &ServeEntry,
    resolved_engine: Option<EngineKind>,
) -> Result<(), String> {
    // The four vLLM tuning passthroughs (chunked prefill, tool-call parser,
    // CPU KV swap, weight offload) are emitted by the vLLM driver, so they
    // are honored only when the resolved engine is vLLM. speculative
    // decoding and LoRA adapters have no runtime consumer yet and are
    // rejected regardless of engine. At config-load the engine may still be
    // `auto`; the reject is deferred to prepare (which re-runs this with the
    // resolved engine) rather than guessing, so only a pinned non-vLLM
    // engine trips the passthrough gate early.
    let vllm_passthrough_supported = match resolved_engine {
        Some(kind) => kind == EngineKind::Vllm,
        None => !matches!(
            entry.engine,
            EngineChoice::LlamaCpp | EngineChoice::Embedded
        ),
    };

    let mut unsupported = Vec::new();
    if entry.speculative.is_some() {
        unsupported.push("speculative");
    }
    if !entry.lora_adapters.is_empty() || entry.max_loras.is_some() {
        unsupported.push("lora_adapters/max_loras");
    }
    if !vllm_passthrough_supported {
        if entry.chunked_prefill.is_some() {
            unsupported.push("chunked_prefill");
        }
        if entry.tool_call_parser.is_some() {
            unsupported.push("tool_call_parser");
        }
        if entry.swap_space_gib.is_some() {
            unsupported.push("swap_space_gib");
        }
        if entry.cpu_offload_gib.is_some() {
            unsupported.push("cpu_offload_gib");
        }
    }
    if !unsupported.is_empty() {
        return Err(format!(
            "legacy serve model {:?} sets serving fields the managed runtime cannot honor here: {}. speculative decoding and lora_adapters are not yet supported; chunked_prefill, tool_call_parser, swap_space_gib, and cpu_offload_gib require the vLLM engine, so pin engine: vllm or remove them.",
            entry.model,
            unsupported.join(", "),
        ));
    }

    if entry.engine == EngineChoice::Auto && !entry.extra_args.is_empty() {
        for engine in [EngineKind::LlamaCpp, EngineKind::Vllm] {
            crate::validate_engine_args(engine, &entry.extra_args).map_err(|error| {
                format!(
                    "legacy serve model {:?} uses engine: auto with arguments that are not valid for every possible managed engine; pin engine explicitly: {error}",
                    entry.model
                )
            })?;
        }
        return Ok(());
    }

    let engine = resolved_engine.unwrap_or_else(|| entry.engine.resolve(false, false));
    crate::validate_engine_args(engine, &entry.extra_args)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Reject serving tuning a canonical deployment's engine cannot honor, and
/// validate its extra engine arguments, mirroring the legacy `serve:` gate.
fn validate_canonical_engine_tuning(
    id: &str,
    config: &ManagedDeploymentConfig,
) -> Result<(), DesiredStateError> {
    // The four vLLM tuning passthroughs are emitted only by the vLLM driver, so
    // an explicitly non-vLLM engine that sets them is rejected. engine: auto
    // defers to the resolved engine, which ignores them when it is not vLLM.
    if config.engine == ManagedEngineChoice::LlamaCpp {
        let mut unsupported = Vec::new();
        if config.chunked_prefill.is_some() {
            unsupported.push("chunked_prefill");
        }
        if config.tool_call_parser.is_some() {
            unsupported.push("tool_call_parser");
        }
        if config.swap_space_gib.is_some() {
            unsupported.push("swap_space_gib");
        }
        if config.cpu_offload_gib.is_some() {
            unsupported.push("cpu_offload_gib");
        }
        if !unsupported.is_empty() {
            return Err(DesiredStateError::Invalid(format!(
                "managed deployment {id:?} sets vLLM-only serving fields on engine: llama_cpp: {}. pin engine: vllm or remove them.",
                unsupported.join(", ")
            )));
        }
    }
    if config.extra_args.is_empty() {
        return Ok(());
    }
    let engines: &[EngineKind] = match config.engine {
        ManagedEngineChoice::Vllm => &[EngineKind::Vllm],
        ManagedEngineChoice::LlamaCpp => &[EngineKind::LlamaCpp],
        ManagedEngineChoice::Auto => &[EngineKind::LlamaCpp, EngineKind::Vllm],
    };
    for engine in engines {
        crate::validate_engine_args(*engine, &config.extra_args).map_err(|error| {
            DesiredStateError::Invalid(format!(
                "managed deployment {id:?} sets extra_args not valid for engine {engine:?}: {error}"
            ))
        })?;
    }
    Ok(())
}

/// Hold a per-deployment engine pin to the same strictness as the node-wide
/// engine policy: a version is never `latest`, and an image is tag- or
/// digest-pinned.
fn validate_canonical_engine_pin(
    id: &str,
    config: &ManagedDeploymentConfig,
) -> Result<(), DesiredStateError> {
    if config.engine_version.as_deref() == Some("latest") {
        return Err(DesiredStateError::Invalid(format!(
            "managed deployment {id:?} engine_version must be a pinned version, not `latest`"
        )));
    }
    if let Some(image) = &config.engine_image {
        let provisioning = crate::EngineProvisioning {
            image: Some(image.clone()),
            ..Default::default()
        };
        if !provisioning.image_is_pinned() {
            return Err(DesiredStateError::Invalid(format!(
                "managed deployment {id:?} engine_image {image:?} must be tag- or digest-pinned, not `latest` or untagged"
            )));
        }
    }
    Ok(())
}

fn lower_canonical_deployment(config: &ManagedDeploymentConfig) -> ModelDeployment {
    ModelDeployment {
        model: config.model.clone(),
        variant: config.variant.clone(),
        heterogeneous_variants: config.heterogeneous_variants,
        replicas: config.replicas,
        tensor_parallel: config.tensor_parallel,
        required_labels: config.required_labels.clone(),
        spread_by: config.spread_by.clone(),
        pull: match config.pull {
            ManagedPullPolicy::OnBoot => PullPolicy::OnBoot,
            ManagedPullPolicy::OnDemand => PullPolicy::OnDemand,
            ManagedPullPolicy::Manual => PullPolicy::Manual,
        },
        warm: config.warm,
        cold_start: match config.cold_start.unwrap_or(ManagedColdStartPolicy::Wait) {
            ManagedColdStartPolicy::Wait => crate::ColdStartPolicy::Wait,
            ManagedColdStartPolicy::Reject => crate::ColdStartPolicy::Reject,
            ManagedColdStartPolicy::Fallback => crate::ColdStartPolicy::Fallback,
        },
        keep_alive_secs: config.keep_alive_secs,
        max_concurrency: config.max_concurrency,
        max_queue_depth: config.max_queue_depth,
        queue_timeout_ms: config.queue_timeout_ms,
        engine: match config.engine {
            ManagedEngineChoice::Auto => EngineChoice::Auto,
            ManagedEngineChoice::Vllm => EngineChoice::Vllm,
            ManagedEngineChoice::LlamaCpp => EngineChoice::LlamaCpp,
        },
        rollout: match config.rollout {
            ManagedRolloutPolicy::Rolling => RolloutPolicy::Rolling,
            ManagedRolloutPolicy::Recreate => RolloutPolicy::Recreate,
        },
        extra_args: config.extra_args.clone(),
        chunked_prefill: config.chunked_prefill.map(|prefill| crate::ChunkedPrefill {
            max_batched_tokens: prefill.max_batched_tokens,
            target_ttft_ms: prefill.target_ttft_ms,
        }),
        tool_call_parser: config.tool_call_parser.clone(),
        swap_space_gib: config.swap_space_gib,
        cpu_offload_gib: config.cpu_offload_gib,
        engine_version: config.engine_version.clone(),
        engine_image: config.engine_image.clone(),
        engine_sha256: config.engine_sha256.clone(),
    }
}

fn lower_legacy_deployment(
    entry: &ServeEntry,
    host: &ModelHostConfig,
    catalog: &Catalog,
) -> Result<ModelDeployment, DesiredStateError> {
    let max_concurrency = host
        .max_concurrent_requests
        .map(u32::try_from)
        .transpose()
        .map_err(|_| {
            DesiredStateError::Invalid(
                "legacy max_concurrent_requests exceeds the canonical u32 limit".to_string(),
            )
        })?;
    let pull = catalog
        .get(&entry.model)
        .map(|catalog_entry| catalog_entry.pull)
        .unwrap_or_default();
    Ok(ModelDeployment {
        model: entry.model.clone(),
        variant: entry.variant.clone(),
        heterogeneous_variants: false,
        replicas: 1,
        tensor_parallel: None,
        required_labels: BTreeMap::new(),
        spread_by: Vec::new(),
        pull,
        warm: pull == PullPolicy::OnBoot,
        cold_start: crate::ColdStartPolicy::Wait,
        keep_alive_secs: entry
            .keep_alive_duration()
            .map(|duration| duration.as_secs()),
        max_concurrency,
        max_queue_depth: 128,
        queue_timeout_ms: host.queue_timeout_ms.unwrap_or(30_000),
        engine: entry.engine,
        rollout: RolloutPolicy::Rolling,
        // Legacy serving tuning stays on `legacy_entry`; the canonical
        // ModelDeployment tuning fields are unused on this path.
        extra_args: Vec::new(),
        chunked_prefill: None,
        tool_call_parser: None,
        swap_space_gib: None,
        cpu_offload_gib: None,
        engine_version: None,
        engine_image: None,
        engine_sha256: None,
    })
}

fn lower_authority(authority: ModelHostAuthority) -> DeploymentSourceMode {
    match authority {
        ModelHostAuthority::FileManaged => DeploymentSourceMode::FileManaged,
        ModelHostAuthority::AdminManaged => DeploymentSourceMode::AdminManaged,
        ModelHostAuthority::ClusterAuthority => DeploymentSourceMode::ClusterAuthority,
    }
}

#[derive(Serialize)]
struct LegacyDeploymentIdentity<'a> {
    provider: &'a str,
    public_model: &'a str,
    entry: &'a ServeEntry,
}

fn legacy_deployment_id(
    provider: &str,
    public_model: &str,
    entry: &ServeEntry,
) -> Result<String, DesiredStateError> {
    let material = LegacyDeploymentIdentity {
        provider,
        public_model,
        entry,
    };
    let canonical = serde_json_canonicalizer::to_vec(&material)
        .map_err(|error| DesiredStateError::Invalid(error.to_string()))?;
    let digest = hex::encode(Sha256::digest(canonical));
    Ok(format!(
        "legacy-{}-{}-{}",
        identifier_fragment(provider),
        identifier_fragment(public_model),
        &digest[..8]
    ))
}

fn identifier_fragment(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut previous_separator = false;
    for character in value.chars() {
        let character = character.to_ascii_lowercase();
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '_') {
            result.push(character);
            previous_separator = false;
        } else if !previous_separator {
            result.push('-');
            previous_separator = true;
        }
    }
    let trimmed = result.trim_matches('-');
    if trimmed.is_empty() {
        "unnamed".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::validate_legacy_managed_compatibility;
    use crate::{EngineKind, ModelHostConfig, ServeEntry};

    fn first_entry(yaml: &str) -> ServeEntry {
        serde_yaml::from_str::<ModelHostConfig>(yaml)
            .expect("fixture parses")
            .models
            .into_iter()
            .next()
            .expect("fixture declares a model")
    }

    #[test]
    fn vllm_passthroughs_are_accepted_for_vllm() {
        let entry = first_entry(
            "models:\n  - model: qwen3-8b\n    engine: vllm\n    chunked_prefill: {}\n    tool_call_parser: hermes\n    swap_space_gib: 16\n    cpu_offload_gib: 8\n",
        );
        validate_legacy_managed_compatibility(&entry, Some(EngineKind::Vllm))
            .expect("the vLLM driver emits every tuning passthrough");
    }

    #[test]
    fn vllm_passthroughs_are_rejected_for_a_non_vllm_engine() {
        let entry = first_entry("models:\n  - model: qwen3-8b\n    swap_space_gib: 16\n");
        let error = validate_legacy_managed_compatibility(&entry, Some(EngineKind::LlamaCpp))
            .expect_err("llama.cpp does not emit the vLLM tuning flags");
        assert!(error.contains("swap_space_gib"), "{error}");
    }

    #[test]
    fn speculative_and_lora_are_rejected_even_on_vllm() {
        let entry = first_entry(
            "models:\n  - model: qwen3-8b\n    engine: vllm\n    speculative: {}\n    lora_adapters:\n      - name: a\n        source: hf:o/a\n",
        );
        let error = validate_legacy_managed_compatibility(&entry, Some(EngineKind::Vllm))
            .expect_err("speculative decoding and LoRA have no runtime consumer yet");
        assert!(error.contains("speculative"), "{error}");
        assert!(error.contains("lora_adapters"), "{error}");
    }

    fn canonical(yaml: &str) -> sbproxy_config::ManagedDeploymentConfig {
        serde_yaml::from_str(yaml).expect("managed deployment parses")
    }

    #[test]
    fn canonical_vllm_tuning_is_rejected_on_llama_cpp() {
        let config = canonical("model: qwen3-8b\nengine: llama_cpp\nswap_space_gib: 16\n");
        let error = super::validate_canonical_engine_tuning("local", &config)
            .expect_err("llama.cpp does not emit the vLLM tuning flags");
        assert!(error.to_string().contains("swap_space_gib"), "{error:?}");
    }

    #[test]
    fn canonical_vllm_tuning_is_accepted_on_vllm_and_auto() {
        for engine in ["vllm", "auto"] {
            let config = canonical(&format!(
                "model: qwen3-8b\nengine: {engine}\ntool_call_parser: hermes\nswap_space_gib: 16\n"
            ));
            super::validate_canonical_engine_tuning("local", &config)
                .unwrap_or_else(|error| panic!("engine {engine} accepts the tuning: {error:?}"));
        }
    }

    #[test]
    fn canonical_tuning_lowers_onto_the_deployment() {
        let config = canonical(
            "model: qwen3-8b\nengine: vllm\ntool_call_parser: hermes\nswap_space_gib: 16\ncpu_offload_gib: 8\nchunked_prefill:\n  max_batched_tokens: 2048\n",
        );
        let lowered = super::lower_canonical_deployment(&config);
        assert_eq!(lowered.tool_call_parser.as_deref(), Some("hermes"));
        assert_eq!(lowered.swap_space_gib, Some(16));
        assert_eq!(lowered.cpu_offload_gib, Some(8));
        assert_eq!(
            lowered
                .chunked_prefill
                .and_then(|prefill| prefill.max_batched_tokens),
            Some(2048)
        );
    }

    #[test]
    fn engine_pin_lowers_and_accepts_a_pinned_version_and_image() {
        let config = canonical(
            "model: qwen3-8b\nengine: vllm\nengine_version: 0.11.0\nengine_image: vllm/vllm-openai:v0.11.0\nengine_sha256: abc123\n",
        );
        super::validate_canonical_engine_pin("local", &config).expect("a pinned version and image");
        let lowered = super::lower_canonical_deployment(&config);
        assert_eq!(lowered.engine_version.as_deref(), Some("0.11.0"));
        assert_eq!(
            lowered.engine_image.as_deref(),
            Some("vllm/vllm-openai:v0.11.0")
        );
        assert_eq!(lowered.engine_sha256.as_deref(), Some("abc123"));
    }

    #[test]
    fn engine_pin_rejects_latest_version() {
        let config = canonical("model: qwen3-8b\nengine_version: latest\n");
        let error = super::validate_canonical_engine_pin("local", &config)
            .expect_err("latest is not a pinned version");
        assert!(error.to_string().contains("latest"), "{error:?}");
    }

    #[test]
    fn engine_pin_rejects_an_unpinned_image() {
        for image in ["vllm/vllm-openai", "vllm/vllm-openai:latest"] {
            let config = canonical(&format!("model: qwen3-8b\nengine_image: {image}\n"));
            let error = super::validate_canonical_engine_pin("local", &config)
                .expect_err(&format!("image {image} must be pinned"));
            assert!(error.to_string().contains("pinned"), "{error:?}");
        }
    }
}
