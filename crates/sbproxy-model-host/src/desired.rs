// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Normalization of canonical and legacy local-model desired state.

use std::collections::BTreeMap;

use sbproxy_config::{
    ManagedDeploymentConfig, ManagedEngineChoice, ManagedPullPolicy, ManagedRolloutPolicy,
    ModelHostAuthority, ModelHostControlConfig,
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
        if !control.deployments.contains_key(&provider.deployment) {
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

fn lower_canonical_deployment(config: &ManagedDeploymentConfig) -> ModelDeployment {
    ModelDeployment {
        model: config.model.clone(),
        variant: config.variant.clone(),
        heterogeneous_variants: config.heterogeneous_variants,
        replicas: config.replicas,
        required_labels: config.required_labels.clone(),
        pull: match config.pull {
            ManagedPullPolicy::OnBoot => PullPolicy::OnBoot,
            ManagedPullPolicy::OnDemand => PullPolicy::OnDemand,
            ManagedPullPolicy::Manual => PullPolicy::Manual,
        },
        warm: config.warm,
        keep_alive_secs: config.keep_alive_secs,
        max_concurrency: config.max_concurrency,
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
        required_labels: BTreeMap::new(),
        pull,
        warm: pull == PullPolicy::OnBoot,
        keep_alive_secs: entry
            .keep_alive_duration()
            .map(|duration| duration.as_secs()),
        max_concurrency,
        queue_timeout_ms: host.queue_timeout_ms.unwrap_or(30_000),
        engine: entry.engine,
        rollout: RolloutPolicy::Rolling,
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
