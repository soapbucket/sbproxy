// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Executable model-host capability contract (WOR-1836).
//!
//! This registry is the source of truth for model-host support claims.
//! It covers both product capabilities and every field in the current
//! `serve:` schema. Stable configuration fields carry a small executable
//! consumer contract; fields that are parsed ahead of their complete
//! runtime behavior remain explicitly preview or config-only.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::config::{EngineChoice, KvCacheQuant};
use crate::{ModelHostConfig, ServeEntry};

/// Schema version of the model-host capability registry.
pub const CAPABILITY_REGISTRY_VERSION: u32 = 1;

/// Model-host product area governed by a capability entry.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityDomain {
    /// Catalog and model-manifest behavior.
    Manifest,
    /// Artifact acquisition, verification, and cache behavior.
    Artifact,
    /// Managed inference engines.
    Engine,
    /// Model process and residency lifecycle.
    Lifecycle,
    /// Multi-node membership, placement, and dispatch.
    Cluster,
    /// Key and request governance applied to model routes.
    Policy,
    /// Administrative API and UI behavior.
    Admin,
    /// Supported host platforms and accelerator discovery.
    Platform,
}

impl CapabilityDomain {
    fn as_str(self) -> &'static str {
        match self {
            Self::Manifest => "manifest",
            Self::Artifact => "artifact",
            Self::Engine => "engine",
            Self::Lifecycle => "lifecycle",
            Self::Cluster => "cluster",
            Self::Policy => "policy",
            Self::Admin => "admin",
            Self::Platform => "platform",
        }
    }
}

/// Product-support level exposed to config, CLI, admin, and docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SupportLevel {
    /// Executable end-to-end behavior with named evidence.
    Stable,
    /// Runnable behavior whose production contract is not yet complete.
    Preview,
    /// A parsed or displayed field without an executable consumer.
    ConfigOnly,
    /// Behavior intentionally unavailable in this build.
    Unsupported,
}

impl SupportLevel {
    /// Stable snake-case representation used in JSON and generated docs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Preview => "preview",
            Self::ConfigOnly => "config_only",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Executable behavior probe attached to a stable configuration field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumerContract {
    /// A serve model changes the normalized model-name set.
    ServeModelsChangeDesiredDeployments,
    /// A legacy catalog ID resolves to the declared repository and quant.
    CatalogIdResolvesExactRepo,
    /// An explicit cache directory changes artifact addressing.
    CacheDirectoryChangesArtifactPath,
    /// The eviction field changes admission under a full budget.
    EvictionChangesAdmission,
    /// The concurrency cap changes request scheduling.
    PriorityGateChangesDispatch,
}

impl ConsumerContract {
    /// Stable evidence ID rendered into the capability matrix.
    pub const fn id(self) -> &'static str {
        match self {
            Self::ServeModelsChangeDesiredDeployments => {
                "contract.serve_models_change_desired_deployments"
            }
            Self::CatalogIdResolvesExactRepo => "contract.catalog_id_resolves_exact_repo",
            Self::CacheDirectoryChangesArtifactPath => {
                "contract.cache_directory_changes_artifact_path"
            }
            Self::EvictionChangesAdmission => "contract.eviction_changes_admission",
            Self::PriorityGateChangesDispatch => "contract.priority_gate_changes_dispatch",
        }
    }

    /// Execute the deterministic behavior probe for this contract.
    pub fn assert_behavior(self) -> Result<(), String> {
        match self {
            Self::ServeModelsChangeDesiredDeployments => {
                let config: ModelHostConfig = serde_yaml::from_str(
                    "models:\n  - model: one\n  - model: two\n    name: public-two\n",
                )
                .map_err(|error| error.to_string())?;
                let actual = config.model_names()?;
                let expected = vec!["one".to_string(), "public-two".to_string()];
                (actual == expected)
                    .then_some(())
                    .ok_or_else(|| format!("expected {expected:?}, got {actual:?}"))
            }
            Self::CatalogIdResolvesExactRepo => {
                let catalog = crate::Catalog::from_yaml(
                    "models:\n  exact:\n    hf_repo: Org/Exact\n    quants: [Q4_K_M]\n    params: 1B\n    license: apache-2.0\n    family: fixture\n    min_vram_hint_gib: 1.0\n",
                )
                .map_err(|error| error.to_string())?;
                let resolved = catalog
                    .resolve("exact")
                    .map_err(|error| error.to_string())?;
                if resolved.hf_repo != "Org/Exact" || resolved.quant != "Q4_K_M" {
                    return Err(format!("legacy resolution returned {resolved:?}"));
                }
                Ok(())
            }
            Self::CacheDirectoryChangesArtifactPath => {
                let config: ModelHostConfig = serde_yaml::from_str(
                    "cache_dir: /tmp/model-cache\nmodels:\n  - model: exact\n",
                )
                .map_err(|error| error.to_string())?;
                let actual = crate::manifest::resolve_cache_dir(config.cache_dir.as_deref(), None);
                (actual == std::path::Path::new("/tmp/model-cache"))
                    .then_some(())
                    .ok_or_else(|| format!("explicit cache directory resolved to {actual:?}"))
            }
            Self::EvictionChangesAdmission => {
                use crate::residency::ResidencyManager;

                let lru_config: ModelHostConfig =
                    serde_yaml::from_str("eviction: lru\nmodels: []\n")
                        .map_err(|error| error.to_string())?;
                let never_config: ModelHostConfig =
                    serde_yaml::from_str("eviction: never\nmodels: []\n")
                        .map_err(|error| error.to_string())?;
                let mut lru = ResidencyManager::new(10, lru_config.eviction);
                lru.load("old", 10, 1)?;
                let evicted = lru.load("new", 10, 2)?;
                if evicted != ["old".to_string()] {
                    return Err(format!("LRU evicted {evicted:?}"));
                }

                let mut never = ResidencyManager::new(10, never_config.eviction);
                never.load("old", 10, 1)?;
                never
                    .load("new", 10, 2)
                    .expect_err("never policy must reject instead of evicting");
                Ok(())
            }
            Self::PriorityGateChangesDispatch => {
                use crate::scheduling::{admit, PriorityClass, SchedulingDecision};

                let capped_config: ModelHostConfig =
                    serde_yaml::from_str("max_concurrent_requests: 1\nmodels: []\n")
                        .map_err(|error| error.to_string())?;
                let roomy_config: ModelHostConfig =
                    serde_yaml::from_str("max_concurrent_requests: 2\nmodels: []\n")
                        .map_err(|error| error.to_string())?;
                let running = [PriorityClass::Standard];
                let capped = admit(
                    PriorityClass::Standard,
                    &running,
                    capped_config.max_concurrent_requests.unwrap_or_default(),
                );
                let roomy = admit(
                    PriorityClass::Standard,
                    &running,
                    roomy_config.max_concurrent_requests.unwrap_or_default(),
                );
                if capped != SchedulingDecision::Queue || roomy != SchedulingDecision::Admit {
                    return Err(format!("capacity decisions were {capped:?} and {roomy:?}"));
                }
                Ok(())
            }
        }
    }
}

/// One serializable product capability.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct CapabilityEntry {
    /// Stable dotted identifier.
    pub id: &'static str,
    /// Product area.
    pub domain: CapabilityDomain,
    /// Current support level.
    pub status: SupportLevel,
    /// Concise operator-facing behavior summary.
    pub summary: &'static str,
    /// Test, source, or certification identifiers backing a stable claim.
    pub evidence: &'static [&'static str],
    /// Executable behavior probe, required for stable capabilities.
    #[serde(skip)]
    pub consumer: Option<ConsumerContract>,
}

/// Capability classification for one `serve:` schema field.
#[derive(Debug, Clone, Copy)]
pub struct ConfigFieldCapability {
    /// Stable JSON-style configuration path.
    pub path: &'static str,
    /// Current support level.
    pub status: SupportLevel,
    /// Capability entry that owns the field.
    pub capability_id: &'static str,
    /// Executable consumer probe, required for stable fields.
    pub consumer: Option<ConsumerContract>,
}

/// A non-stable configured field surfaced to validation and planning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilityFinding {
    /// Configuration path.
    pub path: String,
    /// Current field support level.
    pub status: SupportLevel,
    /// Actionable support explanation.
    pub message: String,
}

/// Immutable versioned registry used by config, CLI, admin, and docs.
pub struct CapabilityRegistry {
    version: u32,
    entries: &'static [CapabilityEntry],
    config_fields: &'static [ConfigFieldCapability],
}

impl CapabilityRegistry {
    /// Registry schema version.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Product capability entries in deterministic display order.
    pub const fn entries(&self) -> &'static [CapabilityEntry] {
        self.entries
    }

    /// Configuration-field classifications in schema order.
    pub const fn config_fields(&self) -> &'static [ConfigFieldCapability] {
        self.config_fields
    }

    /// Validate registry uniqueness, evidence, references, domains, and
    /// complete `ModelHostConfig` plus `ServeEntry` schema coverage.
    pub fn validate(&self) -> Result<(), String> {
        if self.version == 0 {
            return Err("capability registry version must be positive".to_string());
        }

        let mut ids = BTreeSet::new();
        let mut domains = BTreeSet::new();
        for entry in self.entries {
            if !ids.insert(entry.id) {
                return Err(format!("duplicate capability id '{}'", entry.id));
            }
            domains.insert(entry.domain);
            if entry.status == SupportLevel::Stable && entry.evidence.is_empty() {
                return Err(format!(
                    "stable capability '{}' has no executable evidence",
                    entry.id
                ));
            }
            if entry.status == SupportLevel::Stable {
                let consumer = entry.consumer.ok_or_else(|| {
                    format!(
                        "stable capability '{}' has no executable consumer contract",
                        entry.id
                    )
                })?;
                if !entry.evidence.contains(&consumer.id()) {
                    return Err(format!(
                        "stable capability '{}' does not name consumer '{}' as evidence",
                        entry.id,
                        consumer.id()
                    ));
                }
            }
        }
        let required_domains = BTreeSet::from([
            CapabilityDomain::Manifest,
            CapabilityDomain::Artifact,
            CapabilityDomain::Engine,
            CapabilityDomain::Lifecycle,
            CapabilityDomain::Cluster,
            CapabilityDomain::Policy,
            CapabilityDomain::Admin,
            CapabilityDomain::Platform,
        ]);
        if domains != required_domains {
            return Err(format!(
                "capability domains differ: expected {required_domains:?}, got {domains:?}"
            ));
        }

        let mut paths = BTreeSet::new();
        for field in self.config_fields {
            if !paths.insert(field.path) {
                return Err(format!("duplicate config capability path '{}'", field.path));
            }
            if !ids.contains(field.capability_id) {
                return Err(format!(
                    "config field '{}' names unknown capability '{}'",
                    field.path, field.capability_id
                ));
            }
            if field.status == SupportLevel::Stable && field.consumer.is_none() {
                return Err(format!(
                    "stable config field '{}' has no consumer contract",
                    field.path
                ));
            }
            if field.status == SupportLevel::Stable {
                let owner = self
                    .entries
                    .iter()
                    .find(|entry| entry.id == field.capability_id)
                    .expect("capability existence checked above");
                if owner.status != SupportLevel::Stable {
                    return Err(format!(
                        "stable config field '{}' belongs to non-stable capability '{}'",
                        field.path, field.capability_id
                    ));
                }
            }
        }

        let expected_paths = schema_field_paths()?;
        if paths != expected_paths {
            let missing: Vec<_> = expected_paths.difference(&paths).copied().collect();
            let extra: Vec<_> = paths.difference(&expected_paths).copied().collect();
            return Err(format!(
                "config field registry differs from schema; missing={missing:?}, extra={extra:?}"
            ));
        }
        self.validate_schema_descriptions()?;
        Ok(())
    }

    /// Ensure every non-stable field identifies its exact support level
    /// in the generated JSON Schema description.
    pub fn validate_schema_descriptions(&self) -> Result<(), String> {
        let host = serde_json::to_value(schemars::schema_for!(ModelHostConfig))
            .map_err(|error| format!("serialize ModelHostConfig schema: {error}"))?;
        let entry = serde_json::to_value(schemars::schema_for!(ServeEntry))
            .map_err(|error| format!("serialize ServeEntry schema: {error}"))?;

        for field in self
            .config_fields
            .iter()
            .filter(|field| field.status != SupportLevel::Stable)
        {
            let (schema, property) = match field.path.strip_prefix("serve.models[].") {
                Some(property) => (&entry, property),
                None => {
                    let property = field
                        .path
                        .strip_prefix("serve.")
                        .ok_or_else(|| format!("invalid config field path '{}'", field.path))?;
                    (&host, property)
                }
            };
            let description = schema
                .get("properties")
                .and_then(|properties| properties.get(property))
                .and_then(|property| property.get("description"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let label = format!("Support: {}.", field.status.as_str());
            if !description.contains(&label) {
                return Err(format!(
                    "config field '{}' schema description must contain '{label}'",
                    field.path
                ));
            }
        }
        Ok(())
    }

    /// Return findings for every actively configured non-stable field.
    pub fn validate_config(&self, config: &ModelHostConfig) -> Vec<CapabilityFinding> {
        self.config_fields
            .iter()
            .filter(|field| field.status != SupportLevel::Stable)
            .filter(|field| field_is_active(field.path, config))
            .map(|field| CapabilityFinding {
                path: field.path.to_string(),
                status: field.status,
                message: format!(
                    "{} is {} under capability {}; consult the model-host capability matrix",
                    field.path,
                    field.status.as_str(),
                    field.capability_id
                ),
            })
            .collect()
    }

    /// Render the deterministic checked-in Markdown capability matrix.
    pub fn render_markdown(&self) -> String {
        let mut output = String::from(
            "# Model-host capability matrix\n*Last modified: 2026-07-10*\n\n*Generated from the executable registry; do not hand-edit.*\n\n",
        );
        output.push_str(&format!("Registry version: `{}`\n\n", self.version));
        output.push_str("## Product capabilities\n\n");
        output.push_str("| Capability | Domain | Status | Evidence | Summary |\n");
        output.push_str("| --- | --- | --- | --- | --- |\n");
        for entry in self.entries {
            let evidence = if entry.evidence.is_empty() {
                "none".to_string()
            } else {
                entry.evidence.join("<br>")
            };
            output.push_str(&format!(
                "| `{}` | `{}` | `{}` | {} | {} |\n",
                entry.id,
                entry.domain.as_str(),
                entry.status.as_str(),
                evidence,
                entry.summary
            ));
        }
        output.push_str("\n## Configuration fields\n\n");
        output.push_str("| Field | Status | Capability | Consumer contract |\n");
        output.push_str("| --- | --- | --- | --- |\n");
        for field in self.config_fields {
            let consumer = field.consumer.map(ConsumerContract::id).unwrap_or("none");
            output.push_str(&format!(
                "| `{}` | `{}` | `{}` | `{}` |\n",
                field.path,
                field.status.as_str(),
                field.capability_id,
                consumer
            ));
        }
        output
    }
}

fn schema_field_paths() -> Result<BTreeSet<&'static str>, String> {
    let host = schemars::schema_for!(ModelHostConfig);
    let serve_entry = schemars::schema_for!(ServeEntry);
    let host_object = host
        .schema
        .object
        .as_ref()
        .ok_or_else(|| "ModelHostConfig schema is not an object".to_string())?;
    let entry_object = serve_entry
        .schema
        .object
        .as_ref()
        .ok_or_else(|| "ServeEntry schema is not an object".to_string())?;

    let mut paths = BTreeSet::new();
    for property in host_object.properties.keys() {
        let path = CONFIG_FIELDS
            .iter()
            .find(|field| field.path == format!("serve.{property}"))
            .map(|field| field.path)
            .ok_or_else(|| format!("no static path for ModelHostConfig property '{property}'"))?;
        paths.insert(path);
    }
    for property in entry_object.properties.keys() {
        let wanted = format!("serve.models[].{property}");
        let path = CONFIG_FIELDS
            .iter()
            .find(|field| field.path == wanted)
            .map(|field| field.path)
            .ok_or_else(|| format!("no static path for ServeEntry property '{property}'"))?;
        paths.insert(path);
    }
    Ok(paths)
}

fn field_is_active(path: &str, config: &ModelHostConfig) -> bool {
    match path {
        "serve.catalog_file" => config.catalog_file.is_some(),
        "serve.cache_budget_gib" => config.cache_budget_gib.is_some(),
        "serve.engines" => !config.engines.is_empty(),
        "serve.queue_timeout_ms" => config.queue_timeout_ms.is_some(),
        "serve.models[].engine" => config
            .models
            .iter()
            .any(|entry| entry.engine != EngineChoice::Auto),
        "serve.models[].keep_alive" => config.models.iter().any(|entry| entry.keep_alive.is_some()),
        "serve.models[].max_context" => config
            .models
            .iter()
            .any(|entry| entry.max_context.is_some()),
        "serve.models[].extra_args" => config
            .models
            .iter()
            .any(|entry| !entry.extra_args.is_empty()),
        "serve.models[].kv_quant" => config
            .models
            .iter()
            .any(|entry| entry.kv_quant != KvCacheQuant::Auto),
        "serve.models[].speculative" => config
            .models
            .iter()
            .any(|entry| entry.speculative.is_some()),
        "serve.models[].chunked_prefill" => config
            .models
            .iter()
            .any(|entry| entry.chunked_prefill.is_some()),
        "serve.models[].lora_adapters" => config
            .models
            .iter()
            .any(|entry| !entry.lora_adapters.is_empty()),
        "serve.models[].pinned" => config.models.iter().any(|entry| entry.pinned),
        "serve.models[].tool_call_parser" => config
            .models
            .iter()
            .any(|entry| entry.tool_call_parser.is_some()),
        "serve.models[].swap_space_gib" => config
            .models
            .iter()
            .any(|entry| entry.swap_space_gib.is_some()),
        "serve.models[].cpu_offload_gib" => config
            .models
            .iter()
            .any(|entry| entry.cpu_offload_gib.is_some()),
        "serve.models[].max_loras" => config.models.iter().any(|entry| entry.max_loras.is_some()),
        "serve.models[].gguf_file" => config.models.iter().any(|entry| entry.gguf_file.is_some()),
        _ => false,
    }
}

const CAPABILITIES: &[CapabilityEntry] = &[
    CapabilityEntry {
        id: "manifest.serve_model_declarations",
        domain: CapabilityDomain::Manifest,
        status: SupportLevel::Stable,
        summary: "Serve model declarations change normalized desired model names.",
        evidence: &["contract.serve_models_change_desired_deployments"],
        consumer: Some(ConsumerContract::ServeModelsChangeDesiredDeployments),
    },
    CapabilityEntry {
        id: "manifest.legacy_catalog_resolution",
        domain: CapabilityDomain::Manifest,
        status: SupportLevel::Stable,
        summary: "Legacy catalog IDs resolve during the migration window.",
        evidence: &["contract.catalog_id_resolves_exact_repo"],
        consumer: Some(ConsumerContract::CatalogIdResolvesExactRepo),
    },
    CapabilityEntry {
        id: "manifest.catalog_v2",
        domain: CapabilityDomain::Manifest,
        status: SupportLevel::Preview,
        summary: "Typed immutable artifact variants land in the foundations PR.",
        evidence: &[],
        consumer: None,
    },
    CapabilityEntry {
        id: "artifact.legacy_download",
        domain: CapabilityDomain::Artifact,
        status: SupportLevel::Preview,
        summary: "Legacy file downloads lack the complete atomic artifact contract.",
        evidence: &[],
        consumer: None,
    },
    CapabilityEntry {
        id: "artifact.cache_addressing",
        domain: CapabilityDomain::Artifact,
        status: SupportLevel::Stable,
        summary: "Explicit cache directories deterministically change artifact paths.",
        evidence: &["contract.cache_directory_changes_artifact_path"],
        consumer: Some(ConsumerContract::CacheDirectoryChangesArtifactPath),
    },
    CapabilityEntry {
        id: "artifact.cache_budget",
        domain: CapabilityDomain::Artifact,
        status: SupportLevel::ConfigOnly,
        summary: "Cache budget is parsed but safe protected collection is not yet active.",
        evidence: &[],
        consumer: None,
    },
    CapabilityEntry {
        id: "engine.managed_launch",
        domain: CapabilityDomain::Engine,
        status: SupportLevel::Preview,
        summary: "llama.cpp and vLLM launch paths require managed-artifact hardening.",
        evidence: &[],
        consumer: None,
    },
    CapabilityEntry {
        id: "engine.container_launch",
        domain: CapabilityDomain::Engine,
        status: SupportLevel::ConfigOnly,
        summary: "Container launch configuration is not an executable stable path.",
        evidence: &[],
        consumer: None,
    },
    CapabilityEntry {
        id: "lifecycle.single_node_residency",
        domain: CapabilityDomain::Lifecycle,
        status: SupportLevel::Stable,
        summary: "Single-node residency honors the configured eviction policy.",
        evidence: &["contract.eviction_changes_admission"],
        consumer: Some(ConsumerContract::EvictionChangesAdmission),
    },
    CapabilityEntry {
        id: "lifecycle.keep_alive",
        domain: CapabilityDomain::Lifecycle,
        status: SupportLevel::Preview,
        summary: "Keep-alive is visible in status but idle unload is not complete.",
        evidence: &[],
        consumer: None,
    },
    CapabilityEntry {
        id: "cluster.managed_replicas",
        domain: CapabilityDomain::Cluster,
        status: SupportLevel::Unsupported,
        summary: "Managed multi-node placement and dispatch are not available in PR 1.",
        evidence: &[],
        consumer: None,
    },
    CapabilityEntry {
        id: "policy.local_provider_governance",
        domain: CapabilityDomain::Policy,
        status: SupportLevel::Preview,
        summary: "Local providers remain behind the existing gateway policy path.",
        evidence: &[],
        consumer: None,
    },
    CapabilityEntry {
        id: "admin.model_status",
        domain: CapabilityDomain::Admin,
        status: SupportLevel::Preview,
        summary: "Read-only local model status is available.",
        evidence: &[],
        consumer: None,
    },
    CapabilityEntry {
        id: "admin.model_management",
        domain: CapabilityDomain::Admin,
        status: SupportLevel::Unsupported,
        summary: "Model mutation API and UI land in the operator-product PR.",
        evidence: &[],
        consumer: None,
    },
    CapabilityEntry {
        id: "platform.host_probe",
        domain: CapabilityDomain::Platform,
        status: SupportLevel::Preview,
        summary: "CPU, Apple, and NVIDIA probes require final platform certification.",
        evidence: &[],
        consumer: None,
    },
    CapabilityEntry {
        id: "lifecycle.priority_admission",
        domain: CapabilityDomain::Lifecycle,
        status: SupportLevel::Stable,
        summary: "Configured local concurrency changes request admission.",
        evidence: &["contract.priority_gate_changes_dispatch"],
        consumer: Some(ConsumerContract::PriorityGateChangesDispatch),
    },
];

const CONFIG_FIELDS: &[ConfigFieldCapability] = &[
    ConfigFieldCapability {
        path: "serve.models",
        status: SupportLevel::Stable,
        capability_id: "manifest.serve_model_declarations",
        consumer: Some(ConsumerContract::ServeModelsChangeDesiredDeployments),
    },
    ConfigFieldCapability {
        path: "serve.catalog_file",
        status: SupportLevel::Preview,
        capability_id: "manifest.catalog_v2",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.cache_dir",
        status: SupportLevel::Stable,
        capability_id: "artifact.cache_addressing",
        consumer: Some(ConsumerContract::CacheDirectoryChangesArtifactPath),
    },
    ConfigFieldCapability {
        path: "serve.cache_budget_gib",
        status: SupportLevel::ConfigOnly,
        capability_id: "artifact.cache_budget",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.eviction",
        status: SupportLevel::Stable,
        capability_id: "lifecycle.single_node_residency",
        consumer: Some(ConsumerContract::EvictionChangesAdmission),
    },
    ConfigFieldCapability {
        path: "serve.engines",
        status: SupportLevel::Preview,
        capability_id: "engine.managed_launch",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.max_concurrent_requests",
        status: SupportLevel::Stable,
        capability_id: "lifecycle.priority_admission",
        consumer: Some(ConsumerContract::PriorityGateChangesDispatch),
    },
    ConfigFieldCapability {
        path: "serve.queue_timeout_ms",
        status: SupportLevel::Preview,
        capability_id: "lifecycle.priority_admission",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].model",
        status: SupportLevel::Stable,
        capability_id: "manifest.serve_model_declarations",
        consumer: Some(ConsumerContract::ServeModelsChangeDesiredDeployments),
    },
    ConfigFieldCapability {
        path: "serve.models[].name",
        status: SupportLevel::Stable,
        capability_id: "manifest.serve_model_declarations",
        consumer: Some(ConsumerContract::ServeModelsChangeDesiredDeployments),
    },
    ConfigFieldCapability {
        path: "serve.models[].engine",
        status: SupportLevel::Preview,
        capability_id: "engine.managed_launch",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].keep_alive",
        status: SupportLevel::Preview,
        capability_id: "lifecycle.keep_alive",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].max_context",
        status: SupportLevel::Preview,
        capability_id: "engine.managed_launch",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].extra_args",
        status: SupportLevel::Preview,
        capability_id: "engine.managed_launch",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].kv_quant",
        status: SupportLevel::Preview,
        capability_id: "engine.managed_launch",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].speculative",
        status: SupportLevel::Preview,
        capability_id: "engine.managed_launch",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].chunked_prefill",
        status: SupportLevel::Preview,
        capability_id: "engine.managed_launch",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].lora_adapters",
        status: SupportLevel::Preview,
        capability_id: "engine.managed_launch",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].pinned",
        status: SupportLevel::Preview,
        capability_id: "lifecycle.single_node_residency",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].tool_call_parser",
        status: SupportLevel::Preview,
        capability_id: "engine.managed_launch",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].swap_space_gib",
        status: SupportLevel::Preview,
        capability_id: "engine.managed_launch",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].cpu_offload_gib",
        status: SupportLevel::Preview,
        capability_id: "engine.managed_launch",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].max_loras",
        status: SupportLevel::Preview,
        capability_id: "engine.managed_launch",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].gguf_file",
        status: SupportLevel::Preview,
        capability_id: "artifact.legacy_download",
        consumer: None,
    },
];

static REGISTRY: CapabilityRegistry = CapabilityRegistry {
    version: CAPABILITY_REGISTRY_VERSION,
    entries: CAPABILITIES,
    config_fields: CONFIG_FIELDS,
};

/// Return the process-wide immutable model-host capability registry.
pub fn capability_registry() -> &'static CapabilityRegistry {
    &REGISTRY
}
