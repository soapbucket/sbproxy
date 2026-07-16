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
    /// Catalog v2 resolves a pinned logical model to exact immutable bytes.
    CatalogV2SelectsExactArtifact,
    /// Managed cache misses enforce intent, pull policy, and network policy.
    VerifiedArtifactPolicyBlocksUnauthorizedNetwork,
    /// Cache collection preserves resident and pinned artifacts.
    CacheBudgetProtectsActiveArtifacts,
    /// An explicit cache directory changes artifact addressing.
    CacheDirectoryChangesArtifactPath,
    /// The eviction field changes admission under a full budget.
    EvictionChangesAdmission,
    /// The concurrency cap changes request scheduling.
    PriorityGateChangesDispatch,
    /// Canonical desired state commits atomically and failed preparation preserves it.
    CanonicalDesiredStateReconcilesAtomically,
    /// Managed engine kinds expose one typed capability contract.
    ManagedDriversExposeTypedCapabilities,
    /// Keep-alive starts only after the last active permit completes.
    KeepAliveStartsAfterLastPermit,
    /// Exact artifact removal honors configured, resident, and pinned protection.
    ExactRemovalProtectsReferences,
    /// Runtime status and admission failures serialize bounded stable labels.
    StatusReportsStableLifecycle,
    /// Managed replicas converge on one deterministic placement plan.
    ClusterPlacementConverges,
}

impl ConsumerContract {
    /// Stable evidence ID rendered into the capability matrix.
    pub const fn id(self) -> &'static str {
        match self {
            Self::ServeModelsChangeDesiredDeployments => {
                "contract.serve_models_change_desired_deployments"
            }
            Self::CatalogIdResolvesExactRepo => "contract.catalog_id_resolves_exact_repo",
            Self::CatalogV2SelectsExactArtifact => "contract.catalog_v2_selects_exact_artifact",
            Self::VerifiedArtifactPolicyBlocksUnauthorizedNetwork => {
                "contract.verified_artifact_policy_blocks_unauthorized_network"
            }
            Self::CacheBudgetProtectsActiveArtifacts => {
                "contract.cache_budget_protects_active_artifacts"
            }
            Self::CacheDirectoryChangesArtifactPath => {
                "contract.cache_directory_changes_artifact_path"
            }
            Self::EvictionChangesAdmission => "contract.eviction_changes_admission",
            Self::PriorityGateChangesDispatch => "contract.priority_gate_changes_dispatch",
            Self::CanonicalDesiredStateReconcilesAtomically => {
                "contract.canonical_desired_state_reconciles_atomically"
            }
            Self::ManagedDriversExposeTypedCapabilities => {
                "contract.managed_drivers_expose_typed_capabilities"
            }
            Self::KeepAliveStartsAfterLastPermit => "contract.keep_alive_starts_after_last_permit",
            Self::ExactRemovalProtectsReferences => "contract.exact_removal_protects_references",
            Self::StatusReportsStableLifecycle => "contract.status_reports_stable_lifecycle",
            Self::ClusterPlacementConverges => "contract.cluster_placement_converges",
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
            Self::CatalogV2SelectsExactArtifact => {
                use crate::{AcceleratorKind, EngineKind, ResolveArtifactRequest, WorkerProfile};

                let catalog = crate::Catalog::builtin();
                let resolved = catalog
                    .resolve_artifact(
                        &ResolveArtifactRequest {
                            model: "qwen2.5-0.5b-instruct".to_string(),
                            variant: Some("q4_k_m".to_string()),
                            engine: EngineChoice::Auto,
                            replicas: 1,
                            heterogeneous_variants: false,
                        },
                        &WorkerProfile {
                            accelerator: AcceleratorKind::Metal,
                            compute_capability: None,
                            memory_bytes: 24 * 1024 * 1024 * 1024,
                            engines: BTreeSet::from([EngineKind::LlamaCpp]),
                        },
                    )
                    .map_err(|error| error.to_string())?;
                if resolved.variant_id != "q4_k_m"
                    || resolved.revision != "9217f5db79a29953eb74d5343926648285ec7e67"
                    || resolved.files.len() != 1
                    || resolved.files[0].sha256
                        != "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db"
                {
                    return Err(format!(
                        "catalog v2 resolved unexpected artifact {resolved:?}"
                    ));
                }
                Ok(())
            }
            Self::VerifiedArtifactPolicyBlocksUnauthorizedNetwork => {
                use crate::{NetworkPolicy, PullIntent, PullPolicy};

                let digest = &"a".repeat(64);
                let manual = crate::artifact::enforce_cache_miss_policy(
                    digest,
                    PullIntent::Runtime,
                    NetworkPolicy::Allowed,
                    PullPolicy::Manual,
                    false,
                );
                if !matches!(
                    manual,
                    Err(crate::ArtifactError::ManualArtifactMissing { .. })
                ) {
                    return Err(format!("runtime manual policy returned {manual:?}"));
                }
                let offline = crate::artifact::enforce_cache_miss_policy(
                    digest,
                    PullIntent::Explicit,
                    NetworkPolicy::Denied,
                    PullPolicy::Manual,
                    false,
                );
                if !matches!(
                    offline,
                    Err(crate::ArtifactError::OfflineArtifactMissing { .. })
                ) {
                    return Err(format!("offline HTTP policy returned {offline:?}"));
                }
                crate::artifact::enforce_cache_miss_policy(
                    digest,
                    PullIntent::Explicit,
                    NetworkPolicy::Denied,
                    PullPolicy::Manual,
                    true,
                )
                .map_err(|error| format!("offline file source was rejected: {error}"))
            }
            Self::CacheBudgetProtectsActiveArtifacts => {
                let resident = "a".repeat(64);
                let pinned = "b".repeat(64);
                let protection = crate::CacheProtection {
                    resident: BTreeSet::from([resident.clone()]),
                    pinned: BTreeSet::from([pinned.clone()]),
                    ..crate::CacheProtection::default()
                };
                let resident_reason =
                    crate::artifact::explicit_protection_reason(&protection, &resident);
                let pinned_reason =
                    crate::artifact::explicit_protection_reason(&protection, &pinned);
                let other_reason =
                    crate::artifact::explicit_protection_reason(&protection, &"c".repeat(64));
                if resident_reason != Some("resident")
                    || pinned_reason != Some("pinned")
                    || other_reason.is_some()
                {
                    return Err(format!(
                        "protection reasons were {resident_reason:?}, {pinned_reason:?}, and {other_reason:?}"
                    ));
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
            Self::PriorityGateChangesDispatch => assert_priority_gate_changes_dispatch(),
            Self::CanonicalDesiredStateReconcilesAtomically => assert_canonical_reconciliation(),
            Self::ManagedDriversExposeTypedCapabilities => assert_managed_driver_capabilities(),
            Self::KeepAliveStartsAfterLastPermit => assert_keep_alive_lifecycle(),
            Self::ExactRemovalProtectsReferences => assert_exact_removal_protection(),
            Self::StatusReportsStableLifecycle => assert_stable_status_shape(),
            Self::ClusterPlacementConverges => assert_cluster_placement_converges(),
        }
    }
}

fn assert_cluster_placement_converges() -> Result<(), String> {
    use crate::node_snapshot::{NodeDeviceSnapshot, NodeEngineSnapshot, NodeHealthState, NodeRole};
    use crate::{
        ArtifactFormat, EngineAvailability, EngineKind, GpuVendor, PlacementNode, PlacementRequest,
    };
    use std::collections::BTreeMap;

    let node = |node_id: &str, zone: &str| PlacementNode {
        node_id: node_id.to_string(),
        roles: BTreeSet::from([NodeRole::Worker]),
        health: NodeHealthState::Ready,
        labels: BTreeMap::from([("zone".to_string(), zone.to_string())]),
        model_endpoint: Some(format!("https://{node_id}.internal:9443")),
        placement_weight: 64_000,
        engines: vec![NodeEngineSnapshot {
            engine: EngineKind::LlamaCpp,
            availability: EngineAvailability::Available,
            version: Some("fixture".to_string()),
            artifact_formats: vec![ArtifactFormat::Gguf],
            accelerators: BTreeSet::from([crate::AcceleratorKind::Cpu]),
            supports_container: false,
            supports_uv: false,
            reason_code: None,
        }],
        devices: vec![NodeDeviceSnapshot {
            index: 0,
            vendor: GpuVendor::Cpu,
            accelerator: Some(crate::AcceleratorKind::Cpu),
            name: "host RAM".to_string(),
            total_memory_bytes: 64_000_000_000,
            available_memory_bytes: 64_000_000_000,
            compute_capability: None,
            supports_fp8: false,
            compute_utilization_millis: None,
            memory_occupancy_millis: None,
        }],
        artifacts: Vec::new(),
    };
    let deployment: crate::ModelDeployment = serde_yaml::from_str(
        "model: qwen2.5-0.5b-instruct\nvariant: q4_k_m\nreplicas: 2\nspread_by: [zone]\nengine: llama_cpp\n",
    )
    .map_err(|error| error.to_string())?;
    let request = |nodes| PlacementRequest {
        deployment_id: "assistant".to_string(),
        deployment_generation: 7,
        deployment: deployment.clone(),
        nodes,
    };
    let first = crate::plan_placement(
        &crate::Catalog::builtin(),
        request(vec![node("worker-b", "b"), node("worker-a", "a")]),
    )
    .map_err(|error| error.to_string())?;
    let second = crate::plan_placement(
        &crate::Catalog::builtin(),
        request(vec![node("worker-a", "a"), node("worker-b", "b")]),
    )
    .map_err(|error| error.to_string())?;
    if first != second
        || first.unplaced_replicas != 0
        || first.assignments.len() != 2
        || first
            .assignments
            .iter()
            .map(|assignment| assignment.failure_domains.get("zone"))
            .collect::<BTreeSet<_>>()
            .len()
            != 2
    {
        return Err(format!(
            "cluster placement did not converge: {first:?} / {second:?}"
        ));
    }
    Ok(())
}

fn assert_managed_driver_capabilities() -> Result<(), String> {
    let llama = crate::LlamaCppDriver::default();
    let vllm = crate::VllmDriver::default();
    let llama_capabilities = crate::EngineDriver::capabilities(&llama);
    let vllm_capabilities = crate::EngineDriver::capabilities(&vllm);
    if llama_capabilities.artifact_formats != [crate::ArtifactFormat::Gguf]
        || llama_capabilities.supports_container
        || llama_capabilities.supports_uv
    {
        return Err(format!(
            "unexpected llama.cpp capabilities: {llama_capabilities:?}"
        ));
    }
    if !vllm_capabilities
        .artifact_formats
        .contains(&crate::ArtifactFormat::Safetensors)
        || !vllm_capabilities.supports_container
        || !vllm_capabilities.supports_uv
    {
        return Err(format!(
            "unexpected vLLM capabilities: {vllm_capabilities:?}"
        ));
    }
    Ok(())
}

struct CapabilityPreparer;

#[async_trait::async_trait]
impl crate::DeploymentPreparer for CapabilityPreparer {
    async fn prepare(
        &self,
        request: crate::DeploymentPrepareRequest,
    ) -> Result<std::sync::Arc<dyn crate::PreparedDeploymentRuntime>, crate::RuntimeManagerError>
    {
        if request.deployment_id == "broken" {
            return Err(crate::RuntimeManagerError::Prepare(
                "capability fixture rejected broken deployment".to_string(),
            ));
        }
        Ok(std::sync::Arc::new(CapabilityPreparedRuntime))
    }
}

struct CapabilityPreparedRuntime;

#[async_trait::async_trait]
impl crate::PreparedDeploymentRuntime for CapabilityPreparedRuntime {
    async fn memory_estimate(
        &self,
        _intent: crate::PullIntent,
    ) -> Result<crate::MemoryEstimate, crate::RuntimeManagerError> {
        Err(crate::RuntimeManagerError::Prepare(
            "capability fixture is cold only".to_string(),
        ))
    }

    async fn start(
        &self,
        _intent: crate::PullIntent,
    ) -> Result<crate::RunningEngine, crate::RuntimeManagerError> {
        Err(crate::RuntimeManagerError::Prepare(
            "capability fixture does not launch".to_string(),
        ))
    }

    async fn stop(&self, _grace: std::time::Duration) -> Result<(), crate::RuntimeManagerError> {
        Ok(())
    }

    async fn reset(&self) -> Result<Option<crate::OperationJob>, crate::RuntimeManagerError> {
        Ok(None)
    }
}

fn capability_desired_state(
    source_revision: &str,
    deployments: &[&str],
) -> Result<crate::RuntimeDesiredState, String> {
    let mut control = sbproxy_config::ModelHostControlConfig::default();
    for deployment in deployments {
        control.deployments.insert(
            (*deployment).to_string(),
            serde_yaml::from_str("model: qwen2.5-0.5b-instruct\nvariant: q4_k_m\nwarm: false\n")
                .map_err(|error| error.to_string())?,
        );
    }
    crate::compile_desired_state(
        crate::RuntimeDesiredInput {
            source_revision: source_revision.to_string(),
            canonical: Some(control),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &crate::Catalog::builtin(),
    )
    .map_err(|error| error.to_string())
}

fn assert_canonical_reconciliation() -> Result<(), String> {
    let catalog = crate::Catalog::builtin();
    let manager = crate::ModelRuntimeManager::new(
        catalog.catalog_revision.clone(),
        std::sync::Arc::new(CapabilityPreparer),
    )
    .map_err(|error| error.to_string())?;
    let first = futures::executor::block_on(
        manager.reconcile(capability_desired_state("first", &["coder"])?),
    )
    .map_err(|error| error.to_string())?;
    if first.plan.added != ["coder".to_string()] || manager.current_revision() != 1 {
        return Err(format!("unexpected first reconcile report: {first:?}"));
    }

    let revision = manager.current_revision();
    let error = futures::executor::block_on(
        manager.reconcile(capability_desired_state("broken", &["coder", "broken"])?),
    )
    .expect_err("broken fixture preparation must fail");
    if !matches!(error, crate::RuntimeManagerError::Prepare(_))
        || manager.current_revision() != revision
        || !manager.current_desired().deployments.contains_key("coder")
        || manager.current_desired().deployments.contains_key("broken")
    {
        return Err(format!(
            "failed reconciliation changed the last good state: {error}"
        ));
    }
    Ok(())
}

fn assert_keep_alive_lifecycle() -> Result<(), String> {
    let gate = crate::AdmissionGate::new(1, 1, std::time::Duration::from_secs(30))?;
    gate.mark_ready_idle();
    if !gate.is_idle_expired_at(
        tokio::time::Instant::now() + std::time::Duration::from_secs(31),
        std::time::Duration::from_secs(30),
    ) {
        return Err("ready idle deployment did not expire".to_string());
    }
    let permit = futures::executor::block_on(gate.admit(crate::PriorityClass::Standard))
        .map_err(|error| error.to_string())?;
    if gate.is_idle_expired_at(
        tokio::time::Instant::now() + std::time::Duration::from_secs(120),
        std::time::Duration::from_secs(30),
    ) {
        return Err("active permit was treated as idle".to_string());
    }
    drop(permit);
    if !gate.is_idle_expired_at(
        tokio::time::Instant::now() + std::time::Duration::from_secs(31),
        std::time::Duration::from_secs(30),
    ) {
        return Err("keep-alive did not restart after permit completion".to_string());
    }
    Ok(())
}

fn assert_priority_gate_changes_dispatch() -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    runtime.block_on(async {
        let gate = crate::AdmissionGate::new(1, 2, std::time::Duration::from_secs(30))?;
        let active = gate
            .admit(crate::PriorityClass::Standard)
            .await
            .map_err(|error| error.to_string())?;
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let batch_gate = gate.clone();
        let batch_sender = sender.clone();
        let batch = tokio::spawn(async move {
            let permit = batch_gate.admit(crate::PriorityClass::Batch).await?;
            let _ = batch_sender.send("batch");
            drop(permit);
            Ok::<_, crate::AdmissionRejection>(())
        });
        tokio::task::yield_now().await;
        let interactive_gate = gate.clone();
        let interactive = tokio::spawn(async move {
            let permit = interactive_gate
                .admit(crate::PriorityClass::Interactive)
                .await?;
            let _ = sender.send("interactive");
            drop(permit);
            Ok::<_, crate::AdmissionRejection>(())
        });
        tokio::task::yield_now().await;
        if gate.counts().queued != 2 {
            return Err(format!(
                "expected two queued requests, got {:?}",
                gate.counts()
            ));
        }
        drop(active);
        if receiver.recv().await != Some("interactive") || receiver.recv().await != Some("batch") {
            return Err("priority admission did not prefer interactive over batch".to_string());
        }
        batch
            .await
            .map_err(|error| error.to_string())?
            .map_err(|error| error.to_string())?;
        interactive
            .await
            .map_err(|error| error.to_string())?
            .map_err(|error| error.to_string())?;
        Ok(())
    })
}

fn assert_exact_removal_protection() -> Result<(), String> {
    for (reason, protection) in [
        (
            "configured",
            crate::CacheProtection {
                configured: BTreeSet::from(["a".repeat(64)]),
                ..crate::CacheProtection::default()
            },
        ),
        (
            "resident",
            crate::CacheProtection {
                resident: BTreeSet::from(["a".repeat(64)]),
                ..crate::CacheProtection::default()
            },
        ),
        (
            "pinned",
            crate::CacheProtection {
                pinned: BTreeSet::from(["a".repeat(64)]),
                ..crate::CacheProtection::default()
            },
        ),
    ] {
        let actual = crate::artifact::explicit_protection_reason(&protection, &"a".repeat(64));
        if actual != Some(reason) {
            return Err(format!("expected {reason} protection, got {actual:?}"));
        }
    }
    Ok(())
}

fn assert_stable_status_shape() -> Result<(), String> {
    let status = crate::DeploymentRuntimeStatus {
        deployment: "coder".to_string(),
        replica: 0,
        generation: 7,
        state: crate::DeploymentRuntimeState::Ready,
        active_requests: 1,
        queued_requests: 2,
        engine: Some(crate::EngineKind::LlamaCpp),
        driver_availability: Some(crate::EngineAvailability::Available),
        artifact_digest: Some("a".repeat(64)),
        selected_devices: vec![0],
        memory: None,
        port: Some(41000),
        reason_code: None,
        job_id: Some("01CAPABILITY".to_string()),
        last_error: None,
    };
    let json = serde_json::to_value(status).map_err(|error| error.to_string())?;
    if json["deployment"] != "coder" || json["state"] != "ready" || json["port"] != 41000 {
        return Err(format!("unexpected lifecycle status shape: {json}"));
    }
    let reasons = [
        crate::AdmissionReason::InsufficientCapacity,
        crate::AdmissionReason::QueueFull,
        crate::AdmissionReason::QueueTimeout,
        crate::AdmissionReason::EngineUnhealthy,
        crate::AdmissionReason::CrashLoop,
        crate::AdmissionReason::Draining,
    ];
    if reasons.iter().any(|reason| reason.as_str().contains(' ')) {
        return Err("admission reason codes must be bounded snake case".to_string());
    }
    Ok(())
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
            "# Model-host capability matrix\n*Last modified: 2026-07-13*\n\n*Generated from the executable registry; do not hand-edit.*\n\n",
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
        "serve.models[].variant" => config.models.iter().any(|entry| entry.variant.is_some()),
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
        id: "manifest.canonical_desired_state",
        domain: CapabilityDomain::Manifest,
        status: SupportLevel::Stable,
        summary: "Canonical proxy.model_host deployments compile into one atomic runtime revision.",
        evidence: &[
            "contract.canonical_desired_state_reconciles_atomically",
            "test.runtime_reconcile",
            "test.model_host_reload",
        ],
        consumer: Some(ConsumerContract::CanonicalDesiredStateReconcilesAtomically),
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
        status: SupportLevel::Stable,
        summary: "Catalog v2 resolves pinned logical models to exact immutable artifacts.",
        evidence: &[
            "contract.catalog_v2_selects_exact_artifact",
            "test.catalog_v2",
        ],
        consumer: Some(ConsumerContract::CatalogV2SelectsExactArtifact),
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
        id: "artifact.verified_acquisition",
        domain: CapabilityDomain::Artifact,
        status: SupportLevel::Stable,
        summary: "Managed artifacts are exact, atomic, resumable, and policy enforced.",
        evidence: &[
            "contract.verified_artifact_policy_blocks_unauthorized_network",
            "test.artifact_manager",
            "test.artifact_policy",
        ],
        consumer: Some(ConsumerContract::VerifiedArtifactPolicyBlocksUnauthorizedNetwork),
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
        status: SupportLevel::Stable,
        summary: "Cache collection enforces LRU budgets without deleting protected artifacts.",
        evidence: &[
            "contract.cache_budget_protects_active_artifacts",
            "test.artifact_gc",
        ],
        consumer: Some(ConsumerContract::CacheBudgetProtectsActiveArtifacts),
    },
    CapabilityEntry {
        id: "artifact.exact_removal",
        domain: CapabilityDomain::Artifact,
        status: SupportLevel::Stable,
        summary: "Exact cache removal is idempotent and rejects configured, resident, pinned, locked, leased, or active artifacts.",
        evidence: &[
            "contract.exact_removal_protects_references",
            "test.artifact_manager",
            "test.models_lifecycle_cli",
        ],
        consumer: Some(ConsumerContract::ExactRemovalProtectsReferences),
    },
    CapabilityEntry {
        id: "engine.typed_managed_drivers",
        domain: CapabilityDomain::Engine,
        status: SupportLevel::Stable,
        summary: "Managed engines share typed detect, provision, launch, health, and shutdown contracts over verified local artifacts.",
        evidence: &[
            "contract.managed_drivers_expose_typed_capabilities",
            "test.engine_drivers",
        ],
        consumer: Some(ConsumerContract::ManagedDriversExposeTypedCapabilities),
    },
    CapabilityEntry {
        id: "engine.llama_cpp_managed",
        domain: CapabilityDomain::Engine,
        status: SupportLevel::Preview,
        summary: "Managed llama.cpp supports digest-verified binary acquisition and Linux CUDA source builds; Apple Metal is certified while live CUDA remains deferred.",
        evidence: &[
            "test.engine_drivers",
            "test.cuda_build",
            "cert.apple_metal.2026-07-11",
        ],
        consumer: None,
    },
    CapabilityEntry {
        id: "engine.vllm_uv",
        domain: CapabilityDomain::Engine,
        status: SupportLevel::Preview,
        summary: "Managed vLLM can use a pinned uv environment; live NVIDIA certification remains deferred.",
        evidence: &["test.engine_drivers"],
        consumer: None,
    },
    CapabilityEntry {
        id: "engine.vllm_container",
        domain: CapabilityDomain::Engine,
        status: SupportLevel::Preview,
        summary: "Digest-pinned private container plans use read-only artifacts and selected devices; live NVIDIA certification remains deferred.",
        evidence: &["test.engine_drivers"],
        consumer: None,
    },
    CapabilityEntry {
        id: "lifecycle.atomic_reconciliation",
        domain: CapabilityDomain::Lifecycle,
        status: SupportLevel::Stable,
        summary: "Startup, file reload, SIGHUP, and admin reload prepare a complete revision before commit; pre-commit failures do not publish the candidate.",
        evidence: &[
            "contract.canonical_desired_state_reconciles_atomically",
            "test.runtime_reconcile",
            "test.model_host_reload",
        ],
        consumer: Some(ConsumerContract::CanonicalDesiredStateReconcilesAtomically),
    },
    CapabilityEntry {
        id: "lifecycle.single_node_residency",
        domain: CapabilityDomain::Lifecycle,
        status: SupportLevel::Stable,
        summary: "Single-node residency honors the global resident limit and configured eviction policy across devices.",
        evidence: &["contract.eviction_changes_admission"],
        consumer: Some(ConsumerContract::EvictionChangesAdmission),
    },
    CapabilityEntry {
        id: "lifecycle.keep_alive",
        domain: CapabilityDomain::Lifecycle,
        status: SupportLevel::Stable,
        summary: "Keep-alive starts after the last completed request and never expires active or queued work.",
        evidence: &[
            "contract.keep_alive_starts_after_last_permit",
            "test.local_admission",
            "test.runtime_reconcile",
        ],
        consumer: Some(ConsumerContract::KeepAliveStartsAfterLastPermit),
    },
    CapabilityEntry {
        id: "cluster.managed_replicas",
        domain: CapabilityDomain::Cluster,
        status: SupportLevel::Stable,
        summary: "Managed replicas use versioned worker snapshots, deterministic placement and spread, readiness-gated rollout, and authenticated cluster health status.",
        evidence: &[
            "contract.cluster_placement_converges",
            "test.placement",
            "test.runtime_reconcile",
            "test.cluster_control_plane",
            "test.model_cluster_control",
        ],
        consumer: Some(ConsumerContract::ClusterPlacementConverges),
    },
    CapabilityEntry {
        id: "cluster.remote_dispatch",
        domain: CapabilityDomain::Cluster,
        status: SupportLevel::Preview,
        summary: "Authenticated HTTP/2 local and peer dispatch, coordinated cold starts, streaming cancellation, and pre-output failover have local test coverage; a dedicated executable consumer contract and live production certification remain incomplete.",
        evidence: &[
            "test.model_plane_envelope",
            "test.model_plane_transport",
            "test.managed_replica_routing",
            "test.managed_replica_dispatch",
            "test.model_cluster_dispatch",
        ],
        consumer: None,
    },
    CapabilityEntry {
        id: "policy.local_provider_governance",
        domain: CapabilityDomain::Policy,
        status: SupportLevel::Preview,
        summary: "Managed routes preserve gateway provider and model policy, expose topology-free logical discovery, and emit bounded route metadata; strict distributed limits and full key introspection remain deferred.",
        evidence: &[
            "test.managed_replica_dispatch",
            "test.admin_model_host",
            "test.model_cluster_dispatch",
        ],
        consumer: None,
    },
    CapabilityEntry {
        id: "admin.model_status",
        domain: CapabilityDomain::Admin,
        status: SupportLevel::Stable,
        summary: "Authenticated admin status, load, stop, drain, and reset adapt the shared runtime lifecycle.",
        evidence: &[
            "contract.status_reports_stable_lifecycle",
            "test.models_lifecycle_cli",
            "test.admin_model_host",
        ],
        consumer: Some(ConsumerContract::StatusReportsStableLifecycle),
    },
    CapabilityEntry {
        id: "admin.model_management",
        domain: CapabilityDomain::Admin,
        status: SupportLevel::Preview,
        summary: "Backend E2E covers authenticated full-map revision conflicts and restart persistence; UI unit and component contracts cover mode-aware catalog evidence, lifecycle state, conflict recovery, removal guards, and cluster authority proof.",
        evidence: &[
            "contract.canonical_desired_state_reconciles_atomically",
            "test.admin_model_management",
            "test.ui_model_management",
        ],
        consumer: None,
    },
    CapabilityEntry {
        id: "platform.apple_metal",
        domain: CapabilityDomain::Platform,
        status: SupportLevel::Stable,
        summary: "Apple Metal completed a real managed gateway completion, status, stop, cache-reuse, and Ctrl-C shutdown gate on Apple M4 Max.",
        evidence: &[
            "contract.catalog_v2_selects_exact_artifact",
            "test.engine_drivers",
            "cert.apple_metal.2026-07-11",
        ],
        consumer: Some(ConsumerContract::CatalogV2SelectsExactArtifact),
    },
    CapabilityEntry {
        id: "platform.nvidia_cuda",
        domain: CapabilityDomain::Platform,
        status: SupportLevel::Preview,
        summary: "NVIDIA discovery, vLLM, and CUDA llama.cpp have deterministic coverage; live GCP certification is reserved for the final PR group.",
        evidence: &["test.cuda_build", "test.local_admission"],
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
    CapabilityEntry {
        id: "lifecycle.model_cli",
        domain: CapabilityDomain::Lifecycle,
        status: SupportLevel::Stable,
        summary: "Pull, list, show, remove, process status, and stop commands use versioned JSON and shared artifact or runtime contracts.",
        evidence: &[
            "contract.exact_removal_protects_references",
            "test.models_lifecycle_cli",
        ],
        consumer: Some(ConsumerContract::ExactRemovalProtectsReferences),
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
        capability_id: "engine.typed_managed_drivers",
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
        status: SupportLevel::Stable,
        capability_id: "lifecycle.priority_admission",
        consumer: Some(ConsumerContract::PriorityGateChangesDispatch),
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
        path: "serve.models[].variant",
        status: SupportLevel::Stable,
        capability_id: "manifest.catalog_v2",
        consumer: Some(ConsumerContract::CatalogV2SelectsExactArtifact),
    },
    ConfigFieldCapability {
        path: "serve.models[].engine",
        status: SupportLevel::Preview,
        capability_id: "engine.typed_managed_drivers",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].keep_alive",
        status: SupportLevel::Stable,
        capability_id: "lifecycle.keep_alive",
        consumer: Some(ConsumerContract::KeepAliveStartsAfterLastPermit),
    },
    ConfigFieldCapability {
        path: "serve.models[].max_context",
        status: SupportLevel::Preview,
        capability_id: "engine.typed_managed_drivers",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].extra_args",
        status: SupportLevel::Preview,
        capability_id: "engine.typed_managed_drivers",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].kv_quant",
        status: SupportLevel::Preview,
        capability_id: "engine.typed_managed_drivers",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].speculative",
        status: SupportLevel::Unsupported,
        capability_id: "engine.typed_managed_drivers",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].chunked_prefill",
        status: SupportLevel::Preview,
        capability_id: "engine.typed_managed_drivers",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].lora_adapters",
        status: SupportLevel::Unsupported,
        capability_id: "engine.typed_managed_drivers",
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
        capability_id: "engine.typed_managed_drivers",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].swap_space_gib",
        status: SupportLevel::Preview,
        capability_id: "engine.typed_managed_drivers",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].cpu_offload_gib",
        status: SupportLevel::Preview,
        capability_id: "engine.typed_managed_drivers",
        consumer: None,
    },
    ConfigFieldCapability {
        path: "serve.models[].max_loras",
        status: SupportLevel::Unsupported,
        capability_id: "engine.typed_managed_drivers",
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
