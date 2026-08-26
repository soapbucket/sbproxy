use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::agent_orchestration::FsmState;
use crate::evaluation::{Dataset, DatasetEntry};
use crate::prompt_versioning::WeightedPromptVersion;
use sbproxy_security::egress::{EgressAuthorizer, EgressPurpose};
use sbproxy_vault::SecretString;

/// Hard ceiling used for scope components before runtime-specific limits apply.
pub(crate) const MAX_SCOPE_COMPONENT_BYTES: usize = 128;

/// Tenant and compiled-origin boundary for every toolkit operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ToolkitScope {
    /// Stable compiled-origin identifier.
    pub origin_id: String,
    /// Stable tenant identifier.
    pub tenant_id: String,
}

impl ToolkitScope {
    /// Construct a non-empty, bounded scope.
    pub fn new(
        origin_id: impl Into<String>,
        tenant_id: impl Into<String>,
    ) -> Result<Self, ToolkitError> {
        let scope = Self {
            origin_id: origin_id.into(),
            tenant_id: tenant_id.into(),
        };
        for (field, value) in [
            ("scope.origin_id", scope.origin_id.as_str()),
            ("scope.tenant_id", scope.tenant_id.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(ToolkitError::InvalidConfiguration { field });
            }
            if value.len() > MAX_SCOPE_COMPONENT_BYTES {
                return Err(ToolkitError::LimitExceeded {
                    resource: field,
                    limit: MAX_SCOPE_COMPONENT_BYTES,
                    observed: value.len(),
                });
            }
        }
        Ok(scope)
    }
}

/// Bounded resource policy for one immutable runtime generation.
#[derive(Debug, Clone)]
pub struct AiToolkitLimits {
    /// Maximum configured agents.
    pub max_agents: usize,
    /// Maximum capabilities advertised by one agent.
    pub max_capabilities_per_agent: usize,
    /// Maximum configured workflows.
    pub max_workflows: usize,
    /// Maximum distinct dataset names per scope.
    pub max_datasets: usize,
    /// Maximum immutable versions of one dataset.
    pub max_dataset_versions: usize,
    /// Maximum immutable dataset versions retained across all scopes (hard maximum 16,384).
    pub max_dataset_versions_total: usize,
    /// Maximum entries in one dataset version.
    pub max_dataset_entries: usize,
    /// Maximum serialized dataset-entry bytes retained across all scopes (hard maximum 512 MiB).
    pub max_dataset_bytes_total: usize,
    /// Maximum weighted prompt rollouts.
    pub max_rollouts: usize,
    /// Maximum versions in one rollout.
    pub max_rollout_versions: usize,
    /// Maximum redacted operation and experiment summaries retained.
    pub max_retained_operations: usize,
    /// Maximum serialized request or evaluation response bytes.
    pub max_request_bytes: usize,
    /// Maximum agent response bytes.
    pub max_response_bytes: usize,
    /// Maximum identifier bytes.
    pub max_identifier_bytes: usize,
    /// Maximum description bytes.
    pub max_description_bytes: usize,
    /// Maximum serialized JSON Schema bytes.
    pub max_schema_bytes: usize,
    /// Maximum shared-secret bytes.
    pub max_secret_bytes: usize,
    /// Maximum cases in one evaluation.
    pub max_evaluation_cases: usize,
    /// Maximum custom metrics in one evaluation.
    pub max_metrics: usize,
    /// Maximum judge criteria in one evaluation.
    pub max_judge_criteria: usize,
    /// Maximum concurrent live agent workflows.
    pub agent_concurrency: usize,
    /// Maximum concurrent offline evaluations.
    pub evaluation_concurrency: usize,
    /// Workflow deadline used when an input leaves it unspecified.
    pub default_workflow_timeout_ms: u64,
    /// Maximum accepted workflow deadline.
    pub max_workflow_timeout_ms: u64,
}

impl Default for AiToolkitLimits {
    fn default() -> Self {
        Self {
            max_agents: 64,
            max_capabilities_per_agent: 32,
            max_workflows: 64,
            max_datasets: 32,
            max_dataset_versions: 8,
            max_dataset_versions_total: 256,
            max_dataset_entries: 1_000,
            max_dataset_bytes_total: 64 * 1024 * 1024,
            max_rollouts: 128,
            max_rollout_versions: 16,
            max_retained_operations: 256,
            max_request_bytes: 256 * 1024,
            max_response_bytes: 1024 * 1024,
            max_identifier_bytes: 128,
            max_description_bytes: 512,
            max_schema_bytes: 64 * 1024,
            max_secret_bytes: 256,
            max_evaluation_cases: 1_000,
            max_metrics: 16,
            max_judge_criteria: 16,
            agent_concurrency: 8,
            evaluation_concurrency: 2,
            default_workflow_timeout_ms: 10_000,
            max_workflow_timeout_ms: 60_000,
        }
    }
}

/// Exact-generation egress policy used by agent orchestration.
#[derive(Debug, Clone)]
pub struct AgentEgressInput {
    /// Compiled authorizer from the same config generation as the runtime.
    pub authorizer: EgressAuthorizer,
    /// Must be [`EgressPurpose::AgentOrchestration`].
    pub purpose: EgressPurpose,
}

/// One governed capability advertised by an agent.
#[derive(Debug, Clone)]
pub struct ToolkitCapabilityInput {
    /// Stable capability name used by workflow actions.
    pub name: String,
    /// Bounded operator-facing description.
    pub description: String,
    /// JSON Schema enforced before an invocation.
    pub input_schema: Value,
    /// JSON Schema enforced after an invocation.
    pub output_schema: Value,
}

/// One configured agent endpoint and its protected shared secret.
#[derive(Debug, Clone)]
pub struct ToolkitAgentInput {
    /// Tenant/origin scope that owns the agent.
    pub scope: ToolkitScope,
    /// Stable agent identifier.
    pub id: String,
    /// Governed invocation endpoint.
    pub endpoint: String,
    /// Resolved secret protected from Debug/Display and zeroized on drop.
    pub shared_secret: SecretString,
    /// Advertised capabilities.
    pub capabilities: Vec<ToolkitCapabilityInput>,
}

/// One bounded workflow definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolkitWorkflowInput {
    /// Tenant/origin scope that owns the workflow.
    pub scope: ToolkitScope,
    /// Stable workflow name.
    pub name: String,
    /// Initial state name.
    pub initial_state: String,
    /// FSM graph.
    pub states: Vec<FsmState>,
    /// Maximum transitions.
    pub max_steps: usize,
    /// Whole-workflow deadline in milliseconds.
    pub timeout_ms: u64,
}

/// Request to validate a workflow against configured scoped capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowValidationRequest {
    /// Authenticated scope performing validation.
    pub scope: ToolkitScope,
    /// Candidate workflow definition.
    pub workflow: ToolkitWorkflowInput,
}

/// Successful workflow validation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowValidationResult {
    /// Always true on success; invalid workflows return [`ToolkitError`].
    pub valid: bool,
}

/// One immutable dataset version seeded at publication.
#[derive(Debug, Clone)]
pub struct ToolkitDatasetInput {
    /// Tenant/origin scope that owns the dataset.
    pub scope: ToolkitScope,
    /// Exact immutable dataset version.
    pub dataset: Dataset,
}

/// One stable weighted prompt rollout.
#[derive(Debug, Clone)]
pub struct PromptRolloutInput {
    /// Tenant/origin scope that owns the rollout.
    pub scope: ToolkitScope,
    /// Rollout name, equal to every version's name.
    pub name: String,
    /// Stable, operator-controlled cohort salt.
    pub salt: String,
    /// Mature weighted prompt versions.
    pub versions: Vec<WeightedPromptVersion>,
}

/// All materialized inputs for one immutable runtime generation.
#[derive(Clone)]
pub struct AiToolkitConfigInput {
    /// Runtime bounds.
    pub limits: AiToolkitLimits,
    /// Immutable origin/tenant scopes eligible for dynamic dataset registration.
    pub allowed_scopes: Vec<ToolkitScope>,
    /// Governed agents.
    pub agents: Vec<ToolkitAgentInput>,
    /// Agent workflows.
    pub workflows: Vec<ToolkitWorkflowInput>,
    /// Initial immutable dataset versions.
    pub datasets: Vec<ToolkitDatasetInput>,
    /// Weighted prompt rollouts.
    pub prompt_rollouts: Vec<PromptRolloutInput>,
    /// Exact-generation egress authorizer, required when agents exist.
    pub agent_egress: Option<AgentEgressInput>,
}

impl Default for AiToolkitConfigInput {
    fn default() -> Self {
        Self {
            limits: AiToolkitLimits::default(),
            allowed_scopes: Vec::new(),
            agents: Vec::new(),
            workflows: Vec::new(),
            datasets: Vec::new(),
            prompt_rollouts: Vec::new(),
            agent_egress: None,
        }
    }
}

/// Scoped agent discovery request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDiscoveryRequest {
    /// Scope visible to the authenticated caller.
    pub scope: ToolkitScope,
    /// Optional exact capability filter.
    pub capability: Option<String>,
}

/// Redacted agent summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSummary {
    /// Stable agent identifier.
    pub id: String,
    /// Sorted capability names.
    pub capabilities: Vec<String>,
}

/// Result of scoped discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentDiscoveryResult {
    /// Sorted matching agents.
    pub agents: Vec<AgentSummary>,
}

/// Request to execute one configured workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRunRequest {
    /// Scope that owns the workflow and agents.
    pub scope: ToolkitScope,
    /// Exact workflow name.
    pub workflow: String,
    /// Initial JSON payload.
    pub input: Value,
}

/// Redacted routing metadata for one completed workflow hop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowStepSummary {
    /// FSM state invoked.
    pub state: String,
    /// Capability invoked.
    pub capability: String,
    /// Outcome label returned by the agent.
    pub outcome: String,
    /// Agent chosen deterministically for the capability.
    pub agent_id: String,
}

/// Workflow execution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRunResult {
    /// Workflow name.
    pub workflow: String,
    /// Whether the FSM reached a terminal outcome.
    pub completed: bool,
    /// Last state that ran.
    pub final_state: String,
    /// Last validated agent output.
    pub output: Value,
    /// Bounded hop summaries.
    pub steps: Vec<WorkflowStepSummary>,
}

/// Request to register one immutable dataset version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetRegistrationRequest {
    /// Scope that owns the dataset.
    pub scope: ToolkitScope,
    /// Dataset name.
    pub name: String,
    /// Exact non-zero version.
    pub version: u32,
    /// Bounded entries.
    pub entries: Vec<DatasetEntry>,
}

/// Dataset registration acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetRegistrationResult {
    /// Dataset name.
    pub name: String,
    /// Registered version.
    pub version: u32,
    /// Number of entries registered.
    pub entries: usize,
}

/// Exact dataset identity used by evaluations and summaries.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DatasetRef {
    /// Dataset name.
    pub name: String,
    /// Immutable version.
    pub version: u32,
}

/// Recorded judge outputs supplied to an offline evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineJudgeInput {
    /// Judge model metadata; no network call is made.
    pub judge_model: String,
    /// Exact criteria expected in every recorded judge response.
    pub criteria: Vec<String>,
    /// One already-recorded judge JSON response per case.
    pub responses: Vec<String>,
}

/// Supported offline custom metric specifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MetricSpec {
    /// Regular expression match.
    Regex {
        /// Rust regular expression.
        pattern: String,
    },
    /// JSON response validation.
    JsonSchema {
        /// JSON Schema document.
        schema: Value,
    },
    /// Inclusive response byte range.
    LengthRange {
        /// Minimum bytes.
        #[serde(alias = "min_bytes")]
        min: usize,
        /// Maximum bytes.
        #[serde(alias = "max_bytes")]
        max: usize,
    },
    /// Response must contain every keyword.
    ContainsKeywords {
        /// Required literal keywords.
        keywords: Vec<String>,
    },
}

/// Request for an entirely offline evaluation of recorded responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationRunRequest {
    /// Scope that owns the dataset and result.
    pub scope: ToolkitScope,
    /// Unique experiment run identifier.
    pub experiment_id: String,
    /// Human-readable experiment name.
    pub experiment_name: String,
    /// Exact dataset version; latest-version fallback is forbidden.
    pub dataset: DatasetRef,
    /// Candidate model metadata.
    pub model: String,
    /// Candidate prompt version metadata.
    pub prompt_version: Option<String>,
    /// Bounded metadata retained only for existing experiment compatibility.
    pub parameters: Value,
    /// One already-recorded candidate response per dataset entry.
    pub responses: Vec<String>,
    /// Optional already-recorded judge outputs.
    pub judge: Option<OfflineJudgeInput>,
    /// Custom metrics applied to every candidate response.
    pub metrics: Vec<MetricSpec>,
}

/// Bounded aggregate evaluation result; never contains raw case content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationRunResult {
    /// Unique experiment identifier.
    pub experiment_id: String,
    /// Human-readable experiment name.
    pub experiment_name: String,
    /// Exact evaluated dataset.
    pub dataset: DatasetRef,
    /// Candidate model metadata.
    pub model: String,
    /// Candidate prompt version metadata.
    pub prompt_version: Option<String>,
    /// Number of evaluated cases.
    pub cases: usize,
    /// Exact-output match rate over entries carrying an expected output.
    pub expected_match_rate: Option<f64>,
    /// Mean pass rate across every case and configured metric.
    pub metric_pass_rate: f64,
    /// Mean composite judge score, if judge results were supplied.
    pub judge_score: Option<f64>,
    /// Mean score by exact criterion, with bounded keys.
    pub criteria_scores: BTreeMap<String, f64>,
    /// UTC timestamp recorded by the runtime.
    pub recorded_at: String,
}

/// Stable weighted prompt selection request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptSelectionRequest {
    /// Scope that owns the rollout.
    pub scope: ToolkitScope,
    /// Exact rollout name.
    pub name: String,
    /// Stable caller cohort key; never retained or emitted.
    pub cohort: String,
}

/// Selected mature prompt version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptSelectionResult {
    /// Prompt name.
    pub name: String,
    /// Selected immutable version.
    pub version: u32,
    /// Selected prompt content.
    pub content: String,
    /// Configured relative weight.
    pub weight: f64,
    /// Length-framed scope/rollout/cohort digest for bounded typed events.
    pub cohort_digest: String,
}

/// Scoped redacted snapshot request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolkitSnapshotRequest {
    /// Scope visible to the authenticated caller.
    pub scope: ToolkitScope,
    /// Optional row limit, clamped to retained bounds.
    pub limit: Option<usize>,
}

/// Redacted workflow inventory row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowSummary {
    /// Workflow name.
    pub name: String,
    /// Maximum steps.
    pub max_steps: usize,
    /// Whole-run deadline in milliseconds.
    pub timeout_ms: u64,
}

/// Redacted dataset inventory row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetSummary {
    /// Dataset name.
    pub name: String,
    /// Exact version.
    pub version: u32,
    /// Entry count.
    pub entries: usize,
}

/// Redacted rollout version row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutVersionSummary {
    /// Immutable version.
    pub version: u32,
    /// Relative weight.
    pub weight: f64,
}

/// Redacted rollout inventory row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutSummary {
    /// Rollout name.
    pub name: String,
    /// Version and weight only; content and salt are excluded.
    pub versions: Vec<RolloutVersionSummary>,
}

/// Redacted operation audit row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolkitOperationSummary {
    /// Closed operation label.
    pub operation: String,
    /// Closed outcome label.
    pub outcome: String,
    /// UTC timestamp.
    pub recorded_at: String,
}

/// Authenticated, scope-only, bounded runtime snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolkitSnapshot {
    /// Scope represented by the snapshot.
    pub scope: ToolkitScope,
    /// Redacted agents.
    pub agents: Vec<AgentSummary>,
    /// Workflow inventory.
    pub workflows: Vec<WorkflowSummary>,
    /// Exact dataset versions.
    pub datasets: Vec<DatasetSummary>,
    /// Rollout versions and weights only.
    pub rollouts: Vec<RolloutSummary>,
    /// Aggregate experiment summaries only.
    pub experiments: Vec<EvaluationRunResult>,
    /// Closed operation/outcome rows only.
    pub operations: Vec<ToolkitOperationSummary>,
    /// True when any retained collection exceeded the requested limit.
    pub truncated: bool,
}

/// Closed, content-safe failure contract for toolkit operations.
#[derive(Debug, Error)]
pub enum ToolkitError {
    /// A fixed resource ceiling was exceeded.
    #[error("AI toolkit {resource} limit exceeded: limit {limit}, observed {observed}")]
    LimitExceeded {
        /// Closed resource label.
        resource: &'static str,
        /// Configured ceiling.
        limit: usize,
        /// Observed count or bytes.
        observed: usize,
    },
    /// A structural configuration field is invalid.
    #[error("invalid AI toolkit configuration field: {field}")]
    InvalidConfiguration {
        /// Closed field label; never field content.
        field: &'static str,
    },
    /// A JSON Schema could not be compiled.
    #[error("invalid AI toolkit JSON Schema at {boundary}")]
    InvalidSchema {
        /// Closed schema boundary label.
        boundary: &'static str,
    },
    /// An immutable key was already published.
    #[error("AI toolkit {resource} already exists")]
    Duplicate {
        /// Closed resource label.
        resource: &'static str,
    },
    /// A scoped resource was not found.
    #[error("AI toolkit {resource} was not found")]
    NotFound {
        /// Closed resource label.
        resource: &'static str,
    },
    /// A fail-fast concurrency permit was unavailable.
    #[error("AI toolkit {operation} is at its concurrency limit")]
    Busy {
        /// Closed operation label.
        operation: &'static str,
    },
    /// A whole-operation deadline elapsed.
    #[error("AI toolkit {operation} deadline elapsed")]
    Deadline {
        /// Closed operation label.
        operation: &'static str,
    },
    /// Governed egress failed with a closed reason label.
    #[error("AI toolkit governed egress failed: {reason}")]
    GovernedEgress {
        /// Closed [`sbproxy_security`] reason label.
        reason: &'static str,
    },
    /// The agent returned a non-success status; its body is discarded.
    #[error("AI toolkit agent rejected the request with status {status}")]
    AgentRejected {
        /// Bounded HTTP status code.
        status: u16,
    },
    /// An agent wire response was malformed.
    #[error("AI toolkit agent response was invalid")]
    InvalidAgentResponse,
    /// A payload failed a compiled schema at a closed boundary.
    #[error("AI toolkit payload failed schema validation at {boundary}")]
    SchemaViolation {
        /// Closed input/output label.
        boundary: &'static str,
    },
    /// An offline judge response violated its closed contract.
    #[error("AI toolkit offline judge response was invalid")]
    InvalidJudgeResponse,
    /// A bounded JSON payload could not be serialized.
    #[error("AI toolkit JSON serialization failed")]
    Serialization,
}
