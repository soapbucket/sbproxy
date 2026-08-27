use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use jsonschema::JSONSchema;
use parking_lot::Mutex;
use tokio::sync::Semaphore;

use crate::agent_orchestration::{AgentCapability, AgentRegistry, FsmWorkflow};
use crate::ai_metrics::{record_ai_toolkit_operation, AiToolkitCapability, AiToolkitOutcome};
use crate::evaluation::Dataset;
use crate::prompt_versioning::WeightedPromptStore;
use sbproxy_vault::SecretString;

use super::validation::{
    checked_bounded_add, compile_schema, ensure_count, ensure_serialized, validate_config,
    validate_identifier, validate_scope,
};
use super::{
    AgentDiscoveryRequest, AgentDiscoveryResult, AgentEgressInput, AgentSummary,
    AiToolkitConfigInput, AiToolkitLimits, DatasetRegistrationRequest, DatasetRegistrationResult,
    EvaluationRunResult, RolloutSummary, RolloutVersionSummary, ToolkitError,
    ToolkitOperationSummary, ToolkitScope, WorkflowSummary,
};

pub(crate) fn metric_outcome<T>(result: &Result<T, ToolkitError>) -> AiToolkitOutcome {
    match result {
        Ok(_) => AiToolkitOutcome::Success,
        Err(error) => error_metric_outcome(error),
    }
}

/// The single authoritative mapping from a toolkit error to its closed
/// metric outcome. The admin layer's metric and typed-event streams both
/// route through this, so the two label streams cannot drift apart.
pub fn error_metric_outcome(error: &ToolkitError) -> AiToolkitOutcome {
    match error {
        ToolkitError::NotFound { .. } => AiToolkitOutcome::NotFound,
        ToolkitError::Deadline { .. } => AiToolkitOutcome::Timeout,
        ToolkitError::Busy { .. } => AiToolkitOutcome::Busy,
        ToolkitError::GovernedEgress {
            reason: "egress_denied",
        } => AiToolkitOutcome::EgressRefused,
        ToolkitError::GovernedEgress {
            reason: "response_too_large",
        } => AiToolkitOutcome::ResponseTooLarge,
        // The agent-fault family. The admin surface already answers 502
        // `agent_operation_failed` for every one of these, so a more
        // specific outcome is provably safe to expose; folding them into
        // `Internal` pages the proxy team for a customer's broken agent
        // and hides the 502 rate from the metric and the SIEM feed alike.
        ToolkitError::GovernedEgress {
            reason: "transport_error" | "client_build_failed" | "not_replayable",
        }
        | ToolkitError::AgentRejected { .. } => AiToolkitOutcome::AgentFailed,
        ToolkitError::LimitExceeded { resource, .. }
            if resource.contains("response") || resource.contains("output") =>
        {
            AiToolkitOutcome::ResponseTooLarge
        }
        ToolkitError::LimitExceeded { resource, .. }
            if resource.contains("request") || resource.contains("input") =>
        {
            AiToolkitOutcome::BodyTooLarge
        }
        ToolkitError::LimitExceeded { .. } => AiToolkitOutcome::Invalid,
        ToolkitError::InvalidConfiguration { .. }
        | ToolkitError::InvalidSchema { .. }
        | ToolkitError::Duplicate { .. }
        | ToolkitError::SchemaViolation { .. }
        | ToolkitError::InvalidAgentResponse
        | ToolkitError::InvalidJudgeResponse => AiToolkitOutcome::Invalid,
        _ => AiToolkitOutcome::Internal,
    }
}

pub(crate) struct CompiledCapability {
    pub(crate) input: JSONSchema,
    pub(crate) output: JSONSchema,
}

pub(crate) struct AgentRuntime {
    pub(crate) endpoint: String,
    pub(crate) shared_secret: SecretString,
    pub(crate) capabilities: HashMap<String, CompiledCapability>,
}

pub(crate) struct ScopeAgents {
    pub(crate) registry: AgentRegistry,
    pub(crate) agents: HashMap<String, AgentRuntime>,
}

#[derive(Clone)]
pub(crate) struct WorkflowRuntime {
    pub(crate) workflow: FsmWorkflow,
    pub(crate) timeout_ms: u64,
}

pub(crate) struct ScopeRollouts {
    pub(crate) store: WeightedPromptStore,
    pub(crate) salts: HashMap<String, String>,
}

#[derive(Default)]
pub(crate) struct DatasetRegistry {
    pub(crate) versions: HashMap<(ToolkitScope, String, u32), Dataset>,
    pub(crate) retained_bytes: usize,
    /// Serialized entry bytes retained per scope. The process total above
    /// is a ceiling for the deployment; this is what keeps one scope from
    /// being the whole of it.
    pub(crate) scope_bytes: HashMap<ToolkitScope, usize>,
}

/// Live bounded facade for governed orchestration, offline evaluation, and rollout selection.
pub struct AiToolkitRuntime {
    pub(crate) limits: AiToolkitLimits,
    pub(crate) allowed_scopes: HashSet<ToolkitScope>,
    pub(crate) agents: HashMap<ToolkitScope, ScopeAgents>,
    pub(crate) workflows: HashMap<(ToolkitScope, String), WorkflowRuntime>,
    pub(crate) datasets: Mutex<DatasetRegistry>,
    pub(crate) rollouts: HashMap<ToolkitScope, ScopeRollouts>,
    pub(crate) experiments: Mutex<VecDeque<(ToolkitScope, EvaluationRunResult)>>,
    pub(crate) operations: Mutex<VecDeque<(ToolkitScope, ToolkitOperationSummary)>>,
    pub(crate) agent_egress: Option<AgentEgressInput>,
    pub(crate) no_redirect_client: reqwest::Client,
    pub(crate) agent_semaphore: Semaphore,
    pub(crate) evaluation_semaphore: Semaphore,
}

impl AiToolkitRuntime {
    /// Validate a complete generation without publishing or dialing anything.
    pub fn validate(input: &AiToolkitConfigInput) -> Result<(), ToolkitError> {
        validate_config(input)
    }

    /// Compile and publish one immutable toolkit generation.
    pub fn try_new(input: AiToolkitConfigInput) -> Result<Arc<Self>, ToolkitError> {
        validate_config(&input)?;
        let no_redirect_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ToolkitError::InvalidConfiguration {
                field: "agent_http_client",
            })?;

        let limits = input.limits.clone();
        let allowed_scopes = input.allowed_scopes.into_iter().collect();
        let mut agents: HashMap<ToolkitScope, ScopeAgents> = HashMap::new();
        for configured in input.agents {
            let scope_agents =
                agents
                    .entry(configured.scope.clone())
                    .or_insert_with(|| ScopeAgents {
                        registry: AgentRegistry::new(),
                        agents: HashMap::new(),
                    });
            let mut advertised = Vec::with_capacity(configured.capabilities.len());
            let mut compiled = HashMap::with_capacity(configured.capabilities.len());
            for capability in configured.capabilities {
                let input_schema =
                    compile_schema(&capability.input_schema, &limits, "agent_input")?;
                let output_schema =
                    compile_schema(&capability.output_schema, &limits, "agent_output")?;
                advertised.push(AgentCapability {
                    name: capability.name.clone(),
                    description: capability.description,
                    input_schema: capability.input_schema,
                    output_schema: capability.output_schema,
                });
                compiled.insert(
                    capability.name,
                    CompiledCapability {
                        input: input_schema,
                        output: output_schema,
                    },
                );
            }
            scope_agents.registry.register(&configured.id, advertised);
            scope_agents.agents.insert(
                configured.id,
                AgentRuntime {
                    endpoint: configured.endpoint,
                    shared_secret: configured.shared_secret,
                    capabilities: compiled,
                },
            );
        }

        let mut workflows = HashMap::with_capacity(input.workflows.len());
        for configured in input.workflows {
            let workflow = FsmWorkflow::new(
                configured.name.as_str(),
                configured.initial_state.as_str(),
                configured.states,
                configured.max_steps,
            )
            .map_err(|_| ToolkitError::InvalidConfiguration {
                field: "workflow.graph",
            })?;
            workflows.insert(
                (configured.scope, configured.name),
                WorkflowRuntime {
                    workflow,
                    timeout_ms: configured.timeout_ms,
                },
            );
        }

        let mut datasets = DatasetRegistry {
            versions: HashMap::with_capacity(input.datasets.len()),
            retained_bytes: 0,
            scope_bytes: HashMap::new(),
        };
        for configured in input.datasets {
            let dataset_bytes = ensure_serialized(
                &configured.dataset.entries,
                "dataset_bytes",
                limits.max_request_bytes,
            )?;
            let next_version_count = checked_bounded_add(
                "dataset_versions_total",
                datasets.versions.len(),
                1,
                limits.max_dataset_versions_total,
            )?;
            let next_retained_bytes = checked_bounded_add(
                "dataset_bytes_total",
                datasets.retained_bytes,
                dataset_bytes,
                limits.max_dataset_bytes_total,
            )?;
            // Config-seeded rows are operator-authored and already refused
            // at `validate_config`; they are accounted per scope here so a
            // later admin registration measures the share it is really
            // left with rather than an empty one.
            let scope_bytes = datasets.scope_bytes.entry(configured.scope.clone()).or_insert(0);
            *scope_bytes = scope_bytes.saturating_add(dataset_bytes);
            let key = (
                configured.scope,
                configured.dataset.name.clone(),
                configured.dataset.version,
            );
            let previous = datasets.versions.insert(key, configured.dataset);
            debug_assert!(previous.is_none());
            debug_assert_eq!(datasets.versions.len(), next_version_count);
            datasets.retained_bytes = next_retained_bytes;
        }

        let mut rollouts: HashMap<ToolkitScope, ScopeRollouts> = HashMap::new();
        for configured in input.prompt_rollouts {
            let scoped = rollouts
                .entry(configured.scope)
                .or_insert_with(|| ScopeRollouts {
                    store: WeightedPromptStore::new(),
                    salts: HashMap::new(),
                });
            scoped
                .store
                .replace_versions(&configured.name, configured.versions)
                .map_err(|_| ToolkitError::InvalidConfiguration {
                    field: "rollout.versions",
                })?;
            scoped.salts.insert(configured.name, configured.salt);
        }

        Ok(Arc::new(Self {
            agent_semaphore: Semaphore::new(limits.agent_concurrency),
            evaluation_semaphore: Semaphore::new(limits.evaluation_concurrency),
            limits,
            allowed_scopes,
            agents,
            workflows,
            datasets: Mutex::new(datasets),
            rollouts,
            experiments: Mutex::new(VecDeque::new()),
            operations: Mutex::new(VecDeque::new()),
            agent_egress: input.agent_egress,
            no_redirect_client,
        }))
    }

    /// Construct an empty immutable runtime for disabled/default pipelines.
    pub fn disabled() -> Arc<Self> {
        match Self::try_new(AiToolkitConfigInput::default()) {
            Ok(runtime) => runtime,
            Err(_) => {
                let limits = AiToolkitLimits::default();
                Arc::new(Self {
                    agent_semaphore: Semaphore::new(limits.agent_concurrency),
                    evaluation_semaphore: Semaphore::new(limits.evaluation_concurrency),
                    limits,
                    allowed_scopes: HashSet::new(),
                    agents: HashMap::new(),
                    workflows: HashMap::new(),
                    datasets: Mutex::new(DatasetRegistry::default()),
                    rollouts: HashMap::new(),
                    experiments: Mutex::new(VecDeque::new()),
                    operations: Mutex::new(VecDeque::new()),
                    agent_egress: None,
                    // A disabled runtime cannot issue a request, so its fallback
                    // client's redirect policy is unobservable.
                    no_redirect_client: reqwest::Client::new(),
                })
            }
        }
    }

    /// True when this generation owns any toolkit resource.
    pub fn is_enabled(&self) -> bool {
        !self.agents.is_empty()
            || !self.workflows.is_empty()
            || !self.datasets.lock().versions.is_empty()
            || !self.rollouts.is_empty()
    }

    /// Discover only agents in the authenticated tenant/origin scope.
    pub fn discover_agents(
        &self,
        request: AgentDiscoveryRequest,
    ) -> Result<AgentDiscoveryResult, ToolkitError> {
        let scope = request.scope.clone();
        let result = self.discover_agents_inner(request);
        // Successful discovery reads stay out of the bounded operations
        // ring so polling cannot evict mutating history; failures record.
        if result.is_err() {
            self.record_operation(scope, "agent_discovery", metric_outcome(&result).as_label());
        }
        record_ai_toolkit_operation(AiToolkitCapability::Workflow, metric_outcome(&result));
        result
    }

    fn discover_agents_inner(
        &self,
        request: AgentDiscoveryRequest,
    ) -> Result<AgentDiscoveryResult, ToolkitError> {
        validate_scope(&request.scope, &self.limits)?;
        if let Some(capability) = request.capability.as_deref() {
            validate_identifier(
                capability,
                "discovery.capability",
                self.limits.max_identifier_bytes,
            )?;
        }
        let scoped = self
            .agents
            .get(&request.scope)
            .ok_or(ToolkitError::NotFound { resource: "agent" })?;
        let mut ids = match request.capability.as_deref() {
            Some(capability) => scoped.registry.find_by_capability(capability),
            None => scoped.registry.list_agents(),
        };
        ids.sort();
        let agents = ids
            .into_iter()
            .map(|id| {
                let mut capabilities = scoped.registry.discover(&id).unwrap_or_default();
                capabilities.sort();
                AgentSummary { id, capabilities }
            })
            .collect();
        let result = AgentDiscoveryResult { agents };
        ensure_serialized(
            &result,
            "agent_discovery_response_bytes",
            self.limits.max_response_bytes,
        )?;
        Ok(result)
    }

    /// Atomically register one immutable, exact dataset version.
    pub fn register_dataset(
        &self,
        request: DatasetRegistrationRequest,
    ) -> Result<DatasetRegistrationResult, ToolkitError> {
        let scope = request.scope.clone();
        let result = self.register_dataset_inner(request);
        self.record_operation(
            scope,
            "dataset_registration",
            metric_outcome(&result).as_label(),
        );
        record_ai_toolkit_operation(AiToolkitCapability::Evaluation, metric_outcome(&result));
        result
    }

    fn register_dataset_inner(
        &self,
        request: DatasetRegistrationRequest,
    ) -> Result<DatasetRegistrationResult, ToolkitError> {
        validate_scope(&request.scope, &self.limits)?;
        if !self.allowed_scopes.contains(&request.scope) {
            return Err(ToolkitError::NotFound {
                resource: "dataset_scope",
            });
        }
        validate_identifier(
            &request.name,
            "dataset.name",
            self.limits.max_identifier_bytes,
        )?;
        if request.version == 0 {
            return Err(ToolkitError::InvalidConfiguration {
                field: "dataset.version",
            });
        }
        ensure_count(
            "dataset_entries",
            request.entries.len(),
            self.limits.max_dataset_entries,
        )?;
        let dataset_bytes = ensure_serialized(
            &request.entries,
            "dataset_bytes",
            self.limits.max_request_bytes,
        )?;
        let entries = request.entries.len();
        let dataset = Dataset::new(request.name.clone(), request.version, request.entries)
            .map_err(|_| ToolkitError::InvalidConfiguration { field: "dataset" })?;
        let key = (request.scope.clone(), request.name.clone(), request.version);
        let mut datasets = self.datasets.lock();
        if datasets.versions.contains_key(&key) {
            return Err(ToolkitError::Duplicate {
                resource: "dataset_version",
            });
        }
        let names: HashSet<&str> = datasets
            .versions
            .keys()
            .filter(|(scope, _, _)| scope == &request.scope)
            .map(|(_, name, _)| name.as_str())
            .collect();
        if !names.contains(request.name.as_str()) {
            checked_bounded_add("dataset_names", names.len(), 1, self.limits.max_datasets)?;
        }
        let versions = datasets
            .versions
            .keys()
            .filter(|(scope, name, _)| scope == &request.scope && name == &request.name)
            .count();
        checked_bounded_add(
            "dataset_versions",
            versions,
            1,
            self.limits.max_dataset_versions,
        )?;
        // The per-scope caps above multiply out to exactly the shipped
        // process totals, so on their own they let one tenant hold 100% of
        // both and refuse every other tenant's registration until the next
        // config reload. This is that tenant's share of the process budget,
        // and its own ceiling well before the process one.
        let (scope_bytes_ceiling, scope_versions_ceiling) = self.scope_dataset_share();
        let scope_versions = datasets
            .versions
            .keys()
            .filter(|(scope, _, _)| scope == &request.scope)
            .count();
        checked_bounded_add(
            "dataset_versions_scope",
            scope_versions,
            1,
            scope_versions_ceiling,
        )?;
        let scope_bytes = datasets
            .scope_bytes
            .get(&request.scope)
            .copied()
            .unwrap_or(0);
        let next_scope_bytes = checked_bounded_add(
            "dataset_bytes_scope",
            scope_bytes,
            dataset_bytes,
            scope_bytes_ceiling,
        )?;
        let next_version_count = checked_bounded_add(
            "dataset_versions_total",
            datasets.versions.len(),
            1,
            self.limits.max_dataset_versions_total,
        )?;
        let next_retained_bytes = checked_bounded_add(
            "dataset_bytes_total",
            datasets.retained_bytes,
            dataset_bytes,
            self.limits.max_dataset_bytes_total,
        )?;
        let previous = datasets.versions.insert(key, dataset);
        debug_assert!(previous.is_none());
        debug_assert_eq!(datasets.versions.len(), next_version_count);
        datasets.retained_bytes = next_retained_bytes;
        datasets
            .scope_bytes
            .insert(request.scope.clone(), next_scope_bytes);
        Ok(DatasetRegistrationResult {
            name: request.name,
            version: request.version,
            entries,
        })
    }

    /// One scope's share of the process-wide dataset budgets, in bytes and
    /// in versions.
    ///
    /// No configuration key is introduced. The share is the existing total
    /// divided by the number of scopes this generation admits, so a
    /// single-origin deployment still gets the whole budget and a
    /// multi-tenant one gets the isolation the operations ring already has
    /// (`retain_scoped_row`). The byte share is floored at one maximum
    /// request so a scope can always register at least one dataset, and
    /// neither share can exceed its process total.
    pub(crate) fn scope_dataset_share(&self) -> (usize, usize) {
        let scopes = self.allowed_scopes.len().max(1);
        let bytes = (self.limits.max_dataset_bytes_total / scopes)
            .max(self.limits.max_request_bytes)
            .min(self.limits.max_dataset_bytes_total);
        let versions = (self.limits.max_dataset_versions_total / scopes)
            .max(1)
            .min(self.limits.max_dataset_versions_total);
        (bytes, versions)
    }

    pub(crate) fn record_operation(
        &self,
        scope: ToolkitScope,
        operation: &'static str,
        outcome: &'static str,
    ) {
        if validate_scope(&scope, &self.limits).is_err() {
            return;
        }
        let row = ToolkitOperationSummary {
            operation: operation.to_string(),
            outcome: outcome.to_string(),
            recorded_at: chrono::Utc::now().to_rfc3339(),
        };
        let mut operations = self.operations.lock();
        let retained = retain_scoped_row(
            &mut operations,
            scope,
            row,
            self.limits.max_retained_operations,
        );
        if !retained {
            // The process-wide ring is full of other scopes' rows, so this
            // scope's first row cannot be retained without evicting another
            // tenant's history. The operation itself was still counted in
            // the metric and, for admin operations, the typed event; say so
            // loudly once, because an empty snapshot must be
            // distinguishable from "no activity".
            static RETENTION_DROP_REPORTED: std::sync::Once = std::sync::Once::new();
            RETENTION_DROP_REPORTED.call_once(|| {
                tracing::warn!(
                    target: "sbproxy::ai::toolkit",
                    total_ceiling = MAX_TOTAL_RETAINED_ROWS,
                    "toolkit operation row dropped: the process-wide retention ring is full of \
                     other scopes' rows; the scope's snapshot will show no operations even \
                     though its metric and event streams recorded them"
                );
            });
        }
    }

    pub(crate) fn retain_experiment(
        &self,
        scope: ToolkitScope,
        row: EvaluationRunResult,
    ) -> Result<(), ToolkitError> {
        validate_scope(&scope, &self.limits)?;
        let mut experiments = self.experiments.lock();
        if experiments.iter().any(|(candidate_scope, existing)| {
            candidate_scope == &scope && existing.experiment_id == row.experiment_id
        }) {
            return Err(ToolkitError::Duplicate {
                resource: "experiment_id",
            });
        }
        if !retain_scoped_row(
            &mut experiments,
            scope,
            row,
            self.limits.max_retained_operations,
        ) {
            return Err(ToolkitError::LimitExceeded {
                resource: "experiment_retention_total",
                limit: MAX_TOTAL_RETAINED_ROWS,
                observed: experiments.len().saturating_add(1),
            });
        }
        Ok(())
    }

    pub(crate) fn workflow_summaries(&self, scope: &ToolkitScope) -> Vec<WorkflowSummary> {
        let mut rows: Vec<_> = self
            .workflows
            .iter()
            .filter(|((candidate, _), _)| candidate == scope)
            .map(|((_, name), workflow)| WorkflowSummary {
                name: name.clone(),
                max_steps: workflow.workflow.max_steps(),
                timeout_ms: workflow.timeout_ms,
            })
            .collect();
        rows.sort_by(|left, right| left.name.cmp(&right.name));
        rows
    }

    pub(crate) fn rollout_summaries(&self, scope: &ToolkitScope) -> Vec<RolloutSummary> {
        let Some(scoped) = self.rollouts.get(scope) else {
            return Vec::new();
        };
        scoped
            .store
            .list_names()
            .into_iter()
            .map(|name| RolloutSummary {
                versions: scoped
                    .store
                    .list_versions(&name)
                    .into_iter()
                    .map(|version| RolloutVersionSummary {
                        version: version.version,
                        weight: version.weight,
                    })
                    .collect(),
                name,
            })
            .collect()
    }
}

/// Total rows retained by one registry across every scope. Per-scope limits
/// remain authoritative below this process ceiling; when the total is full,
/// an active scope replaces only its own oldest row and can never evict a
/// different tenant's history.
pub(crate) const MAX_TOTAL_RETAINED_ROWS: usize = 16_384;

fn retain_scoped_row<T>(
    rows: &mut VecDeque<(ToolkitScope, T)>,
    scope: ToolkitScope,
    row: T,
    per_scope_limit: usize,
) -> bool {
    let own_oldest = rows
        .iter()
        .position(|(candidate_scope, _)| candidate_scope == &scope);
    let own_count = rows
        .iter()
        .filter(|(candidate_scope, _)| candidate_scope == &scope)
        .count();
    if own_count >= per_scope_limit {
        if let Some(index) = own_oldest {
            rows.remove(index);
        }
    } else if rows.len() >= MAX_TOTAL_RETAINED_ROWS {
        let Some(index) = own_oldest else {
            return false;
        };
        rows.remove(index);
    }
    rows.push_back((scope, row));
    true
}
