use std::collections::{HashMap, HashSet};

use jsonschema::JSONSchema;
use serde::Serialize;
use serde_json::Value;

use crate::agent_orchestration::FsmWorkflow;
use crate::prompt_versioning::WeightedPromptStore;
use sbproxy_security::egress::EgressPurpose;

use super::types::MAX_SCOPE_COMPONENT_BYTES;
use super::{AiToolkitConfigInput, AiToolkitLimits, ToolkitError, ToolkitScope};

const MAX_SCHEMA_DEPTH: usize = 64;

pub(crate) fn validate_config(input: &AiToolkitConfigInput) -> Result<(), ToolkitError> {
    validate_limits(&input.limits)?;
    let limits = &input.limits;
    ensure_count("agents", input.agents.len(), limits.max_agents)?;
    ensure_count("workflows", input.workflows.len(), limits.max_workflows)?;
    ensure_count("rollouts", input.prompt_rollouts.len(), limits.max_rollouts)?;

    let mut allowed_scopes = HashSet::with_capacity(input.allowed_scopes.len());
    for scope in &input.allowed_scopes {
        validate_scope(scope, limits)?;
        allowed_scopes.insert(scope.clone());
    }

    let mut agent_ids = HashSet::new();
    let mut scope_capabilities: HashMap<ToolkitScope, HashSet<String>> = HashMap::new();
    for agent in &input.agents {
        validate_scope(&agent.scope, limits)?;
        validate_identifier(&agent.id, "agent.id", limits.max_identifier_bytes)?;
        if reqwest::header::HeaderValue::try_from(agent.id.as_str()).is_err() {
            return Err(ToolkitError::InvalidConfiguration { field: "agent.id" });
        }
        ensure_count(
            "agent_endpoint_bytes",
            agent.endpoint.len(),
            limits.max_description_bytes,
        )?;
        validate_endpoint(&agent.endpoint)?;
        if agent.shared_secret.is_empty() {
            return Err(ToolkitError::InvalidConfiguration {
                field: "agent.shared_secret",
            });
        }
        ensure_count(
            "agent_secret_bytes",
            agent.shared_secret.len(),
            limits.max_secret_bytes,
        )?;
        ensure_count(
            "agent_capabilities",
            agent.capabilities.len(),
            limits.max_capabilities_per_agent,
        )?;
        if !agent_ids.insert((agent.scope.clone(), agent.id.clone())) {
            return Err(ToolkitError::Duplicate { resource: "agent" });
        }

        let mut names = HashSet::new();
        for capability in &agent.capabilities {
            validate_identifier(
                &capability.name,
                "capability.name",
                limits.max_identifier_bytes,
            )?;
            validate_text(
                &capability.description,
                "capability.description",
                limits.max_description_bytes,
                true,
            )?;
            if !names.insert(capability.name.clone()) {
                return Err(ToolkitError::Duplicate {
                    resource: "agent_capability",
                });
            }
            compile_schema(&capability.input_schema, limits, "agent_input")?;
            compile_schema(&capability.output_schema, limits, "agent_output")?;
            scope_capabilities
                .entry(agent.scope.clone())
                .or_default()
                .insert(capability.name.clone());
        }
    }

    if !input.agents.is_empty() {
        let egress = input
            .agent_egress
            .as_ref()
            .ok_or(ToolkitError::InvalidConfiguration {
                field: "agent_egress",
            })?;
        if egress.purpose != EgressPurpose::AgentOrchestration
            || !egress
                .authorizer
                .purposes()
                .contains(&EgressPurpose::AgentOrchestration)
        {
            return Err(ToolkitError::InvalidConfiguration {
                field: "agent_egress.purpose",
            });
        }
    }

    let mut workflow_keys = HashSet::new();
    for workflow in &input.workflows {
        validate_scope(&workflow.scope, limits)?;
        validate_identifier(&workflow.name, "workflow.name", limits.max_identifier_bytes)?;
        validate_identifier(
            &workflow.initial_state,
            "workflow.initial_state",
            limits.max_identifier_bytes,
        )?;
        if !workflow_keys.insert((workflow.scope.clone(), workflow.name.clone())) {
            return Err(ToolkitError::Duplicate {
                resource: "workflow",
            });
        }
        if workflow.timeout_ms == 0 || workflow.timeout_ms > limits.max_workflow_timeout_ms {
            return Err(ToolkitError::InvalidConfiguration {
                field: "workflow.timeout_ms",
            });
        }
        ensure_serialized(
            workflow,
            "workflow_definition_bytes",
            limits.max_request_bytes,
        )?;
        let known_capabilities = scope_capabilities.get(&workflow.scope);
        for state in &workflow.states {
            if !known_capabilities.is_some_and(|capabilities| capabilities.contains(&state.action))
            {
                return Err(ToolkitError::InvalidConfiguration {
                    field: "workflow.state.action",
                });
            }
        }
        FsmWorkflow::new(
            workflow.name.as_str(),
            workflow.initial_state.as_str(),
            workflow.states.clone(),
            workflow.max_steps,
        )
        .map_err(|_| ToolkitError::InvalidConfiguration {
            field: "workflow.graph",
        })?;
    }

    let mut dataset_keys = HashSet::new();
    let mut dataset_names: HashMap<ToolkitScope, HashSet<String>> = HashMap::new();
    let mut dataset_versions: HashMap<(ToolkitScope, String), usize> = HashMap::new();
    let mut dataset_versions_total = 0usize;
    let mut dataset_bytes_total = 0usize;
    for configured in &input.datasets {
        validate_scope(&configured.scope, limits)?;
        if !allowed_scopes.contains(&configured.scope) {
            return Err(ToolkitError::InvalidConfiguration {
                field: "dataset.scope",
            });
        }
        validate_identifier(
            &configured.dataset.name,
            "dataset.name",
            limits.max_identifier_bytes,
        )?;
        if configured.dataset.version == 0 {
            return Err(ToolkitError::InvalidConfiguration {
                field: "dataset.version",
            });
        }
        ensure_count(
            "dataset_entries",
            configured.dataset.entries.len(),
            limits.max_dataset_entries,
        )?;
        let dataset_bytes = ensure_serialized(
            &configured.dataset.entries,
            "dataset_bytes",
            limits.max_request_bytes,
        )?;
        if !dataset_keys.insert((
            configured.scope.clone(),
            configured.dataset.name.clone(),
            configured.dataset.version,
        )) {
            return Err(ToolkitError::Duplicate {
                resource: "dataset_version",
            });
        }
        let name_key = (configured.scope.clone(), configured.dataset.name.clone());
        let scoped_names = dataset_names.entry(configured.scope.clone()).or_default();
        scoped_names.insert(configured.dataset.name.clone());
        ensure_count("dataset_names", scoped_names.len(), limits.max_datasets)?;
        let versions = dataset_versions.entry(name_key).or_default();
        *versions = checked_bounded_add(
            "dataset_versions",
            *versions,
            1,
            limits.max_dataset_versions,
        )?;
        dataset_versions_total = checked_bounded_add(
            "dataset_versions_total",
            dataset_versions_total,
            1,
            limits.max_dataset_versions_total,
        )?;
        dataset_bytes_total = checked_bounded_add(
            "dataset_bytes_total",
            dataset_bytes_total,
            dataset_bytes,
            limits.max_dataset_bytes_total,
        )?;
    }
    let mut rollout_keys = HashSet::new();
    for rollout in &input.prompt_rollouts {
        validate_scope(&rollout.scope, limits)?;
        validate_identifier(&rollout.name, "rollout.name", limits.max_identifier_bytes)?;
        if rollout.name.contains('@') {
            return Err(ToolkitError::InvalidConfiguration {
                field: "rollout.name",
            });
        }
        validate_text(
            &rollout.salt,
            "rollout.salt",
            limits.max_identifier_bytes,
            false,
        )?;
        ensure_count(
            "rollout_versions",
            rollout.versions.len(),
            limits.max_rollout_versions,
        )?;
        if !rollout_keys.insert((rollout.scope.clone(), rollout.name.clone())) {
            return Err(ToolkitError::Duplicate {
                resource: "prompt_rollout",
            });
        }
        for version in &rollout.versions {
            if version.name != rollout.name {
                return Err(ToolkitError::InvalidConfiguration {
                    field: "rollout.version.name",
                });
            }
            ensure_count(
                "prompt_content_bytes",
                version.content.len(),
                limits.max_request_bytes,
            )?;
        }
        let rollout_content_bytes = rollout.versions.iter().fold(0usize, |total, version| {
            total.saturating_add(version.content.len())
        });
        ensure_count(
            "prompt_rollout_content_bytes",
            rollout_content_bytes,
            limits.max_request_bytes,
        )?;
        let store = WeightedPromptStore::new();
        store
            .replace_versions(&rollout.name, rollout.versions.clone())
            .map_err(|_| ToolkitError::InvalidConfiguration {
                field: "rollout.versions",
            })?;
    }

    Ok(())
}

pub(crate) fn compile_schema(
    schema: &Value,
    limits: &AiToolkitLimits,
    boundary: &'static str,
) -> Result<JSONSchema, ToolkitError> {
    if !(schema.is_object() || schema.is_boolean()) {
        return Err(ToolkitError::InvalidSchema { boundary });
    }
    let serialized =
        serde_json::to_vec(schema).map_err(|_| ToolkitError::InvalidSchema { boundary })?;
    ensure_count("schema_bytes", serialized.len(), limits.max_schema_bytes)?;
    validate_schema_tree(schema, MAX_SCHEMA_DEPTH, boundary)?;
    JSONSchema::options()
        .compile(schema)
        .map_err(|_| ToolkitError::InvalidSchema { boundary })
}

fn validate_schema_tree(
    value: &Value,
    remaining: usize,
    boundary: &'static str,
) -> Result<(), ToolkitError> {
    if remaining == 0 {
        return Err(ToolkitError::InvalidSchema { boundary });
    }
    match value {
        Value::Object(map) => {
            if map
                .get("$ref")
                .and_then(Value::as_str)
                .is_some_and(|reference| !reference.starts_with('#'))
            {
                return Err(ToolkitError::InvalidSchema { boundary });
            }
            for child in map.values() {
                validate_schema_tree(child, remaining - 1, boundary)?;
            }
        }
        Value::Array(items) => {
            for child in items {
                validate_schema_tree(child, remaining - 1, boundary)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn validate_scope(
    scope: &ToolkitScope,
    limits: &AiToolkitLimits,
) -> Result<(), ToolkitError> {
    validate_identifier(
        &scope.origin_id,
        "scope.origin_id",
        limits.max_identifier_bytes.min(MAX_SCOPE_COMPONENT_BYTES),
    )?;
    validate_identifier(
        &scope.tenant_id,
        "scope.tenant_id",
        limits.max_identifier_bytes.min(MAX_SCOPE_COMPONENT_BYTES),
    )
}

pub(crate) fn validate_identifier(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), ToolkitError> {
    validate_text(value, field, max_bytes, false)
}

pub(crate) fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<(), ToolkitError> {
    if (!allow_empty && value.trim().is_empty()) || value.contains('\0') {
        return Err(ToolkitError::InvalidConfiguration { field });
    }
    ensure_count(field, value.len(), max_bytes)
}

pub(crate) fn ensure_serialized<T: Serialize>(
    value: &T,
    resource: &'static str,
    limit: usize,
) -> Result<usize, ToolkitError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ToolkitError::Serialization)?;
    ensure_count(resource, bytes.len(), limit)?;
    Ok(bytes.len())
}

pub(crate) fn ensure_count(
    resource: &'static str,
    observed: usize,
    limit: usize,
) -> Result<(), ToolkitError> {
    if observed > limit {
        Err(ToolkitError::LimitExceeded {
            resource,
            limit,
            observed,
        })
    } else {
        Ok(())
    }
}

pub(crate) fn checked_bounded_add(
    resource: &'static str,
    current: usize,
    added: usize,
    limit: usize,
) -> Result<usize, ToolkitError> {
    let observed = current
        .checked_add(added)
        .ok_or(ToolkitError::LimitExceeded {
            resource,
            limit,
            observed: usize::MAX,
        })?;
    ensure_count(resource, observed, limit)?;
    Ok(observed)
}

fn validate_endpoint(endpoint: &str) -> Result<(), ToolkitError> {
    let parsed = url::Url::parse(endpoint).map_err(|_| ToolkitError::InvalidConfiguration {
        field: "agent.endpoint",
    })?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ToolkitError::InvalidConfiguration {
            field: "agent.endpoint",
        });
    }
    if parsed.scheme() == "http" && !endpoint_is_local(&parsed) {
        return Err(ToolkitError::InvalidConfiguration {
            field: "agent.endpoint",
        });
    }
    Ok(())
}

fn endpoint_is_local(endpoint: &url::Url) -> bool {
    match endpoint.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => {
            std::net::IpAddr::V4(address).to_canonical().is_loopback()
        }
        Some(url::Host::Ipv6(address)) => {
            std::net::IpAddr::V6(address).to_canonical().is_loopback()
        }
        None => false,
    }
}

fn validate_limits(limits: &AiToolkitLimits) -> Result<(), ToolkitError> {
    const HARD: [(&str, usize, usize); 22] = [
        ("limits.max_agents", 256, 0),
        ("limits.max_capabilities_per_agent", 128, 0),
        ("limits.max_workflows", 256, 0),
        ("limits.max_datasets", 256, 0),
        ("limits.max_dataset_versions", 64, 0),
        ("limits.max_dataset_versions_total", 16_384, 0),
        ("limits.max_dataset_entries", 10_000, 0),
        ("limits.max_dataset_bytes_total", 512 * 1024 * 1024, 0),
        ("limits.max_rollouts", 512, 0),
        ("limits.max_rollout_versions", 64, 0),
        ("limits.max_retained_operations", 2_048, 0),
        ("limits.max_request_bytes", 1024 * 1024, 0),
        ("limits.max_response_bytes", 1024 * 1024, 0),
        ("limits.max_identifier_bytes", 256, 0),
        ("limits.max_description_bytes", 2_048, 0),
        ("limits.max_schema_bytes", 256 * 1024, 0),
        ("limits.max_secret_bytes", 4_096, 0),
        ("limits.max_evaluation_cases", 10_000, 0),
        ("limits.max_metrics", 64, 0),
        ("limits.max_judge_criteria", 64, 0),
        ("limits.agent_concurrency", 64, 0),
        ("limits.evaluation_concurrency", 16, 0),
    ];
    let values = [
        limits.max_agents,
        limits.max_capabilities_per_agent,
        limits.max_workflows,
        limits.max_datasets,
        limits.max_dataset_versions,
        limits.max_dataset_versions_total,
        limits.max_dataset_entries,
        limits.max_dataset_bytes_total,
        limits.max_rollouts,
        limits.max_rollout_versions,
        limits.max_retained_operations,
        limits.max_request_bytes,
        limits.max_response_bytes,
        limits.max_identifier_bytes,
        limits.max_description_bytes,
        limits.max_schema_bytes,
        limits.max_secret_bytes,
        limits.max_evaluation_cases,
        limits.max_metrics,
        limits.max_judge_criteria,
        limits.agent_concurrency,
        limits.evaluation_concurrency,
    ];
    for ((field, hard_max, _), value) in HARD.into_iter().zip(values) {
        if value == 0 || value > hard_max {
            return Err(ToolkitError::InvalidConfiguration { field });
        }
    }
    if limits.default_workflow_timeout_ms == 0
        || limits.max_workflow_timeout_ms == 0
        || limits.default_workflow_timeout_ms > limits.max_workflow_timeout_ms
        || limits.max_workflow_timeout_ms > 60_000
    {
        return Err(ToolkitError::InvalidConfiguration {
            field: "limits.workflow_timeout_ms",
        });
    }
    Ok(())
}
