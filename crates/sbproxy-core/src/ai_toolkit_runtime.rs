//! Generation-pinned assembly for the bounded AI toolkit runtime.
//!
//! Parsed configuration retains only secret references. This module is the
//! single boundary that resolves them, lowers origin references to immutable
//! tenant/origin scopes, and attaches the exact-generation egress authorizer.

use anyhow::Context as _;

use sbproxy_ai::agent_orchestration::FsmState;
use sbproxy_ai::evaluation::{Dataset, DatasetEntry};
use sbproxy_ai::prompt_versioning::WeightedPromptVersion;
use sbproxy_ai::toolkit::{
    AgentEgressInput, AiToolkitConfigInput, AiToolkitLimits, AiToolkitRuntime, PromptRolloutInput,
    ToolkitAgentInput, ToolkitCapabilityInput, ToolkitDatasetInput, ToolkitScope,
    ToolkitWorkflowInput,
};
use sbproxy_config::{CompiledConfig, CompiledOrigin};
use sbproxy_security::egress::EgressPurpose;

/// Build one immutable toolkit runtime from the same compiled config
/// generation as the pipeline that will own it.
pub(crate) fn build(
    config: &CompiledConfig,
    resolve_secrets: bool,
) -> anyhow::Result<std::sync::Arc<AiToolkitRuntime>> {
    let mut input = AiToolkitConfigInput::default();
    let configured = config.server.ai_toolkit.as_ref();
    if let Some(configured) = configured {
        input.allowed_scopes = config
            .origins
            .iter()
            .map(|origin| {
                ToolkitScope::new(origin.origin_id.to_string(), origin.tenant_id.to_string())
            })
            .collect::<Result<Vec<_>, _>>()
            .context("invalid compiled AI toolkit origin scope")?;
        input.limits = lower_limits(&configured.limits);
        let max_secret_bytes = input.limits.max_secret_bytes;
        input.agents = configured
            .agents
            .iter()
            .enumerate()
            .map(|(index, agent)| {
                let scope = scope_for(config, &agent.origin)?;
                if agent.auth.shared_secret.len() > max_secret_bytes {
                    anyhow::bail!(
                        "proxy.ai_toolkit.agents[{index}].auth.shared_secret exceeds the configured \
                         {max_secret_bytes}-byte reference limit"
                    );
                }
                let shared_secret = if resolve_secrets {
                    let field = format!("proxy.ai_toolkit.agents[{index}].auth.shared_secret");
                    let resolved = zeroize::Zeroizing::new(
                        crate::config_source::resolve_secret_reference_bounded(
                            &agent.auth.shared_secret,
                            &field,
                            max_secret_bytes,
                        )?,
                    );
                    sbproxy_vault::SecretString::new(resolved.as_str())
                } else {
                    // Validation proves the complete runtime shape without
                    // touching the environment, filesystem, or secret backend.
                    sbproxy_vault::SecretString::new("x")
                };
                Ok(ToolkitAgentInput {
                    scope,
                    id: agent.id.clone(),
                    endpoint: agent.endpoint.clone(),
                    shared_secret,
                    capabilities: agent
                        .capabilities
                        .iter()
                        .map(|capability| ToolkitCapabilityInput {
                            name: capability.name.clone(),
                            description: capability.description.clone(),
                            input_schema: capability.input_schema.clone(),
                            output_schema: capability.output_schema.clone(),
                        })
                        .collect(),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        input.workflows = configured
            .workflows
            .iter()
            .map(|workflow| {
                Ok(ToolkitWorkflowInput {
                    scope: scope_for(config, &workflow.origin)?,
                    name: workflow.name.clone(),
                    initial_state: workflow.initial_state.clone(),
                    states: workflow
                        .states
                        .iter()
                        .map(|state| FsmState {
                            name: state.name.clone(),
                            action: state.action.clone(),
                            transitions: state.transitions.clone(),
                        })
                        .collect(),
                    max_steps: workflow.max_steps,
                    timeout_ms: workflow.timeout_ms,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        input.datasets = configured
            .datasets
            .iter()
            .map(|dataset| {
                let entries = dataset
                    .entries
                    .iter()
                    .map(|entry| DatasetEntry {
                        input: entry.input.clone(),
                        expected_output: entry.expected_output.clone(),
                        metadata: entry.metadata.clone(),
                    })
                    .collect();
                Ok(ToolkitDatasetInput {
                    scope: scope_for(config, &dataset.origin)?,
                    dataset: Dataset::new(&dataset.name, dataset.version, entries)
                        .context("invalid proxy.ai_toolkit dataset")?,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        input.prompt_rollouts = configured
            .prompt_rollouts
            .iter()
            .map(|rollout| {
                let versions = rollout
                    .versions
                    .iter()
                    .map(|version| {
                        WeightedPromptVersion::new(
                            &rollout.name,
                            version.version,
                            &version.content,
                            version.weight,
                        )
                        .context("invalid proxy.ai_toolkit prompt rollout version")
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                Ok(PromptRolloutInput {
                    scope: scope_for(config, &rollout.origin)?,
                    name: rollout.name.clone(),
                    salt: rollout.salt.clone(),
                    versions,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
    }
    input.agent_egress =
        config
            .egress
            .agent_orchestration
            .clone()
            .map(|authorizer| AgentEgressInput {
                authorizer,
                purpose: EgressPurpose::AgentOrchestration,
            });

    AiToolkitRuntime::validate(&input).context("invalid proxy.ai_toolkit configuration")?;
    AiToolkitRuntime::try_new(input).context("construct proxy.ai_toolkit runtime")
}

fn scope_for(config: &CompiledConfig, configured_origin: &str) -> anyhow::Result<ToolkitScope> {
    let origin = find_origin(config, configured_origin).ok_or_else(|| {
        anyhow::anyhow!(
            "proxy.ai_toolkit references unknown origin {:?}",
            bounded_identifier(configured_origin)
        )
    })?;
    ToolkitScope::new(origin.origin_id.to_string(), origin.tenant_id.to_string())
        .context("invalid proxy.ai_toolkit scope")
}

fn find_origin<'a>(
    config: &'a CompiledConfig,
    configured_origin: &str,
) -> Option<&'a CompiledOrigin> {
    config.origins.iter().find(|origin| {
        origin.origin_id.as_str() == configured_origin
            || origin.hostname.as_str() == configured_origin
    })
}

fn bounded_identifier(value: &str) -> String {
    value.chars().take(128).collect()
}

/// Overlay one configured override onto its runtime default.
///
/// An omitted field leaves the default in place, which is what makes
/// every key in `proxy.ai_toolkit.limits` optional.
fn apply_limit<T: Copy>(limit: &mut T, configured: Option<T>) {
    if let Some(value) = configured {
        *limit = value;
    }
}

/// Lower the optional `proxy.ai_toolkit.limits` overrides onto the runtime
/// defaults.
///
/// Every field is named twice, by hand. A macro over the field list is
/// shorter and was what this did, but the config-reader guard proves a
/// schema key is wired by finding a `configured.<field>` read in
/// production source, and a macro body is invisible to it, so the whole
/// `limits` subtree read as accepted-and-inert. Spelling the reads out is
/// what lets that guard see them.
fn lower_limits(configured: &sbproxy_config::types::AiToolkitLimitsConfig) -> AiToolkitLimits {
    let mut limits = AiToolkitLimits::default();
    apply_limit(&mut limits.max_agents, configured.max_agents);
    apply_limit(
        &mut limits.max_capabilities_per_agent,
        configured.max_capabilities_per_agent,
    );
    apply_limit(&mut limits.max_workflows, configured.max_workflows);
    apply_limit(&mut limits.max_datasets, configured.max_datasets);
    apply_limit(
        &mut limits.max_dataset_versions,
        configured.max_dataset_versions,
    );
    apply_limit(
        &mut limits.max_dataset_versions_total,
        configured.max_dataset_versions_total,
    );
    apply_limit(
        &mut limits.max_dataset_entries,
        configured.max_dataset_entries,
    );
    apply_limit(
        &mut limits.max_dataset_bytes_total,
        configured.max_dataset_bytes_total,
    );
    apply_limit(&mut limits.max_rollouts, configured.max_rollouts);
    apply_limit(
        &mut limits.max_rollout_versions,
        configured.max_rollout_versions,
    );
    apply_limit(
        &mut limits.max_retained_operations,
        configured.max_retained_operations,
    );
    apply_limit(&mut limits.max_request_bytes, configured.max_request_bytes);
    apply_limit(
        &mut limits.max_response_bytes,
        configured.max_response_bytes,
    );
    apply_limit(
        &mut limits.max_identifier_bytes,
        configured.max_identifier_bytes,
    );
    apply_limit(
        &mut limits.max_description_bytes,
        configured.max_description_bytes,
    );
    apply_limit(&mut limits.max_schema_bytes, configured.max_schema_bytes);
    apply_limit(&mut limits.max_secret_bytes, configured.max_secret_bytes);
    apply_limit(
        &mut limits.max_evaluation_cases,
        configured.max_evaluation_cases,
    );
    apply_limit(&mut limits.max_metrics, configured.max_metrics);
    apply_limit(
        &mut limits.max_judge_criteria,
        configured.max_judge_criteria,
    );
    apply_limit(&mut limits.agent_concurrency, configured.agent_concurrency);
    apply_limit(
        &mut limits.evaluation_concurrency,
        configured.evaluation_concurrency,
    );
    apply_limit(
        &mut limits.default_workflow_timeout_ms,
        configured.default_workflow_timeout_ms,
    );
    apply_limit(
        &mut limits.max_workflow_timeout_ms,
        configured.max_workflow_timeout_ms,
    );
    limits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_dataset_inventory_is_seeded_from_compiled_origins() {
        let config = sbproxy_config::compile_config(
            r#"
proxy:
  ai_toolkit:
    limits:
      max_dataset_versions_total: 1
origins:
  ai.example.test:
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
"#,
        )
        .expect("config compiles");
        let runtime = build(&config, false).expect("runtime builds");
        let known = ToolkitScope::new("ai.example.test", "__default__").expect("known scope");
        runtime
            .register_dataset(sbproxy_ai::toolkit::DatasetRegistrationRequest {
                scope: known,
                name: "answers".into(),
                version: 1,
                entries: Vec::new(),
            })
            .expect("compiled origin is eligible for dynamic registration");
        let error = runtime
            .register_dataset(sbproxy_ai::toolkit::DatasetRegistrationRequest {
                scope: ToolkitScope::new("ai.example.test", "__default__").expect("known scope"),
                name: "answers".into(),
                version: 2,
                entries: Vec::new(),
            })
            .expect_err("configured process-wide version limit is lowered");
        assert!(matches!(
            error,
            sbproxy_ai::toolkit::ToolkitError::LimitExceeded {
                resource: "dataset_versions_total",
                limit: 1,
                observed: 2
            }
        ));

        let unknown = ToolkitScope::new("other.example.test", "__default__")
            .expect("syntactically valid scope");
        let error = runtime
            .register_dataset(sbproxy_ai::toolkit::DatasetRegistrationRequest {
                scope: unknown,
                name: "answers".into(),
                version: 1,
                entries: Vec::new(),
            })
            .expect_err("uncompiled origin is refused");
        assert!(matches!(
            error,
            sbproxy_ai::toolkit::ToolkitError::NotFound {
                resource: "dataset_scope"
            }
        ));
    }
}
