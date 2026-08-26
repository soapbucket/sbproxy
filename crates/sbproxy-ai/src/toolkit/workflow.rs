use std::time::Duration;
use std::{net::SocketAddr, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::agent_orchestration::{generate_agent_token, FsmExecution, FsmWorkflow};
use crate::ai_metrics::{record_ai_toolkit_operation, AiToolkitCapability, AiToolkitOutcome};
use sbproxy_security::egress::HostResolver;
use sbproxy_security::governed_egress::GovernedEgress;
use zeroize::Zeroizing;

use super::runtime::metric_outcome;
use super::validation::{ensure_count, ensure_serialized, validate_identifier, validate_scope};
use super::{
    AiToolkitRuntime, ToolkitError, WorkflowRunRequest, WorkflowRunResult, WorkflowStepSummary,
    WorkflowValidationRequest, WorkflowValidationResult,
};

const SENSITIVE_AGENT_HEADERS: [&str; 1] = ["x-sbproxy-agent-id"];
const MAX_AGENT_DNS_ADDRESSES: usize = 64;

/// One asynchronously resolved endpoint answer, replayed synchronously into
/// the authorize-and-pin gate. The workflow's outer Tokio deadline can cancel
/// `lookup_host`; the gate itself then performs only bounded in-memory reads.
struct ResolvedAgentHost {
    host: String,
    port: u16,
    addrs: Result<Arc<[SocketAddr]>, ()>,
}

impl ResolvedAgentHost {
    async fn resolve(endpoint: &str) -> Result<Self, ToolkitError> {
        let parsed = url::Url::parse(endpoint).map_err(|_| ToolkitError::InvalidConfiguration {
            field: "agent.endpoint",
        })?;
        let parsed_host = parsed.host().ok_or(ToolkitError::InvalidConfiguration {
            field: "agent.endpoint",
        })?;
        let host = parsed
            .host_str()
            .ok_or(ToolkitError::InvalidConfiguration {
                field: "agent.endpoint",
            })?
            .to_string();
        let port = parsed
            .port_or_known_default()
            .ok_or(ToolkitError::InvalidConfiguration {
                field: "agent.endpoint",
            })?;
        let addrs = match parsed_host {
            url::Host::Ipv4(address) => Ok(Arc::<[SocketAddr]>::from([SocketAddr::new(
                address.into(),
                port,
            )])),
            url::Host::Ipv6(address) => Ok(Arc::<[SocketAddr]>::from([SocketAddr::new(
                address.into(),
                port,
            )])),
            url::Host::Domain(domain) => resolve_domain(domain, port).await,
        };
        Ok(Self { host, port, addrs })
    }
}

async fn resolve_domain(host: &str, port: u16) -> Result<Arc<[SocketAddr]>, ()> {
    match tokio::net::lookup_host((host, port)).await {
        Ok(resolved) => {
            let mut addrs = Vec::new();
            for address in resolved {
                if !addrs.contains(&address) {
                    addrs.push(address);
                }
                if addrs.len() > MAX_AGENT_DNS_ADDRESSES {
                    break;
                }
            }
            if addrs.is_empty() || addrs.len() > MAX_AGENT_DNS_ADDRESSES {
                Err(())
            } else {
                Ok(Arc::<[SocketAddr]>::from(addrs))
            }
        }
        Err(_) => Err(()),
    }
}

impl HostResolver for ResolvedAgentHost {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, ()> {
        if !self.host.eq_ignore_ascii_case(host) || self.port != port {
            return Err(());
        }
        self.addrs
            .as_ref()
            .map(|addrs| addrs.to_vec())
            .map_err(|_| ())
    }
}

#[cfg(test)]
mod resolver_tests {
    use std::net::{Ipv6Addr, SocketAddr};

    use sbproxy_security::egress::HostResolver as _;

    use super::ResolvedAgentHost;

    #[tokio::test]
    async fn ipv6_literal_is_resolved_without_a_dns_lookup() {
        let resolved = ResolvedAgentHost::resolve("http://[::1]:4317/invoke")
            .await
            .expect("valid IPv6 endpoint");

        assert_eq!(
            resolved.resolve("[::1]", 4317).expect("literal answer"),
            vec![SocketAddr::from((Ipv6Addr::LOCALHOST, 4317))]
        );
    }
}

#[derive(Serialize)]
struct AgentWireRequest<'a> {
    workflow: &'a str,
    state: &'a str,
    capability: &'a str,
    input: &'a Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentWireResponse {
    outcome: String,
    output: Value,
}

impl AiToolkitRuntime {
    /// Validate a candidate workflow against bounds and scoped capabilities without execution.
    pub fn validate_workflow(
        &self,
        request: WorkflowValidationRequest,
    ) -> Result<WorkflowValidationResult, ToolkitError> {
        let scope = request.scope.clone();
        let result = self.validate_workflow_inner(request);
        self.record_operation(
            scope,
            "workflow_validation",
            metric_outcome(&result).as_label(),
        );
        record_ai_toolkit_operation(AiToolkitCapability::Workflow, metric_outcome(&result));
        result
    }

    fn validate_workflow_inner(
        &self,
        request: WorkflowValidationRequest,
    ) -> Result<WorkflowValidationResult, ToolkitError> {
        validate_scope(&request.scope, &self.limits)?;
        validate_scope(&request.workflow.scope, &self.limits)?;
        if request.scope != request.workflow.scope {
            return Err(ToolkitError::InvalidConfiguration {
                field: "workflow_validation.scope",
            });
        }
        validate_identifier(
            &request.workflow.name,
            "workflow.name",
            self.limits.max_identifier_bytes,
        )?;
        validate_identifier(
            &request.workflow.initial_state,
            "workflow.initial_state",
            self.limits.max_identifier_bytes,
        )?;
        if request.workflow.timeout_ms == 0
            || request.workflow.timeout_ms > self.limits.max_workflow_timeout_ms
        {
            return Err(ToolkitError::InvalidConfiguration {
                field: "workflow.timeout_ms",
            });
        }
        ensure_serialized(
            &request.workflow,
            "workflow_definition_bytes",
            self.limits.max_request_bytes,
        )?;
        let scoped_agents = self
            .agents
            .get(&request.scope)
            .ok_or(ToolkitError::NotFound { resource: "agent" })?;
        for state in &request.workflow.states {
            validate_identifier(
                &state.action,
                "workflow.state.action",
                self.limits.max_identifier_bytes,
            )?;
            if scoped_agents
                .registry
                .find_by_capability(&state.action)
                .is_empty()
            {
                return Err(ToolkitError::NotFound {
                    resource: "agent_capability",
                });
            }
        }
        FsmWorkflow::new(
            request.workflow.name.as_str(),
            request.workflow.initial_state.as_str(),
            request.workflow.states,
            request.workflow.max_steps,
        )
        .map_err(|_| ToolkitError::InvalidConfiguration {
            field: "workflow.graph",
        })?;
        Ok(WorkflowValidationResult { valid: true })
    }

    /// Execute one configured FSM through governed, authenticated agent calls.
    pub async fn run_workflow(
        &self,
        request: WorkflowRunRequest,
    ) -> Result<WorkflowRunResult, ToolkitError> {
        let scope = request.scope.clone();
        let permit = match self.agent_semaphore.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                self.record_operation(
                    scope,
                    "agent_workflow",
                    AiToolkitOutcome::Internal.as_label(),
                );
                record_ai_toolkit_operation(
                    AiToolkitCapability::Workflow,
                    AiToolkitOutcome::Internal,
                );
                return Err(ToolkitError::Busy {
                    operation: "agent_workflow",
                });
            }
        };
        let timeout_ms = self
            .workflows
            .get(&(request.scope.clone(), request.workflow.clone()))
            .map(|workflow| workflow.timeout_ms)
            .unwrap_or(self.limits.default_workflow_timeout_ms);
        let result = tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            self.run_workflow_inner(request),
        )
        .await
        .map_err(|_| ToolkitError::Deadline {
            operation: "agent_workflow",
        })
        .and_then(|result| result);
        drop(permit);
        self.record_operation(scope, "agent_workflow", metric_outcome(&result).as_label());
        record_ai_toolkit_operation(AiToolkitCapability::Workflow, metric_outcome(&result));
        result
    }

    async fn run_workflow_inner(
        &self,
        request: WorkflowRunRequest,
    ) -> Result<WorkflowRunResult, ToolkitError> {
        validate_scope(&request.scope, &self.limits)?;
        validate_identifier(
            &request.workflow,
            "workflow_run.workflow",
            self.limits.max_identifier_bytes,
        )?;
        ensure_serialized(
            &request.input,
            "workflow_input_bytes",
            self.limits.max_request_bytes,
        )?;
        let workflow = self
            .workflows
            .get(&(request.scope.clone(), request.workflow.clone()))
            .cloned()
            .ok_or(ToolkitError::NotFound {
                resource: "workflow",
            })?;
        let scoped_agents = self
            .agents
            .get(&request.scope)
            .ok_or(ToolkitError::NotFound { resource: "agent" })?;
        let egress = self
            .agent_egress
            .as_ref()
            .ok_or(ToolkitError::InvalidConfiguration {
                field: "agent_egress",
            })?;

        let max_steps = workflow.workflow.max_steps();
        let mut execution = FsmExecution::new(workflow.workflow);
        let mut payload = request.input;
        let mut steps = Vec::with_capacity(execution.history().len().max(1));
        let mut final_state = execution.current_state().to_string();

        loop {
            // Reserve the state invocation before validation, resolution,
            // authentication, or transport. The FSM records a step only when
            // its outcome transitions, which is too late to prevent the next
            // state in a cycle from producing an externally visible call.
            ensure_count("workflow_steps", steps.len().saturating_add(1), max_steps)?;
            let state = execution.current_state().to_string();
            let capability_name = execution.current_action().to_string();
            let mut candidate_ids = scoped_agents.registry.find_by_capability(&capability_name);
            candidate_ids.sort();
            let agent_id = candidate_ids
                .into_iter()
                .next()
                .ok_or(ToolkitError::NotFound {
                    resource: "agent_capability",
                })?;
            let agent = scoped_agents
                .agents
                .get(&agent_id)
                .ok_or(ToolkitError::NotFound { resource: "agent" })?;
            let capability =
                agent
                    .capabilities
                    .get(&capability_name)
                    .ok_or(ToolkitError::NotFound {
                        resource: "agent_capability",
                    })?;
            if !capability.input.is_valid(&payload) {
                return Err(ToolkitError::SchemaViolation {
                    boundary: "agent_input",
                });
            }

            let wire = AgentWireRequest {
                workflow: &request.workflow,
                state: &state,
                capability: &capability_name,
                input: &payload,
            };
            let body = serde_json::to_vec(&wire).map_err(|_| ToolkitError::Serialization)?;
            ensure_count(
                "agent_request_bytes",
                body.len(),
                self.limits.max_request_bytes,
            )?;
            let resolver = ResolvedAgentHost::resolve(&agent.endpoint).await?;
            let token = Zeroizing::new(generate_agent_token(
                &agent_id,
                agent.shared_secret.expose(),
            ));
            let outbound = self
                .no_redirect_client
                .post(&agent.endpoint)
                .header("x-sbproxy-agent-id", &agent_id)
                .bearer_auth(token.as_str())
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body)
                .build()
                .map_err(|_| ToolkitError::InvalidConfiguration {
                    field: "agent.request",
                })?;
            drop(token);
            let governed = GovernedEgress {
                purpose: egress.purpose,
                authorizer: Some(&egress.authorizer),
                resolver: &resolver,
                origin: &request.scope.origin_id,
                tenant: &request.scope.tenant_id,
                sensitive_headers: &SENSITIVE_AGENT_HEADERS,
                max_response_bytes: self.limits.max_response_bytes,
                no_redirect_client: &self.no_redirect_client,
                // The outer timeout is the authoritative whole-workflow
                // deadline. This larger subordinate call ceiling prevents a
                // slow hop from racing it into an opaque transport label.
                timeout: Duration::from_millis(self.limits.max_workflow_timeout_ms),
            };
            let response =
                governed
                    .send(outbound)
                    .await
                    .map_err(|error| ToolkitError::GovernedEgress {
                        reason: error.as_label(),
                    })?;
            if !(200..300).contains(&response.status) {
                return Err(ToolkitError::AgentRejected {
                    status: response.status,
                });
            }
            let wire: AgentWireResponse = serde_json::from_slice(&response.body)
                .map_err(|_| ToolkitError::InvalidAgentResponse)?;
            validate_identifier(
                &wire.outcome,
                "agent_response.outcome",
                self.limits.max_identifier_bytes,
            )?;
            if !capability.output.is_valid(&wire.output) {
                return Err(ToolkitError::SchemaViolation {
                    boundary: "agent_output",
                });
            }
            ensure_serialized(
                &wire.output,
                "agent_output_bytes",
                self.limits.max_response_bytes,
            )?;

            final_state.clone_from(&state);
            steps.push(WorkflowStepSummary {
                state,
                capability: capability_name,
                outcome: wire.outcome.clone(),
                agent_id,
            });
            payload = wire.output;
            execution
                .transition(&wire.outcome)
                .map_err(|_| ToolkitError::InvalidAgentResponse)?;
            if execution.is_completed() {
                break;
            }
        }

        let result = WorkflowRunResult {
            workflow: request.workflow,
            completed: execution.is_completed(),
            final_state,
            output: payload,
            steps,
        };
        ensure_serialized(
            &result,
            "workflow_response_bytes",
            self.limits.max_response_bytes,
        )?;
        Ok(result)
    }
}
