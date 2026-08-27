//! Authenticated, tenant-scoped admin surface for the AI toolkit runtime.

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::time::{Duration, Instant};

use crate::admin::AdminPrincipal;

/// Maximum toolkit request body accepted by the hand-rolled admin listener.
pub(crate) const MAX_ADMIN_TOOLKIT_BODY_BYTES: usize = 256 * 1024;
const MAX_ADMIN_TOOLKIT_RESPONSE_BYTES: usize = 1024 * 1024;
// The runtime's authoritative offline evaluation deadline is 30 seconds.
// One extra second lets its final deadline check and bookkeeping complete
// without leaving the admin connection unbounded if blocking work wedges.
const ADMIN_EVALUATION_OUTER_TIMEOUT: Duration = Duration::from_secs(31);
// A timed-out blocking worker cannot be cancelled. Retain its join handle for
// one finite observation window so a late panic still receives its sole
// terminal metric without accumulating permanent async reapers.
const ADMIN_EVALUATION_REAPER_GRACE: Duration = Duration::from_secs(5);
const PREFIX: &str = "/admin/ai-toolkit/";
const JSON: &str = "application/json";

enum BlockingJoinOutcome<T> {
    Finished(T),
    JoinFailed,
    TimedOut(tokio::task::JoinHandle<T>),
}

/// Await one already-started blocking worker against a single absolute
/// deadline while retaining ownership of a worker that outlives the caller.
async fn await_blocking_until<T>(
    mut worker: tokio::task::JoinHandle<T>,
    deadline: tokio::time::Instant,
) -> BlockingJoinOutcome<T> {
    match tokio::time::timeout_at(deadline, &mut worker).await {
        Ok(Ok(value)) => BlockingJoinOutcome::Finished(value),
        Ok(Err(_)) => BlockingJoinOutcome::JoinFailed,
        Err(_) => BlockingJoinOutcome::TimedOut(worker),
    }
}

type EvaluationOperationResult =
    Result<sbproxy_ai::toolkit::EvaluationRunResult, sbproxy_ai::toolkit::ToolkitError>;

fn record_evaluation_join_failure() {
    sbproxy_ai::ai_metrics::record_ai_toolkit_operation(
        sbproxy_ai::ai_metrics::AiToolkitCapability::Evaluation,
        sbproxy_ai::ai_metrics::AiToolkitOutcome::Internal,
    );
}

/// Observe a timed-out worker for a finite grace period. Dropping a
/// `spawn_blocking` join handle only detaches the worker; it neither cancels
/// the work nor releases the runtime permit owned inside `run_evaluation`.
fn retain_timed_out_evaluation(worker: tokio::task::JoinHandle<EvaluationOperationResult>) {
    let _reaper = tokio::spawn(async move {
        match tokio::time::timeout(ADMIN_EVALUATION_REAPER_GRACE, worker).await {
            Ok(Ok(_)) => {
                // `run_evaluation` emitted the sole terminal metric.
            }
            Ok(Err(_)) => {
                // A panic cannot reach the runtime's terminal recorder. Do
                // not format the JoinError because its panic payload can
                // contain caller-controlled data.
                record_evaluation_join_failure();
            }
            Err(_) => {
                // The finite reaper now detaches the still-running worker.
                // Its runtime-owned permit remains held until it really exits;
                // its terminal metric is delayed or absent if it never does.
            }
        }
    });
}

/// Response returned to the admin connection handler.
#[derive(Debug)]
pub(crate) struct AdminToolkitResponse {
    /// HTTP status.
    pub(crate) status: u16,
    /// Content type.
    pub(crate) content_type: &'static str,
    /// Bounded JSON body.
    pub(crate) body: String,
}

/// Select an allocation cap as soon as the request line is available.
pub(crate) fn request_body_limit(request_line: &str) -> usize {
    let path = request_line
        .split_whitespace()
        .nth(1)
        .and_then(|path| path.split('?').next())
        .unwrap_or_default();
    if path.starts_with(PREFIX) {
        MAX_ADMIN_TOOLKIT_BODY_BYTES
    } else {
        sbproxy_model_host::MAX_BUNDLE_BYTES
    }
}

/// Record a refusal that occurs in the shared admin connection boundary,
/// before a trusted toolkit scope can be constructed.
pub(crate) fn record_boundary_outcome(
    path: &str,
    outcome: sbproxy_ai::ai_metrics::AiToolkitOutcome,
) {
    if let Some(capability) = route_metric_capability(path) {
        sbproxy_ai::ai_metrics::record_ai_toolkit_operation(capability, outcome);
    }
}

fn route_metric_capability(path: &str) -> Option<sbproxy_ai::ai_metrics::AiToolkitCapability> {
    use sbproxy_ai::ai_metrics::AiToolkitCapability;

    let route = path.split('?').next().unwrap_or(path);
    if route == "/admin/ai-toolkit/agents" || route.starts_with("/admin/ai-toolkit/workflows/") {
        Some(AiToolkitCapability::Workflow)
    } else if route.starts_with("/admin/ai-toolkit/datasets/")
        || route.starts_with("/admin/ai-toolkit/evaluations/")
    {
        Some(AiToolkitCapability::Evaluation)
    } else if route.starts_with("/admin/ai-toolkit/prompts/") {
        Some(AiToolkitCapability::PromptRollout)
    } else {
        // Snapshot is a visibility surface, not an operation capability.
        None
    }
}

/// Dispatch a toolkit admin route after the shared authentication, CSRF, and
/// role gates have run.
pub(crate) async fn dispatch(
    method: &str,
    path: &str,
    body: Option<&str>,
    principal: Option<&AdminPrincipal>,
) -> Option<AdminToolkitResponse> {
    let route = path.split('?').next().unwrap_or(path);
    if !route.starts_with(PREFIX) {
        return None;
    }
    let Some(principal) = principal else {
        record_boundary_outcome(
            route,
            sbproxy_ai::ai_metrics::AiToolkitOutcome::Unauthorized,
        );
        return Some(error_response(401, "authentication_required"));
    };
    if method.eq_ignore_ascii_case("POST")
        && principal.role == sbproxy_config::types::AdminRole::ReadOnly
    {
        record_boundary_outcome(
            route,
            sbproxy_ai::ai_metrics::AiToolkitOutcome::Unauthorized,
        );
        return Some(error_response(403, "mutation_forbidden"));
    }

    let pipeline = crate::reload::current_pipeline_full();
    let response = match (method, route) {
        (method, "/admin/ai-toolkit/agents") if method.eq_ignore_ascii_case("GET") => {
            let query = query_fields(path);
            let Some(origin) = query.get("origin") else {
                record_boundary_outcome(route, sbproxy_ai::ai_metrics::AiToolkitOutcome::Invalid);
                return Some(error_response(400, "origin_required"));
            };
            let scope = match scope_for_origin(&pipeline, origin, principal) {
                Ok(scope) => scope,
                Err(response) => {
                    record_response_outcome(route, &response);
                    return Some(response);
                }
            };
            let request = sbproxy_ai::toolkit::AgentDiscoveryRequest {
                scope,
                capability: query.get("capability").cloned(),
            };
            runtime_result(pipeline.ai_toolkit.discover_agents(request))
        }
        (method, "/admin/ai-toolkit/workflows/validate") if method.eq_ignore_ascii_case("POST") => {
            let request: sbproxy_ai::toolkit::WorkflowValidationRequest =
                match parse_scoped_body(body, &pipeline, principal, true) {
                    Ok(request) => request,
                    Err(response) => {
                        record_response_outcome(route, &response);
                        return Some(response);
                    }
                };
            audit(principal, &request.scope, method, route);
            runtime_result(pipeline.ai_toolkit.validate_workflow(request))
        }
        (method, "/admin/ai-toolkit/workflows/run") if method.eq_ignore_ascii_case("POST") => {
            let request: sbproxy_ai::toolkit::WorkflowRunRequest =
                match parse_scoped_body(body, &pipeline, principal, false) {
                    Ok(request) => request,
                    Err(response) => {
                        record_response_outcome(route, &response);
                        return Some(response);
                    }
                };
            audit(principal, &request.scope, method, route);
            let scope = request.scope.clone();
            let workflow = request.workflow.clone();
            let started = Instant::now();
            let result = pipeline.ai_toolkit.run_workflow(request).await;
            publish_workflow_operation(
                &pipeline,
                &scope,
                &workflow,
                &result,
                elapsed_millis(started),
            );
            match result {
                Ok(result) => json_body(&result),
                Err(error) => toolkit_error(error),
            }
        }
        (method, "/admin/ai-toolkit/datasets/register") if method.eq_ignore_ascii_case("POST") => {
            let request: sbproxy_ai::toolkit::DatasetRegistrationRequest =
                match parse_scoped_body(body, &pipeline, principal, false) {
                    Ok(request) => request,
                    Err(response) => {
                        record_response_outcome(route, &response);
                        return Some(response);
                    }
                };
            audit(principal, &request.scope, method, route);
            runtime_result(pipeline.ai_toolkit.register_dataset(request))
        }
        (method, "/admin/ai-toolkit/evaluations/run") if method.eq_ignore_ascii_case("POST") => {
            let request: sbproxy_ai::toolkit::EvaluationRunRequest =
                match parse_scoped_body(body, &pipeline, principal, false) {
                    Ok(request) => request,
                    Err(response) => {
                        record_response_outcome(route, &response);
                        return Some(response);
                    }
                };
            audit(principal, &request.scope, method, route);
            let scope = request.scope.clone();
            let dataset = request.dataset.clone();
            let experiment_id = request.experiment_id.clone();
            let started = Instant::now();
            let deadline = tokio::time::Instant::now() + ADMIN_EVALUATION_OUTER_TIMEOUT;
            let runtime = std::sync::Arc::clone(&pipeline.ai_toolkit);
            // `run_evaluation` acquires and owns its concurrency permit inside
            // this blocking worker. An admin timeout must not release a permit
            // while the synchronous evaluation is still using the thread.
            let worker = tokio::task::spawn_blocking(move || runtime.run_evaluation(request));
            match await_blocking_until(worker, deadline).await {
                BlockingJoinOutcome::Finished(result) => {
                    publish_evaluation_operation(
                        &pipeline,
                        &scope,
                        &dataset,
                        &experiment_id,
                        &result,
                        elapsed_millis(started),
                    );
                    runtime_result(result)
                }
                BlockingJoinOutcome::JoinFailed => {
                    record_evaluation_join_failure();
                    publish_evaluation_event(
                        &pipeline,
                        &scope,
                        &dataset,
                        &experiment_id,
                        sbproxy_observe::events::AiToolkitEventOutcome::Internal,
                        0,
                        elapsed_millis(started),
                    );
                    error_response(500, "operation_failed")
                }
                BlockingJoinOutcome::TimedOut(worker) => {
                    // Runtime owns the sole terminal metric and will emit its
                    // deadline outcome when the blocking worker returns. Core
                    // emits only the externally observed timeout event here.
                    publish_evaluation_event(
                        &pipeline,
                        &scope,
                        &dataset,
                        &experiment_id,
                        sbproxy_observe::events::AiToolkitEventOutcome::Timeout,
                        0,
                        elapsed_millis(started),
                    );
                    retain_timed_out_evaluation(worker);
                    error_response(504, "deadline_exceeded")
                }
            }
        }
        (method, "/admin/ai-toolkit/prompts/select") if method.eq_ignore_ascii_case("POST") => {
            let request: sbproxy_ai::toolkit::PromptSelectionRequest =
                match parse_scoped_body(body, &pipeline, principal, false) {
                    Ok(request) => request,
                    Err(response) => {
                        record_response_outcome(route, &response);
                        return Some(response);
                    }
                };
            audit(principal, &request.scope, method, route);
            let scope = request.scope.clone();
            match pipeline.ai_toolkit.select_prompt(request) {
                Ok(result) => {
                    publish_prompt_selection(&pipeline, &scope, &result);
                    json_body(&PromptAdminResult::from(result))
                }
                Err(error) => toolkit_error(error),
            }
        }
        (method, "/admin/ai-toolkit/snapshot") if method.eq_ignore_ascii_case("GET") => {
            let query = query_fields(path);
            let Some(origin) = query.get("origin") else {
                return Some(error_response(400, "origin_required"));
            };
            let scope = match scope_for_origin(&pipeline, origin, principal) {
                Ok(scope) => scope,
                Err(response) => return Some(response),
            };
            let limit = match query.get("limit") {
                Some(limit) => match limit.parse::<usize>() {
                    Ok(limit) => Some(limit),
                    Err(_) => return Some(error_response(400, "invalid_limit")),
                },
                None => None,
            };
            runtime_result(
                pipeline
                    .ai_toolkit
                    .snapshot(sbproxy_ai::toolkit::ToolkitSnapshotRequest { scope, limit }),
            )
        }
        _ => error_response(405, "method_not_allowed"),
    };
    Some(response)
}

fn record_response_outcome(route: &str, response: &AdminToolkitResponse) {
    use sbproxy_ai::ai_metrics::AiToolkitOutcome;

    let outcome = match response.status {
        401 | 403 => AiToolkitOutcome::Unauthorized,
        404 => AiToolkitOutcome::NotFound,
        413 => AiToolkitOutcome::BodyTooLarge,
        500..=599 => AiToolkitOutcome::Internal,
        _ => AiToolkitOutcome::Invalid,
    };
    record_boundary_outcome(route, outcome);
}

fn metric_outcome(
    error: &sbproxy_ai::toolkit::ToolkitError,
) -> sbproxy_ai::ai_metrics::AiToolkitOutcome {
    // One authoritative table lives beside the runtime; a second copy here
    // held the two label streams equal only by convention.
    sbproxy_ai::toolkit::error_metric_outcome(error)
}

fn event_outcome(
    error: &sbproxy_ai::toolkit::ToolkitError,
) -> sbproxy_observe::events::AiToolkitEventOutcome {
    use sbproxy_ai::ai_metrics::AiToolkitOutcome;
    use sbproxy_observe::events::AiToolkitEventOutcome as EventOutcome;

    match metric_outcome(error) {
        AiToolkitOutcome::Success => EventOutcome::Success,
        AiToolkitOutcome::Invalid => EventOutcome::Invalid,
        AiToolkitOutcome::Unauthorized => EventOutcome::Unauthorized,
        AiToolkitOutcome::NotFound => EventOutcome::NotFound,
        AiToolkitOutcome::EgressRefused => EventOutcome::EgressRefused,
        AiToolkitOutcome::Timeout => EventOutcome::Timeout,
        AiToolkitOutcome::BodyTooLarge => EventOutcome::BodyTooLarge,
        AiToolkitOutcome::ResponseTooLarge => EventOutcome::ResponseTooLarge,
        AiToolkitOutcome::Busy => EventOutcome::Busy,
        AiToolkitOutcome::AgentFailed => EventOutcome::AgentFailed,
        AiToolkitOutcome::Internal => EventOutcome::Internal,
    }
}

fn publish_workflow_operation(
    pipeline: &crate::pipeline::CompiledPipeline,
    scope: &sbproxy_ai::toolkit::ToolkitScope,
    workflow: &str,
    result: &Result<sbproxy_ai::toolkit::WorkflowRunResult, sbproxy_ai::toolkit::ToolkitError>,
    duration_ms: u64,
) {
    use sbproxy_observe::events::{AiToolkitEventOutcome, AiWorkflowOperationData};

    let (outcome, steps) = match result {
        Ok(result) => (AiToolkitEventOutcome::Success, result.steps.len()),
        Err(error) => (event_outcome(error), 0),
    };
    let event =
        AiWorkflowOperationData::new(&scope.origin_id, workflow, outcome, steps, duration_ms)
            .into_proxy_event(event_hostname(pipeline, scope), scope.tenant_id.clone());
    sbproxy_observe::publish_proxy_event(sbproxy_observe::EventType::AiWorkflowOperation, || event);
}

fn publish_evaluation_operation(
    pipeline: &crate::pipeline::CompiledPipeline,
    scope: &sbproxy_ai::toolkit::ToolkitScope,
    dataset: &sbproxy_ai::toolkit::DatasetRef,
    experiment_id: &str,
    result: &Result<sbproxy_ai::toolkit::EvaluationRunResult, sbproxy_ai::toolkit::ToolkitError>,
    duration_ms: u64,
) {
    use sbproxy_observe::events::AiToolkitEventOutcome;

    let (outcome, cases) = match result {
        Ok(result) => (AiToolkitEventOutcome::Success, result.cases),
        Err(error) => (event_outcome(error), 0),
    };
    publish_evaluation_event(
        pipeline,
        scope,
        dataset,
        experiment_id,
        outcome,
        cases,
        duration_ms,
    );
}

#[allow(clippy::too_many_arguments)]
fn publish_evaluation_event(
    pipeline: &crate::pipeline::CompiledPipeline,
    scope: &sbproxy_ai::toolkit::ToolkitScope,
    dataset: &sbproxy_ai::toolkit::DatasetRef,
    experiment_id: &str,
    outcome: sbproxy_observe::events::AiToolkitEventOutcome,
    cases: usize,
    duration_ms: u64,
) {
    use sbproxy_observe::events::AiEvaluationOperationData;

    let event = AiEvaluationOperationData::new(
        &scope.origin_id,
        &dataset.name,
        dataset.version,
        experiment_id,
        outcome,
        cases,
        duration_ms,
    )
    .into_proxy_event(event_hostname(pipeline, scope), scope.tenant_id.clone());
    sbproxy_observe::publish_proxy_event(sbproxy_observe::EventType::AiEvaluationOperation, || {
        event
    });
}

fn publish_prompt_selection(
    pipeline: &crate::pipeline::CompiledPipeline,
    scope: &sbproxy_ai::toolkit::ToolkitScope,
    result: &sbproxy_ai::toolkit::PromptSelectionResult,
) {
    use sbproxy_observe::events::{AiPromptRolloutSelectedData, AiToolkitEventOutcome};

    let Ok(data) = AiPromptRolloutSelectedData::new(
        &scope.origin_id,
        &result.name,
        result.version,
        AiToolkitEventOutcome::Success,
        &result.cohort_digest,
    ) else {
        return;
    };
    let event = data.into_proxy_event(event_hostname(pipeline, scope), scope.tenant_id.clone());
    sbproxy_observe::publish_proxy_event(
        sbproxy_observe::EventType::AiPromptRolloutSelected,
        || event,
    );
}

fn event_hostname(
    pipeline: &crate::pipeline::CompiledPipeline,
    scope: &sbproxy_ai::toolkit::ToolkitScope,
) -> String {
    pipeline
        .config
        .origins
        .iter()
        .find(|origin| origin.origin_id.as_str() == scope.origin_id)
        .map(|origin| origin.hostname.to_string())
        .unwrap_or_else(|| scope.origin_id.clone())
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn parse_scoped_body<T: DeserializeOwned>(
    body: Option<&str>,
    pipeline: &crate::pipeline::CompiledPipeline,
    principal: &AdminPrincipal,
    scope_nested_workflow: bool,
) -> Result<T, AdminToolkitResponse> {
    let raw = body.ok_or_else(|| error_response(400, "request_body_required"))?;
    if raw.len() > MAX_ADMIN_TOOLKIT_BODY_BYTES {
        return Err(error_response(413, "request_body_too_large"));
    }
    let mut value: serde_json::Value =
        serde_json::from_str(raw).map_err(|_| error_response(400, "invalid_json"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| error_response(400, "invalid_request"))?;
    let origin = object
        .remove("origin")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| error_response(400, "origin_required"))?;
    let scope = scope_for_origin(pipeline, &origin, principal)?;
    let scope_value =
        serde_json::to_value(&scope).map_err(|_| error_response(500, "operation_failed"))?;
    // A caller-supplied scope is discarded wholesale. Both tenant and
    // canonical origin come from the published config generation.
    object.insert("scope".to_string(), scope_value.clone());
    if scope_nested_workflow {
        let workflow = object
            .get_mut("workflow")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| error_response(400, "workflow_required"))?;
        workflow.insert("scope".to_string(), scope_value);
    }
    serde_json::from_value(value).map_err(|_| error_response(400, "invalid_request"))
}

fn scope_for_origin(
    pipeline: &crate::pipeline::CompiledPipeline,
    requested: &str,
    principal: &AdminPrincipal,
) -> Result<sbproxy_ai::toolkit::ToolkitScope, AdminToolkitResponse> {
    let Some(origin) = pipeline.config.origins.iter().find(|origin| {
        origin.origin_id.as_str() == requested || origin.hostname.as_str() == requested
    }) else {
        return Err(error_response(404, "origin_not_found"));
    };
    if principal
        .tenant
        .as_deref()
        .is_some_and(|tenant| tenant != origin.tenant_id.as_str())
    {
        return Err(error_response(403, "origin_outside_tenant_scope"));
    }
    sbproxy_ai::toolkit::ToolkitScope::new(
        origin.origin_id.to_string(),
        origin.tenant_id.to_string(),
    )
    .map_err(|_| error_response(400, "invalid_scope"))
}

fn query_fields(path: &str) -> std::collections::HashMap<String, String> {
    let Some((_, query)) = path.split_once('?') else {
        return std::collections::HashMap::new();
    };
    url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

fn runtime_result<T: Serialize>(
    result: Result<T, sbproxy_ai::toolkit::ToolkitError>,
) -> AdminToolkitResponse {
    match result {
        Ok(result) => json_body(&result),
        Err(error) => toolkit_error(error),
    }
}

fn json_body<T: Serialize>(value: &T) -> AdminToolkitResponse {
    match serde_json::to_string(value) {
        Ok(body) if body.len() <= MAX_ADMIN_TOOLKIT_RESPONSE_BYTES => AdminToolkitResponse {
            status: 200,
            content_type: JSON,
            body,
        },
        Ok(_) => error_response(500, "response_body_too_large"),
        Err(_) => error_response(500, "operation_failed"),
    }
}

fn toolkit_error(error: sbproxy_ai::toolkit::ToolkitError) -> AdminToolkitResponse {
    use sbproxy_ai::toolkit::ToolkitError;
    let (status, code) = match error {
        ToolkitError::NotFound { .. } => (404, "not_found"),
        ToolkitError::Duplicate { .. } => (409, "already_exists"),
        ToolkitError::LimitExceeded { resource, .. }
            if resource.contains("response") || resource.contains("output") =>
        {
            (502, "response_too_large")
        }
        ToolkitError::LimitExceeded { resource, .. }
            if resource.contains("request")
                || resource.contains("input")
                || resource.contains("body") =>
        {
            (413, "request_body_too_large")
        }
        ToolkitError::LimitExceeded { .. } => (400, "limit_exceeded"),
        ToolkitError::Busy { .. } => (429, "busy"),
        ToolkitError::Deadline { .. } => (504, "deadline_exceeded"),
        ToolkitError::GovernedEgress { .. }
        | ToolkitError::AgentRejected { .. }
        | ToolkitError::InvalidAgentResponse => (502, "agent_operation_failed"),
        ToolkitError::InvalidConfiguration { .. }
        | ToolkitError::InvalidSchema { .. }
        | ToolkitError::SchemaViolation { .. }
        | ToolkitError::InvalidJudgeResponse => (400, "invalid_request"),
        ToolkitError::Serialization => (500, "operation_failed"),
    };
    error_response(status, code)
}

fn error_response(status: u16, code: &'static str) -> AdminToolkitResponse {
    AdminToolkitResponse {
        status,
        content_type: JSON,
        body: serde_json::json!({"error": code}).to_string(),
    }
}

fn audit(
    principal: &AdminPrincipal,
    scope: &sbproxy_ai::toolkit::ToolkitScope,
    method: &str,
    route: &str,
) {
    sbproxy_observe::AdminActionAuditEntry::new(
        "ai_toolkit_admin_action",
        Some(principal.username.clone()),
        Some(scope.tenant_id.clone()),
        None,
        None,
        Some(format!("{method} {route}")),
    )
    .emit();
}

#[derive(Serialize)]
struct PromptAdminResult {
    name: String,
    version: u32,
    weight: f64,
    cohort_digest: String,
}

impl From<sbproxy_ai::toolkit::PromptSelectionResult> for PromptAdminResult {
    fn from(result: sbproxy_ai::toolkit::PromptSelectionResult) -> Self {
        Self {
            name: result.name,
            version: result.version,
            weight: result.weight,
            cohort_digest: result.cohort_digest,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant_pipeline() -> crate::pipeline::CompiledPipeline {
        let compiled = sbproxy_config::compile_config(
            r#"
proxy:
  tenants:
    - id: tenant-a
origins:
  ai.test:
    tenant_id: tenant-a
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
"#,
        )
        .expect("tenant config compiles");
        crate::pipeline::CompiledPipeline::from_config_for_validation(compiled)
            .expect("pipeline validates")
    }

    fn principal(tenant: Option<&str>) -> AdminPrincipal {
        AdminPrincipal {
            username: "operator".into(),
            role: sbproxy_config::types::AdminRole::Admin,
            via_session: false,
            csrf: None,
            tenant: tenant.map(str::to_owned),
        }
    }

    #[test]
    fn toolkit_route_has_a_small_preallocation_body_limit() {
        assert_eq!(
            request_body_limit("POST /admin/ai-toolkit/workflows/run HTTP/1.1"),
            MAX_ADMIN_TOOLKIT_BODY_BYTES
        );
        assert_eq!(
            request_body_limit("POST /admin/model-host/models HTTP/1.1"),
            sbproxy_model_host::MAX_BUNDLE_BYTES
        );
    }

    #[test]
    fn toolkit_limit_errors_keep_request_response_and_quota_statuses_distinct() {
        use sbproxy_ai::toolkit::ToolkitError;

        let response = toolkit_error(ToolkitError::LimitExceeded {
            resource: "workflow_response_bytes",
            limit: 1,
            observed: 2,
        });
        let request = toolkit_error(ToolkitError::LimitExceeded {
            resource: "workflow_input_bytes",
            limit: 1,
            observed: 2,
        });
        let quota = toolkit_error(ToolkitError::LimitExceeded {
            resource: "evaluation_cases",
            limit: 1,
            observed: 2,
        });
        assert_eq!(response.status, 502);
        assert_eq!(request.status, 413);
        assert_eq!(quota.status, 400);
        assert_eq!(toolkit_error(ToolkitError::Serialization).status, 500);
    }

    #[test]
    fn workflow_admin_result_returns_the_bounded_validated_output() {
        let result = sbproxy_ai::toolkit::WorkflowRunResult {
            workflow: "flow".into(),
            completed: true,
            final_state: "done".into(),
            output: serde_json::json!({"secret": "must-not-escape"}),
            steps: Vec::new(),
        };
        let body = json_body(&result);
        assert_eq!(body.status, 200);
        assert!(body.body.contains("must-not-escape"));
        assert!(body.body.contains("output"));
    }

    #[test]
    fn prompt_admin_result_never_serializes_prompt_content() {
        let result = sbproxy_ai::toolkit::PromptSelectionResult {
            name: "system".into(),
            version: 2,
            content: "private prompt".into(),
            weight: 3.0,
            cohort_digest: "a".repeat(64),
        };
        let body = json_body(&PromptAdminResult::from(result));
        assert_eq!(body.status, 200);
        assert!(!body.body.contains("private prompt"));
        assert!(!body.body.contains("content"));
        let digest = "a".repeat(64);
        assert!(body.body.contains(digest.as_str()));
    }

    #[test]
    fn body_scope_is_replaced_with_the_compiled_origin_scope() {
        let pipeline = tenant_pipeline();
        let request: sbproxy_ai::toolkit::WorkflowRunRequest = parse_scoped_body(
            Some(
                r#"{"origin":"ai.test","scope":{"origin_id":"other","tenant_id":"tenant-b"},"workflow":"flow","input":{}}"#,
            ),
            &pipeline,
            &principal(Some("tenant-a")),
            false,
        )
        .expect("own origin is allowed");
        assert_eq!(request.scope.origin_id, "ai.test");
        assert_eq!(request.scope.tenant_id, "tenant-a");
    }

    #[test]
    fn tenant_operator_cannot_address_another_tenants_origin() {
        let pipeline = tenant_pipeline();
        let response = scope_for_origin(&pipeline, "ai.test", &principal(Some("tenant-b")))
            .expect_err("cross-tenant origin must be refused");
        assert_eq!(response.status, 403);
        assert!(!response.body.contains("tenant-a"));
        assert!(!response.body.contains("tenant-b"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_deadline_returns_while_the_owned_worker_can_finish() {
        let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let worker_permits = std::sync::Arc::clone(&permits);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker = tokio::task::spawn_blocking(move || {
            let permit = worker_permits
                .try_acquire_owned()
                .expect("worker owns the evaluation permit");
            started_tx.send(()).expect("signal worker start");
            release_rx.recv().expect("release worker");
            drop(permit);
            7_u8
        });
        started_rx.await.expect("worker reaches its owned section");
        assert_eq!(permits.available_permits(), 0);

        let wait_started = tokio::time::Instant::now();
        let outcome =
            await_blocking_until(worker, wait_started + std::time::Duration::from_millis(25)).await;
        let BlockingJoinOutcome::TimedOut(worker) = outcome else {
            panic!("blocked worker must reach the outer deadline");
        };
        assert!(
            wait_started.elapsed() < std::time::Duration::from_millis(500),
            "outer handler wait must remain bounded"
        );
        assert_eq!(
            permits.available_permits(),
            0,
            "timing out the waiter must not release a worker-owned permit"
        );

        release_tx
            .send(())
            .expect("allow detached worker to finish");
        let value = tokio::time::timeout(std::time::Duration::from_secs(1), worker)
            .await
            .expect("owned worker finishes after release")
            .expect("owned worker joins cleanly");
        assert_eq!(value, 7);
        assert_eq!(permits.available_permits(), 1);
    }

    #[tokio::test]
    async fn blocking_deadline_keeps_join_failure_distinct_from_timeout() {
        let worker = tokio::spawn(async {
            std::future::pending::<()>().await;
            7_u8
        });
        worker.abort();

        let outcome = await_blocking_until(
            worker,
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .await;
        assert!(matches!(outcome, BlockingJoinOutcome::JoinFailed));
    }
}
