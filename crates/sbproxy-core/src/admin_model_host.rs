// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Model-host status admin API (WOR-1665).
//!
//! `GET /admin/model-host/status` reports what the local model host is
//! running right now: resident models with their engine state, bound
//! port, VRAM estimate, and configured `keep_alive`, plus the residency
//! budget and per-device VRAM. Read-only; it sits behind the admin
//! server's shared auth gate like every other `/admin/*` route.
//!
//! This is the "what is running now" half of WOR-1665. The
//! "value-delivered / dollars-saved" half needs a per-completion lane +
//! savings recorder on the request path (none exists yet), so it is a
//! separate slice.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::server::model_host::{
    AdminDeploymentRevisionError, AdminDeploymentRevisionResult, ModelManagementSnapshot,
    ProductionModelRuntime,
};

type Resp = (u16, &'static str, String);

const JSON: &str = "application/json";

const MANAGEMENT_SCHEMA_VERSION: u32 = 1;

trait ModelManagementRuntime {
    fn active_catalog(&self) -> Arc<sbproxy_model_host::Catalog>;

    fn management_snapshot(&self) -> Result<ModelManagementSnapshot, AdminDeploymentRevisionError>;

    fn apply_admin_deployment_revision(
        &self,
        expected_revision: Option<u64>,
        deployments: BTreeMap<String, sbproxy_model_host::ModelDeployment>,
    ) -> Result<AdminDeploymentRevisionResult, AdminDeploymentRevisionError>;
}

impl ModelManagementRuntime for ProductionModelRuntime {
    fn active_catalog(&self) -> Arc<sbproxy_model_host::Catalog> {
        ProductionModelRuntime::active_catalog(self)
    }

    fn management_snapshot(&self) -> Result<ModelManagementSnapshot, AdminDeploymentRevisionError> {
        ProductionModelRuntime::management_snapshot(self)
    }

    fn apply_admin_deployment_revision(
        &self,
        expected_revision: Option<u64>,
        deployments: BTreeMap<String, sbproxy_model_host::ModelDeployment>,
    ) -> Result<AdminDeploymentRevisionResult, AdminDeploymentRevisionError> {
        tokio::runtime::Handle::current().block_on(
            ProductionModelRuntime::apply_admin_deployment_revision(
                self,
                expected_revision,
                deployments,
            ),
        )
    }
}

#[derive(Debug, Serialize)]
struct CatalogResponse {
    schema_version: u32,
    catalog_revision: String,
    models: BTreeMap<String, CatalogModelMetadata>,
}

#[derive(Debug, Serialize)]
struct CatalogModelMetadata {
    params: String,
    license: String,
    family: String,
    context_length: u64,
    variants: Vec<CatalogVariantMetadata>,
}

#[derive(Debug, Serialize)]
struct CatalogVariantMetadata {
    id: String,
    format: sbproxy_model_host::ArtifactFormat,
    quant: String,
    engines: Vec<sbproxy_model_host::EngineKind>,
    accelerators: BTreeSet<sbproxy_model_host::AcceleratorKind>,
    min_memory_bytes: u64,
    download_size_bytes: u64,
    certification: String,
    stability: sbproxy_model_host::SupportLevel,
}

#[derive(Debug, Serialize)]
struct DeploymentsResponse {
    schema_version: u32,
    authority: sbproxy_config::ModelHostAuthority,
    read_only: bool,
    revision: Option<u64>,
    content_digest: Option<String>,
    deployments: BTreeMap<String, sbproxy_model_host::ModelDeployment>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentPutRequest {
    expected_revision: serde_json::Value,
    #[serde(deserialize_with = "deserialize_unique_btree_map")]
    deployments: BTreeMap<String, StrictModelDeployment>,
}

fn deserialize_unique_btree_map<'de, D, K, V>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    K: serde::Deserialize<'de> + Ord,
    V: serde::Deserialize<'de>,
{
    struct UniqueMap<K, V>(std::marker::PhantomData<(K, V)>);

    impl<'de, K, V> serde::de::Visitor<'de> for UniqueMap<K, V>
    where
        K: serde::Deserialize<'de> + Ord,
        V: serde::Deserialize<'de>,
    {
        type Value = BTreeMap<K, V>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a map with unique keys")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut values = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<K, V>()? {
                if values.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate map key"));
                }
            }
            Ok(values)
        }
    }

    deserializer.deserialize_map(UniqueMap(std::marker::PhantomData))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictModelDeployment {
    model: String,
    #[serde(default)]
    variant: Option<String>,
    #[serde(default)]
    heterogeneous_variants: bool,
    #[serde(default = "one_replica")]
    replicas: u32,
    #[serde(default, deserialize_with = "deserialize_unique_btree_map")]
    required_labels: BTreeMap<String, String>,
    #[serde(default)]
    spread_by: Vec<String>,
    #[serde(default)]
    pull: sbproxy_model_host::PullPolicy,
    #[serde(default)]
    warm: bool,
    #[serde(default)]
    keep_alive_secs: Option<u64>,
    #[serde(default)]
    max_concurrency: Option<u32>,
    #[serde(default = "default_max_queue_depth")]
    max_queue_depth: usize,
    #[serde(default = "default_queue_timeout_ms")]
    queue_timeout_ms: u64,
    #[serde(default)]
    engine: sbproxy_model_host::EngineChoice,
    #[serde(default)]
    rollout: sbproxy_model_host::RolloutPolicy,
}

impl From<StrictModelDeployment> for sbproxy_model_host::ModelDeployment {
    fn from(deployment: StrictModelDeployment) -> Self {
        Self {
            model: deployment.model,
            variant: deployment.variant,
            heterogeneous_variants: deployment.heterogeneous_variants,
            replicas: deployment.replicas,
            required_labels: deployment.required_labels,
            spread_by: deployment.spread_by,
            pull: deployment.pull,
            warm: deployment.warm,
            keep_alive_secs: deployment.keep_alive_secs,
            max_concurrency: deployment.max_concurrency,
            max_queue_depth: deployment.max_queue_depth,
            queue_timeout_ms: deployment.queue_timeout_ms,
            engine: deployment.engine,
            rollout: deployment.rollout,
        }
    }
}

const fn one_replica() -> u32 {
    1
}

const fn default_max_queue_depth() -> usize {
    128
}

const fn default_queue_timeout_ms() -> u64 {
    30_000
}

#[derive(Debug, Serialize)]
struct DeploymentPutResponse {
    schema_version: u32,
    revision: u64,
    content_digest: String,
    plan: sbproxy_model_host::ReconcilePlan,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    code: &'static str,
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actual_revision: Option<u64>,
}

fn error_response(status: u16, code: &'static str, error: impl Into<String>) -> Resp {
    json_response(
        status,
        &ErrorResponse {
            code,
            error: error.into(),
            expected_revision: None,
            actual_revision: None,
        },
    )
}

fn json_response(status: u16, value: &impl Serialize) -> Resp {
    match serde_json::to_string(value) {
        Ok(body) => (status, JSON, body),
        Err(error) => {
            tracing::error!(%error, "serialize model management response");
            (
                500,
                JSON,
                r#"{"code":"internal","error":"model management response failed"}"#.to_string(),
            )
        }
    }
}

fn bounded_metadata(value: &str) -> String {
    value.chars().take(256).collect()
}

fn catalog_response(runtime: &impl ModelManagementRuntime) -> Resp {
    let catalog = runtime.active_catalog();
    let models = catalog
        .models
        .iter()
        .map(|(id, entry)| {
            let variants = entry
                .variants
                .iter()
                .map(|variant| {
                    let download_size_bytes = variant
                        .files
                        .iter()
                        .try_fold(0u64, |total, file| total.checked_add(file.size_bytes))?;
                    Some(CatalogVariantMetadata {
                        id: variant.id.clone(),
                        format: variant.format,
                        quant: bounded_metadata(&variant.quant),
                        engines: variant.engines.clone(),
                        accelerators: variant.requirements.accelerators.clone(),
                        min_memory_bytes: variant.requirements.min_memory_bytes,
                        download_size_bytes,
                        certification: bounded_metadata(&variant.certification),
                        stability: variant.stability,
                    })
                })
                .collect::<Option<Vec<_>>>()?;
            Some((
                id.clone(),
                CatalogModelMetadata {
                    params: bounded_metadata(&entry.params),
                    license: bounded_metadata(&entry.license),
                    family: bounded_metadata(&entry.family),
                    context_length: entry.context_length,
                    variants,
                },
            ))
        })
        .collect::<Option<BTreeMap<_, _>>>();
    let Some(models) = models else {
        tracing::error!("model catalog variant download size overflow");
        return error_response(500, "internal", "model catalog metadata unavailable");
    };
    json_response(
        200,
        &CatalogResponse {
            schema_version: MANAGEMENT_SCHEMA_VERSION,
            catalog_revision: catalog.catalog_revision.clone(),
            models,
        },
    )
}

fn deployments_get_response(runtime: &impl ModelManagementRuntime) -> Resp {
    match runtime.management_snapshot() {
        Ok(snapshot) => json_response(
            200,
            &DeploymentsResponse {
                schema_version: MANAGEMENT_SCHEMA_VERSION,
                authority: snapshot.authority,
                read_only: snapshot.read_only,
                revision: snapshot.revision,
                content_digest: snapshot.content_digest,
                deployments: snapshot.deployments,
            },
        ),
        Err(error) => admin_revision_error_response(error),
    }
}

fn deployments_put_response(runtime: &impl ModelManagementRuntime, body: Option<&str>) -> Resp {
    let before = match runtime.management_snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => return admin_revision_error_response(error),
    };
    if before.read_only || before.authority != sbproxy_config::ModelHostAuthority::AdminManaged {
        return error_response(
            403,
            "authority_read_only",
            "model host authority does not allow local admin mutation",
        );
    }
    let Some(body) = body.filter(|body| !body.trim().is_empty()) else {
        return error_response(400, "invalid_body", "deployment revision body is required");
    };
    let request = match serde_json::from_str::<DeploymentPutRequest>(body) {
        Ok(request) => request,
        Err(error) => {
            return error_response(
                400,
                "invalid_body",
                format!("invalid deployment revision body: {error}"),
            )
        }
    };
    let expected_revision = match request.expected_revision {
        serde_json::Value::Null => None,
        serde_json::Value::Number(value) => match value.as_u64() {
            Some(value) => Some(value),
            None => {
                return error_response(
                    400,
                    "invalid_body",
                    "expected_revision must be null or an unsigned integer",
                )
            }
        },
        _ => {
            return error_response(
                400,
                "invalid_body",
                "expected_revision must be null or an unsigned integer",
            )
        }
    };
    let deployments = request
        .deployments
        .into_iter()
        .map(|(id, deployment)| (id, deployment.into()))
        .collect::<BTreeMap<_, _>>();
    let catalog = runtime.active_catalog();
    let draft = sbproxy_model_host::DeploymentRevisionDraft {
        source_mode: sbproxy_model_host::DeploymentSourceMode::AdminManaged,
        source_revision: "admin-api".to_string(),
        catalog_revision: catalog.catalog_revision.clone(),
        deployments,
    };
    if let Err(error) = draft.validate() {
        return error_response(400, "invalid_desired", error.to_string());
    }
    for (deployment_id, deployment) in &draft.deployments {
        let Some(entry) = catalog.get(&deployment.model) else {
            return error_response(
                400,
                "unknown_catalog_model",
                format!(
                    "deployment {deployment_id:?} references unknown catalog model {:?}",
                    deployment.model
                ),
            );
        };
        if let Some(variant) = deployment.variant.as_ref() {
            if !entry
                .variants
                .iter()
                .any(|candidate| candidate.id == *variant)
            {
                return error_response(
                    400,
                    "unknown_catalog_variant",
                    format!(
                        "deployment {deployment_id:?} references unknown catalog variant {variant:?}"
                    ),
                );
            }
        }
    }
    let deployment_count = draft.deployments.len();
    match runtime.apply_admin_deployment_revision(expected_revision, draft.deployments) {
        Ok(result) => {
            tracing::info!(
                target: "sbproxy::admin::audit",
                action = "model_deployments_replace",
                source_mode = "admin_managed",
                prior_revision = ?expected_revision,
                next_revision = result.revision,
                content_digest = %result.content_digest,
                deployment_count,
                "admin model deployment revision committed"
            );
            json_response(
                200,
                &DeploymentPutResponse {
                    schema_version: MANAGEMENT_SCHEMA_VERSION,
                    revision: result.revision,
                    content_digest: result.content_digest,
                    plan: result.plan,
                },
            )
        }
        Err(error) => admin_revision_error_response(error),
    }
}

fn admin_revision_error_response(error: AdminDeploymentRevisionError) -> Resp {
    match error {
        AdminDeploymentRevisionError::AuthorityReadOnly { .. } => error_response(
            403,
            "authority_read_only",
            "model host authority does not allow local admin mutation",
        ),
        AdminDeploymentRevisionError::RevisionConflict { expected, actual } => json_response(
            409,
            &ErrorResponse {
                code: "revision_conflict",
                error: "deployment revision conflicts with durable state".to_string(),
                expected_revision: expected,
                actual_revision: actual,
            },
        ),
        AdminDeploymentRevisionError::Runtime(
            error @ sbproxy_model_host::RuntimeManagerError::InvalidDesired(_),
        ) => error_response(400, "invalid_desired", error.to_string()),
        AdminDeploymentRevisionError::Runtime(
            error @ sbproxy_model_host::RuntimeManagerError::Prepare(_),
        ) => error_response(
            422,
            error.reason_code(),
            "deployment candidate could not be prepared",
        ),
        AdminDeploymentRevisionError::Runtime(
            error @ sbproxy_model_host::RuntimeManagerError::Admission(_),
        ) => error_response(
            422,
            error.reason_code(),
            "deployment candidate does not fit current serving capacity",
        ),
        AdminDeploymentRevisionError::Runtime(sbproxy_model_host::RuntimeManagerError::Engine(
            error,
        )) if matches!(
            error.reason(),
            sbproxy_model_host::EngineFailureReason::EngineBlocked
                | sbproxy_model_host::EngineFailureReason::EngineIncompatible
                | sbproxy_model_host::EngineFailureReason::ArtifactNotReady
                | sbproxy_model_host::EngineFailureReason::UnsafeArgument
        ) =>
        {
            error_response(
                422,
                error.reason().as_str(),
                "deployment candidate is not compatible with the configured model host",
            )
        }
        AdminDeploymentRevisionError::Runtime(
            error @ sbproxy_model_host::RuntimeManagerError::PrepareInfrastructure(_),
        ) => error_response(
            502,
            error.reason_code(),
            "model runtime preparation infrastructure failed",
        ),
        AdminDeploymentRevisionError::Store(_)
        | AdminDeploymentRevisionError::Runtime(sbproxy_model_host::RuntimeManagerError::Store(
            _,
        )) => error_response(
            502,
            "store_failed",
            "deployment revision store operation failed",
        ),
        AdminDeploymentRevisionError::Runtime(error) => {
            error_response(502, error.reason_code(), "model runtime operation failed")
        }
    }
}

fn dispatch_with_runtime(
    runtime: &impl ModelManagementRuntime,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Option<Resp> {
    let path = path.split('?').next().unwrap_or(path);
    match path {
        "/admin/model-host/catalog" => {
            if !method.eq_ignore_ascii_case("GET") {
                return Some(error_response(
                    405,
                    "method_not_allowed",
                    "method not allowed",
                ));
            }
            Some(catalog_response(runtime))
        }
        "/admin/model-host/deployments" => {
            if method.eq_ignore_ascii_case("GET") {
                Some(deployments_get_response(runtime))
            } else if method.eq_ignore_ascii_case("PUT") {
                Some(deployments_put_response(runtime, body))
            } else {
                Some(error_response(
                    405,
                    "method_not_allowed",
                    "method not allowed",
                ))
            }
        }
        _ => None,
    }
}

/// Handle the model-host admin routes, or return `None` so the caller
/// falls through to the next dispatcher.
pub fn dispatch(method: &str, path: &str, body: Option<&str>) -> Option<Resp> {
    let path_only = path.split('?').next().unwrap_or(path);
    if matches!(
        path_only,
        "/admin/model-host/catalog" | "/admin/model-host/deployments"
    ) {
        let runtime = crate::server::model_host::model_runtime_manager();
        return dispatch_with_runtime(runtime.as_ref(), method, path_only, body);
    }
    match path_only {
        "/admin/model-host/status" => {
            if !method.eq_ignore_ascii_case("GET") {
                return Some((
                    405,
                    JSON,
                    r#"{"error":"method not allowed; use GET"}"#.to_string(),
                ));
            }
            Some(status_response())
        }
        // WOR-1765: load (spawn/ready) and evict (unload to free VRAM) a
        // model on demand. keep_alive stays config-driven.
        "/admin/model-host/load" => {
            if !method.eq_ignore_ascii_case("POST") {
                return Some((
                    405,
                    JSON,
                    r#"{"error":"method not allowed; use POST"}"#.to_string(),
                ));
            }
            Some(load_response(body))
        }
        "/admin/model-host/evict" => {
            if !method.eq_ignore_ascii_case("POST") {
                return Some((
                    405,
                    JSON,
                    r#"{"error":"method not allowed; use POST"}"#.to_string(),
                ));
            }
            Some(evict_response(body))
        }
        "/admin/model-host/stop" | "/admin/model-host/drain" => {
            if !method.eq_ignore_ascii_case("POST") {
                return Some((
                    405,
                    JSON,
                    r#"{"error":"method not allowed; use POST"}"#.to_string(),
                ));
            }
            Some(evict_response(body))
        }
        "/admin/model-host/reset" => {
            if !method.eq_ignore_ascii_case("POST") {
                return Some((
                    405,
                    JSON,
                    r#"{"error":"method not allowed; use POST"}"#.to_string(),
                ));
            }
            Some(reset_response(body))
        }
        _ => None,
    }
}

/// Pull the required deployment ID out of a JSON body. `model` remains an
/// accepted compatibility alias for the pre-managed-runtime admin contract.
fn model_from_body(body: Option<&str>) -> Result<String, Resp> {
    let parsed: serde_json::Value = body.and_then(|b| serde_json::from_str(b).ok()).ok_or((
        400,
        JSON,
        r#"{"error":"invalid JSON body; expected {deployment}"}"#.to_string(),
    ))?;
    let model = parsed
        .get("deployment")
        .or_else(|| parsed.get("model"))
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if model.is_empty() {
        return Err((
            400,
            JSON,
            r#"{"error":"missing 'deployment' (or legacy 'model')"}"#.to_string(),
        ));
    }
    Ok(model)
}

fn load_response(body: Option<&str>) -> Resp {
    let runtime = crate::server::model_host::model_runtime_manager();
    let model = match model_from_body(body) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    // Blocking-pool thread (spawn_blocking dispatcher); block on the async
    // load, matching status_response.
    let result = tokio::runtime::Handle::current().block_on(async {
        let running = runtime.ensure_ready(&model).await?;
        let status = runtime.status(&model).await;
        Ok::<_, sbproxy_model_host::RuntimeManagerError>((running, status))
    });
    match result {
        Ok((running, status)) => (
            200,
            JSON,
            serde_json::json!({
                "deployment": model,
                "state": "ready",
                "port": running.port,
                "job_id": status.and_then(|status| status.job_id),
            })
            .to_string(),
        ),
        Err(error) => runtime_error_response("load", error),
    }
}

fn evict_response(body: Option<&str>) -> Resp {
    let runtime = crate::server::model_host::model_runtime_manager();
    let model = match model_from_body(body) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let result = tokio::runtime::Handle::current().block_on(async {
        let report = runtime.drain(&model).await?;
        let status = runtime.status(&model).await;
        Ok::<_, sbproxy_model_host::RuntimeManagerError>((report, status))
    });
    match result {
        Ok((report, status)) => (
            200,
            JSON,
            serde_json::json!({
                "deployment": model,
                "state": "stopped",
                "drain": report,
                "job_id": status.and_then(|status| status.job_id),
            })
            .to_string(),
        ),
        Err(error) => runtime_error_response("stop", error),
    }
}

fn reset_response(body: Option<&str>) -> Resp {
    let runtime = crate::server::model_host::model_runtime_manager();
    let deployment = match model_from_body(body) {
        Ok(deployment) => deployment,
        Err(response) => return response,
    };
    let result =
        tokio::runtime::Handle::current().block_on(async { runtime.reset(&deployment).await });
    match result {
        Ok(job) => (
            200,
            JSON,
            serde_json::json!({
                "deployment": deployment,
                "state": "configured",
                "job_id": job.map(|job| job.id),
            })
            .to_string(),
        ),
        Err(error) => runtime_error_response("reset", error),
    }
}

fn runtime_serving_summary(
    statuses: &[sbproxy_model_host::DeploymentRuntimeStatus],
    fallback: crate::doctor::LocalServing,
) -> (bool, crate::doctor::LocalServing) {
    use sbproxy_model_host::DeploymentRuntimeState;

    if statuses.is_empty() {
        return (false, fallback);
    }

    let serving = statuses
        .iter()
        .any(|status| status.state == DeploymentRuntimeState::Ready);
    if serving {
        return (
            true,
            crate::doctor::LocalServing {
                ready: true,
                blockers: Vec::new(),
                recommendation: None,
            },
        );
    }

    let blockers = statuses
        .iter()
        .map(|status| match status.reason_code.as_deref() {
            Some(reason) => format!(
                "managed deployment {} is {} ({reason})",
                status.deployment,
                status.state.as_str()
            ),
            None => format!(
                "managed deployment {} is {}",
                status.deployment,
                status.state.as_str()
            ),
        })
        .collect();
    let recommendation = if statuses
        .iter()
        .any(|status| status.state == DeploymentRuntimeState::Failed)
    {
        "inspect the retained failure, correct its cause, then reset the deployment"
    } else if statuses
        .iter()
        .any(|status| status.state == DeploymentRuntimeState::Preparing)
    {
        "wait for the preparing deployment to become ready"
    } else if statuses
        .iter()
        .any(|status| status.state == DeploymentRuntimeState::Draining)
    {
        "wait for the draining deployment to stop"
    } else if statuses
        .iter()
        .any(|status| status.state == DeploymentRuntimeState::Stopped)
    {
        "load a stopped deployment or send it a routed request"
    } else {
        "load a configured deployment or send it a routed request"
    };

    (
        false,
        crate::doctor::LocalServing {
            ready: false,
            blockers,
            recommendation: Some(recommendation.to_string()),
        },
    )
}

fn status_response() -> Resp {
    let runtime = crate::server::model_host::model_runtime_manager();
    // The admin dispatcher runs under `spawn_blocking`, so we are on a
    // blocking-pool thread and may block on the async snapshot.
    let statuses = tokio::runtime::Handle::current().block_on(async { runtime.statuses().await });
    // WOR-1829: include the doctor's admission verdict so the admin UI
    // can say *why* a serve: block admits nothing (no memory budget, no
    // engine) instead of showing an empty model list. `collect()` is the
    // shallow probe set (no network), fine for an on-demand admin call.
    let fallback = crate::doctor::DoctorReport::collect().local_serving;
    let (serving, local_serving) = runtime_serving_summary(&statuses, fallback);
    match serde_json::to_string(&serde_json::json!({
        "serving": serving,
        "runtime_revision": runtime.current_revision(),
        "deployments": &statuses,
        "models": &statuses,
        "local_serving": local_serving,
    })) {
        Ok(body) => (200, JSON, body),
        Err(e) => (500, JSON, format!(r#"{{"error":"serialize status: {e}"}}"#)),
    }
}

fn runtime_error_response(operation: &str, error: sbproxy_model_host::RuntimeManagerError) -> Resp {
    let status = match &error {
        sbproxy_model_host::RuntimeManagerError::UnknownDeployment(_) => 404,
        sbproxy_model_host::RuntimeManagerError::Admission(_)
        | sbproxy_model_host::RuntimeManagerError::Draining(_) => 409,
        _ => 502,
    };
    (
        status,
        JSON,
        serde_json::json!({
            "error": format!("{operation} failed: {error}"),
            "reason_code": error.reason_code(),
        })
        .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use sbproxy_model_host::{Catalog, ModelDeployment, PullPolicy, ReconcilePlan, RolloutPolicy};

    type AppliedRevision = (Option<u64>, BTreeMap<String, ModelDeployment>);

    #[derive(Debug)]
    struct FakeManagementRuntime {
        catalog: Arc<Catalog>,
        snapshot: ModelManagementSnapshot,
        apply_result:
            Mutex<Option<Result<AdminDeploymentRevisionResult, AdminDeploymentRevisionError>>>,
        applied: Mutex<Vec<AppliedRevision>>,
    }

    impl ModelManagementRuntime for FakeManagementRuntime {
        fn active_catalog(&self) -> Arc<Catalog> {
            Arc::clone(&self.catalog)
        }

        fn management_snapshot(
            &self,
        ) -> Result<ModelManagementSnapshot, AdminDeploymentRevisionError> {
            Ok(self.snapshot.clone())
        }

        fn apply_admin_deployment_revision(
            &self,
            expected_revision: Option<u64>,
            deployments: BTreeMap<String, ModelDeployment>,
        ) -> Result<AdminDeploymentRevisionResult, AdminDeploymentRevisionError> {
            self.applied
                .lock()
                .expect("applied revisions lock")
                .push((expected_revision, deployments));
            self.apply_result
                .lock()
                .expect("apply result lock")
                .take()
                .expect("configured apply result")
        }
    }

    fn management_snapshot(
        authority: sbproxy_config::ModelHostAuthority,
    ) -> ModelManagementSnapshot {
        ModelManagementSnapshot {
            authority,
            read_only: authority != sbproxy_config::ModelHostAuthority::AdminManaged,
            revision: Some(7),
            content_digest: Some("d".repeat(64)),
            deployments: BTreeMap::from([("existing".to_string(), deployment())]),
        }
    }

    fn deployment() -> ModelDeployment {
        ModelDeployment {
            model: "qwen2.5-0.5b-instruct".to_string(),
            variant: Some("q4_k_m".to_string()),
            heterogeneous_variants: false,
            replicas: 1,
            required_labels: BTreeMap::new(),
            spread_by: Vec::new(),
            pull: PullPolicy::OnDemand,
            warm: false,
            keep_alive_secs: None,
            max_concurrency: None,
            max_queue_depth: 128,
            queue_timeout_ms: 30_000,
            engine: sbproxy_model_host::EngineChoice::Auto,
            rollout: RolloutPolicy::Rolling,
        }
    }

    fn fake_runtime(
        authority: sbproxy_config::ModelHostAuthority,
        apply_result: Result<AdminDeploymentRevisionResult, AdminDeploymentRevisionError>,
    ) -> FakeManagementRuntime {
        FakeManagementRuntime {
            catalog: Arc::new(Catalog::builtin()),
            snapshot: management_snapshot(authority),
            apply_result: Mutex::new(Some(apply_result)),
            applied: Mutex::new(Vec::new()),
        }
    }

    fn catalog_metadata_fixture(
        first_size_bytes: u64,
        second_size_bytes: u64,
        certification: &str,
    ) -> Catalog {
        Catalog::from_yaml(&format!(
            r#"
schema_version: 2
catalog_revision: admin-catalog-fixture
models:
  admin-fixture:
    params: 1B
    license: apache-2.0
    family: fixture
    context_length: 4096
    variants:
      - id: q4_k_m
        format: gguf
        quant: Q4_K_M
        engines: [llama_cpp]
        source: hf:Private/SecretRepo
        revision: private-source-revision
        files:
          - path: private/config.json
            sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            size_bytes: {first_size_bytes}
          - path: private/weights.gguf
            sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
            size_bytes: {second_size_bytes}
        requirements:
          accelerators: [cpu, metal]
          min_memory_bytes: 1024
        stability: preview
        certification: {certification}
"#,
        ))
        .expect("admin catalog fixture")
    }

    fn fake_runtime_with_catalog(catalog: Catalog) -> FakeManagementRuntime {
        let mut runtime = fake_runtime(
            sbproxy_config::ModelHostAuthority::AdminManaged,
            Err(AdminDeploymentRevisionError::Store("unused".to_string())),
        );
        runtime.catalog = Arc::new(catalog);
        runtime
    }

    fn valid_put_body(expected_revision: &str, model: &str, variant: &str) -> String {
        format!(
            r#"{{
                "expected_revision": {expected_revision},
                "deployments": {{
                    "local-qwen": {{
                        "model": "{model}",
                        "variant": "{variant}",
                        "replicas": 1,
                        "pull": "on_demand",
                        "warm": false,
                        "engine": "auto",
                        "rollout": "rolling"
                    }}
                }}
            }}"#
        )
    }

    #[test]
    fn catalog_route_returns_exact_bounded_active_metadata_only() {
        let runtime = fake_runtime_with_catalog(catalog_metadata_fixture(
            17,
            25,
            "fixture-certification-2026-07-12",
        ));

        let (status, content_type, body) =
            dispatch_with_runtime(&runtime, "GET", "/admin/model-host/catalog", None)
                .expect("catalog route");
        let response: serde_json::Value = serde_json::from_str(&body).expect("catalog response");

        assert_eq!(status, 200);
        assert_eq!(content_type, JSON);
        assert_eq!(response["schema_version"], 1);
        assert_eq!(
            response["catalog_revision"],
            runtime.catalog.catalog_revision
        );
        assert_eq!(
            response["models"]["admin-fixture"]["variants"][0]["id"],
            "q4_k_m"
        );
        let variant = &response["models"]["admin-fixture"]["variants"][0];
        assert_eq!(variant["download_size_bytes"], 42);
        assert_eq!(variant["certification"], "fixture-certification-2026-07-12");
        assert_eq!(
            variant
                .as_object()
                .expect("variant metadata object")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "accelerators",
                "certification",
                "download_size_bytes",
                "engines",
                "format",
                "id",
                "min_memory_bytes",
                "quant",
                "stability",
            ])
        );
        assert!(!body.contains("hf_repo"));
        assert!(!body.contains("hf_token"));
        assert!(!body.contains("\"source\""));
        assert!(!body.contains("\"revision\""));
        assert!(!body.contains("\"files\""));
        assert!(!body.contains("\"path\""));
        assert!(!body.contains("\"sha256\""));
        assert!(!body.contains("\"token\""));
        assert!(!body.contains("hf:Private/SecretRepo"));
        assert!(!body.contains("private-source-revision"));
        assert!(!body.contains("private/config.json"));
        assert!(!body.contains("private/weights.gguf"));
        assert!(!body.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn catalog_route_bounds_certification_display_metadata() {
        let certification = "c".repeat(257);
        let runtime = fake_runtime_with_catalog(catalog_metadata_fixture(17, 25, &certification));

        let (status, _, body) =
            dispatch_with_runtime(&runtime, "GET", "/admin/model-host/catalog", None)
                .expect("catalog route");
        let response: serde_json::Value = serde_json::from_str(&body).expect("catalog response");

        assert_eq!(status, 200);
        let returned = response["models"]["admin-fixture"]["variants"][0]["certification"]
            .as_str()
            .expect("bounded certification");
        assert_eq!(returned.chars().count(), 256);
        assert_eq!(returned, "c".repeat(256));
    }

    #[test]
    fn catalog_route_returns_stable_internal_error_when_download_size_overflows() {
        let runtime = fake_runtime_with_catalog(catalog_metadata_fixture(u64::MAX, 1, "fixture"));

        let (status, content_type, body) =
            dispatch_with_runtime(&runtime, "GET", "/admin/model-host/catalog", None)
                .expect("catalog route");
        let response: serde_json::Value = serde_json::from_str(&body).expect("error response");

        assert_eq!(status, 500);
        assert_eq!(content_type, JSON);
        assert_eq!(
            response,
            serde_json::json!({
                "code": "internal",
                "error": "model catalog metadata unavailable",
            })
        );
        assert!(!body.contains("admin-fixture"));
        assert!(!body.contains("Private"));
        assert!(!body.contains("private-source-revision"));
    }

    #[test]
    fn deployments_route_returns_authority_cursor_and_complete_desired_map() {
        let runtime = fake_runtime(
            sbproxy_config::ModelHostAuthority::FileManaged,
            Err(AdminDeploymentRevisionError::Store("unused".to_string())),
        );

        let (status, _, body) =
            dispatch_with_runtime(&runtime, "GET", "/admin/model-host/deployments", None)
                .expect("deployments route");
        let response: serde_json::Value = serde_json::from_str(&body).expect("deployment response");

        assert_eq!(status, 200);
        assert_eq!(response["schema_version"], 1);
        assert_eq!(response["authority"], "file_managed");
        assert_eq!(response["read_only"], true);
        assert_eq!(response["revision"], 7);
        assert_eq!(response["content_digest"], "d".repeat(64));
        assert_eq!(
            response["deployments"]["existing"]["model"],
            "qwen2.5-0.5b-instruct"
        );
    }

    #[test]
    fn deployment_put_rejects_read_only_authorities() {
        for authority in [
            sbproxy_config::ModelHostAuthority::FileManaged,
            sbproxy_config::ModelHostAuthority::ClusterAuthority,
        ] {
            let runtime = fake_runtime(
                authority,
                Err(AdminDeploymentRevisionError::Store("unused".to_string())),
            );

            let (status, _, body) = dispatch_with_runtime(
                &runtime,
                "PUT",
                "/admin/model-host/deployments",
                Some(r#"{"expected_revision":null,"deployments":{}}"#),
            )
            .expect("deployments route");
            let response: serde_json::Value = serde_json::from_str(&body).expect("error response");

            assert_eq!(status, 403, "{authority:?}: {body}");
            assert_eq!(response["code"], "authority_read_only");
            assert!(runtime
                .applied
                .lock()
                .expect("applied revisions lock")
                .is_empty());
        }
    }

    #[test]
    fn deployment_put_requires_a_strict_complete_revision_body() {
        for body in [
            "",
            r#"{"deployments":{}}"#,
            r#"{"expected_revision":null,"deployments":{},"extra":true}"#,
            r#"{"expected_revision":null,"deployments":{"local-qwen":{"model":"qwen2.5-0.5b-instruct","variant":"q4_k_m","mystery":true}}}"#,
            r#"{"expected_revision":null,"deployments":{"duplicate":{"model":"qwen2.5-0.5b-instruct","variant":"q4_k_m"},"duplicate":{"model":"qwen2.5-0.5b-instruct","variant":"q4_k_m"}}}"#,
            r#"{"expected_revision":null,"deployments":{"local-qwen":{"model":"qwen2.5-0.5b-instruct","variant":"q4_k_m","required_labels":{"pool":"cpu","pool":"gpu"}}}}"#,
        ] {
            let runtime = fake_runtime(
                sbproxy_config::ModelHostAuthority::AdminManaged,
                Err(AdminDeploymentRevisionError::Store("unused".to_string())),
            );

            let (status, _, response_body) =
                dispatch_with_runtime(&runtime, "PUT", "/admin/model-host/deployments", Some(body))
                    .expect("deployments route");
            let response: serde_json::Value =
                serde_json::from_str(&response_body).expect("error response");

            assert_eq!(status, 400, "{body}: {response_body}");
            assert_eq!(response["code"], "invalid_body");
        }
    }

    #[test]
    fn deployment_put_rejects_unknown_catalog_models_and_variants() {
        for (model, variant, code) in [
            ("not-in-catalog", "q4_k_m", "unknown_catalog_model"),
            (
                "qwen2.5-0.5b-instruct",
                "not-a-variant",
                "unknown_catalog_variant",
            ),
        ] {
            let runtime = fake_runtime(
                sbproxy_config::ModelHostAuthority::AdminManaged,
                Err(AdminDeploymentRevisionError::Store("unused".to_string())),
            );
            let body = valid_put_body("null", model, variant);

            let (status, _, response_body) = dispatch_with_runtime(
                &runtime,
                "PUT",
                "/admin/model-host/deployments",
                Some(&body),
            )
            .expect("deployments route");
            let response: serde_json::Value =
                serde_json::from_str(&response_body).expect("error response");

            assert_eq!(status, 400, "{response_body}");
            assert_eq!(response["code"], code);
            assert!(runtime
                .applied
                .lock()
                .expect("applied revisions lock")
                .is_empty());
        }
    }

    #[test]
    fn deployment_put_rejects_invalid_multi_replica_variant_policy() {
        let runtime = fake_runtime(
            sbproxy_config::ModelHostAuthority::AdminManaged,
            Err(AdminDeploymentRevisionError::Store("unused".to_string())),
        );
        let body = r#"{
            "expected_revision": null,
            "deployments": {
                "local-qwen": {
                    "model": "qwen2.5-0.5b-instruct",
                    "replicas": 2
                }
            }
        }"#;

        let (status, _, response_body) =
            dispatch_with_runtime(&runtime, "PUT", "/admin/model-host/deployments", Some(body))
                .expect("deployments route");
        let response: serde_json::Value =
            serde_json::from_str(&response_body).expect("error response");

        assert_eq!(status, 400, "{response_body}");
        assert_eq!(response["code"], "invalid_desired");
        assert!(runtime
            .applied
            .lock()
            .expect("applied revisions lock")
            .is_empty());
    }

    #[test]
    fn deployment_put_maps_stale_expected_revision_to_conflict() {
        let runtime = fake_runtime(
            sbproxy_config::ModelHostAuthority::AdminManaged,
            Err(AdminDeploymentRevisionError::RevisionConflict {
                expected: Some(6),
                actual: Some(7),
            }),
        );
        let body = valid_put_body("6", "qwen2.5-0.5b-instruct", "q4_k_m");

        let (status, _, response_body) = dispatch_with_runtime(
            &runtime,
            "PUT",
            "/admin/model-host/deployments",
            Some(&body),
        )
        .expect("deployments route");
        let response: serde_json::Value =
            serde_json::from_str(&response_body).expect("error response");

        assert_eq!(status, 409, "{response_body}");
        assert_eq!(response["code"], "revision_conflict");
        assert_eq!(response["expected_revision"], 6);
        assert_eq!(response["actual_revision"], 7);
    }

    #[test]
    fn candidate_preparation_failure_maps_to_unprocessable_entity() {
        let artifact_error = sbproxy_model_host::ArtifactError::ManualArtifactMissing {
            digest: "candidate-artifact-digest".to_string(),
        };
        let (status, _, body) = admin_revision_error_response(
            AdminDeploymentRevisionError::Runtime(artifact_error.into()),
        );
        let response: serde_json::Value = serde_json::from_str(&body).expect("error response");

        assert_eq!(status, 422);
        assert_eq!(response["code"], "prepare_failed");
        assert!(!body.contains("candidate-artifact-digest"));
    }

    #[test]
    fn infrastructure_preparation_failure_maps_to_bad_gateway() {
        let private_path = std::path::PathBuf::from("/private/cache/lease.lock");
        let artifact_error = sbproxy_model_host::ArtifactError::Io {
            operation: "lease artifact",
            path: private_path.clone(),
            source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "fixture failure"),
        };
        let (status, _, body) = admin_revision_error_response(
            AdminDeploymentRevisionError::Runtime(artifact_error.into()),
        );
        let response: serde_json::Value = serde_json::from_str(&body).expect("error response");

        assert_eq!(status, 502);
        assert_eq!(response["code"], "prepare_infrastructure_failed");
        assert!(!body.contains(private_path.to_string_lossy().as_ref()));
        assert!(!body.contains("fixture failure"));
    }

    #[test]
    fn deployment_put_returns_committed_revision_and_reconcile_plan() {
        let runtime = fake_runtime(
            sbproxy_config::ModelHostAuthority::AdminManaged,
            Ok(AdminDeploymentRevisionResult {
                revision: 8,
                content_digest: "e".repeat(64),
                plan: ReconcilePlan {
                    added: vec!["local-qwen".to_string()],
                    removed: vec!["existing".to_string()],
                    ..ReconcilePlan::default()
                },
            }),
        );
        let body = valid_put_body("7", "qwen2.5-0.5b-instruct", "q4_k_m");

        let (status, _, response_body) = dispatch_with_runtime(
            &runtime,
            "PUT",
            "/admin/model-host/deployments",
            Some(&body),
        )
        .expect("deployments route");
        let response: serde_json::Value =
            serde_json::from_str(&response_body).expect("success response");

        assert_eq!(status, 200, "{response_body}");
        assert_eq!(response["schema_version"], 1);
        assert_eq!(response["revision"], 8);
        assert_eq!(response["content_digest"], "e".repeat(64));
        assert_eq!(response["plan"]["added"], serde_json::json!(["local-qwen"]));
        assert_eq!(response["plan"]["removed"], serde_json::json!(["existing"]));
        let applied = runtime.applied.lock().expect("applied revisions lock");
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].0, Some(7));
        assert_eq!(applied[0].1["local-qwen"], deployment());
    }

    fn runtime_status(
        state: sbproxy_model_host::DeploymentRuntimeState,
    ) -> sbproxy_model_host::DeploymentRuntimeStatus {
        sbproxy_model_host::DeploymentRuntimeStatus {
            deployment: "local".to_string(),
            generation: 1,
            state,
            active_requests: 0,
            queued_requests: 0,
            engine: Some(sbproxy_model_host::EngineKind::LlamaCpp),
            driver_availability: Some(sbproxy_model_host::EngineAvailability::Available),
            artifact_digest: Some("a".repeat(64)),
            selected_devices: vec![0],
            memory: None,
            port: (state == sbproxy_model_host::DeploymentRuntimeState::Ready).then_some(41000),
            reason_code: None,
            job_id: None,
            last_error: None,
        }
    }

    #[test]
    fn live_runtime_state_overrides_the_path_only_doctor_verdict() {
        let fallback = crate::doctor::LocalServing {
            ready: false,
            blockers: vec!["no inference engine is installed yet".to_string()],
            recommendation: Some("install an engine".to_string()),
        };

        let (serving, verdict) = runtime_serving_summary(
            &[runtime_status(
                sbproxy_model_host::DeploymentRuntimeState::Ready,
            )],
            fallback.clone(),
        );
        assert!(serving);
        assert!(verdict.ready);
        assert!(verdict.blockers.is_empty());
        assert!(verdict.recommendation.is_none());

        let (serving, verdict) = runtime_serving_summary(
            &[runtime_status(
                sbproxy_model_host::DeploymentRuntimeState::Stopped,
            )],
            fallback,
        );
        assert!(!serving);
        assert!(!verdict.ready);
        assert_eq!(
            verdict.blockers,
            ["managed deployment local is stopped".to_string()]
        );
        assert_eq!(
            verdict.recommendation.as_deref(),
            Some("load a stopped deployment or send it a routed request")
        );
    }

    #[test]
    fn non_matching_path_falls_through() {
        assert!(dispatch("GET", "/admin/keys", None).is_none());
    }

    #[test]
    fn non_get_is_rejected() {
        let (code, _, _) = dispatch("POST", "/admin/model-host/status", None).unwrap();
        assert_eq!(code, 405);
    }

    #[test]
    fn load_rejects_missing_model() {
        assert_eq!(
            dispatch("POST", "/admin/model-host/load", Some("{}"))
                .expect("matched load route")
                .0,
            400,
        );
        assert_eq!(
            dispatch("POST", "/admin/model-host/evict", None)
                .expect("matched evict route")
                .0,
            400,
        );
    }

    #[tokio::test]
    async fn status_reports_not_serving_without_a_pipeline() {
        // With no compiled pipeline (or no ai_proxy serve block) the
        // endpoint answers 200 with serving:false rather than erroring.
        let (code, ct, body) = tokio::task::spawn_blocking(|| {
            dispatch("GET", "/admin/model-host/status", None).unwrap()
        })
        .await
        .unwrap();
        assert_eq!(code, 200);
        assert_eq!(ct, JSON);
        assert!(body.contains("\"serving\""));
        assert!(body.contains("\"deployments\""));
        assert!(body.contains("\"runtime_revision\""));
    }

    #[tokio::test]
    async fn lifecycle_routes_return_stable_unknown_deployment_reason() {
        for path in [
            "/admin/model-host/load",
            "/admin/model-host/stop",
            "/admin/model-host/reset",
        ] {
            let path = path.to_string();
            let path_label = path.clone();
            let (code, ct, body) = tokio::task::spawn_blocking(move || {
                dispatch(
                    "POST",
                    &path,
                    Some(r#"{"deployment":"definitely-missing"}"#),
                )
                .unwrap()
            })
            .await
            .unwrap();
            assert_eq!(code, 404, "{path_label}: {body}");
            assert_eq!(ct, JSON);
            assert!(body.contains("\"reason_code\":\"unknown_deployment\""));
        }
    }
}
