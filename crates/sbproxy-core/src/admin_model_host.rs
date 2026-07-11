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

type Resp = (u16, &'static str, String);

const JSON: &str = "application/json";

/// Handle the model-host admin routes, or return `None` so the caller
/// falls through to the next dispatcher.
pub fn dispatch(method: &str, path: &str, body: Option<&str>) -> Option<Resp> {
    let path_only = path.split('?').next().unwrap_or(path);
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
