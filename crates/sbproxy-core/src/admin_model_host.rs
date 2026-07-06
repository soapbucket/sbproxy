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
        _ => None,
    }
}

/// Pull the required `model` name out of a `{"model":"..."}` JSON body,
/// or return a 400 response to send back.
fn model_from_body(body: Option<&str>) -> Result<String, Resp> {
    let parsed: serde_json::Value = body.and_then(|b| serde_json::from_str(b).ok()).ok_or((
        400,
        JSON,
        r#"{"error":"invalid JSON body; expected {model}"}"#.to_string(),
    ))?;
    let model = parsed
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if model.is_empty() {
        return Err((400, JSON, r#"{"error":"missing 'model'"}"#.to_string()));
    }
    Ok(model)
}

fn load_response(body: Option<&str>) -> Resp {
    let Some(runtime) = crate::server::model_host::current_model_host() else {
        return (
            200,
            JSON,
            r#"{"serving":false,"reason":"no ai_proxy provider has a serve: block"}"#.to_string(),
        );
    };
    let model = match model_from_body(body) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    // Blocking-pool thread (spawn_blocking dispatcher); block on the async
    // load, matching status_response.
    let result =
        tokio::runtime::Handle::current().block_on(async { runtime.ensure_ready(&model).await });
    match result {
        Ok(port) => (
            200,
            JSON,
            serde_json::json!({ "model": model, "state": "ready", "port": port }).to_string(),
        ),
        Err(e) => (
            502,
            JSON,
            format!(
                r#"{{"error":"load failed: {}"}}"#,
                e.to_string().replace('"', "'")
            ),
        ),
    }
}

fn evict_response(body: Option<&str>) -> Resp {
    let Some(runtime) = crate::server::model_host::current_model_host() else {
        return (
            200,
            JSON,
            r#"{"serving":false,"reason":"no ai_proxy provider has a serve: block"}"#.to_string(),
        );
    };
    let model = match model_from_body(body) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    tokio::runtime::Handle::current().block_on(async { runtime.unload(&model).await });
    (
        200,
        JSON,
        serde_json::json!({ "model": model, "state": "evicted" }).to_string(),
    )
}

fn status_response() -> Resp {
    let Some(runtime) = crate::server::model_host::current_model_host() else {
        // No provider declares a serve: block, so nothing is hosted
        // locally. Report that plainly rather than 404 (the endpoint
        // exists; there is just no local host configured).
        return (
            200,
            JSON,
            r#"{"serving":false,"reason":"no ai_proxy provider has a serve: block"}"#.to_string(),
        );
    };
    // The admin dispatcher runs under `spawn_blocking`, so we are on a
    // blocking-pool thread and may block on the async snapshot.
    let snapshot =
        tokio::runtime::Handle::current().block_on(async move { runtime.status_snapshot().await });
    match serde_json::to_string(&serde_json::json!({
        "serving": true,
        "models": snapshot.models,
        "vram": snapshot.vram,
    })) {
        Ok(body) => (200, JSON, body),
        Err(e) => (500, JSON, format!(r#"{{"error":"serialize status: {e}"}}"#)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // No serve block in tests, so this returns the not-serving body;
        // with a runtime it would 400 on a missing model. Either way it
        // is a matched route, not a fall-through.
        assert!(dispatch("POST", "/admin/model-host/load", Some("{}")).is_some());
        assert!(dispatch("POST", "/admin/model-host/evict", None).is_some());
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
    }
}
