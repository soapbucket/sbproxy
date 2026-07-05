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
pub fn dispatch(method: &str, path: &str) -> Option<Resp> {
    if path != "/admin/model-host/status" {
        return None;
    }
    if !method.eq_ignore_ascii_case("GET") {
        return Some((
            405,
            JSON,
            r#"{"error":"method not allowed; use GET"}"#.to_string(),
        ));
    }
    Some(status_response())
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
        assert!(dispatch("GET", "/admin/keys").is_none());
    }

    #[test]
    fn non_get_is_rejected() {
        let (code, _, _) = dispatch("POST", "/admin/model-host/status").unwrap();
        assert_eq!(code, 405);
    }

    #[tokio::test]
    async fn status_reports_not_serving_without_a_pipeline() {
        // With no compiled pipeline (or no ai_proxy serve block) the
        // endpoint answers 200 with serving:false rather than erroring.
        let (code, ct, body) =
            tokio::task::spawn_blocking(|| dispatch("GET", "/admin/model-host/status").unwrap())
                .await
                .unwrap();
        assert_eq!(code, 200);
        assert_eq!(ct, JSON);
        assert!(body.contains("\"serving\""));
    }
}
