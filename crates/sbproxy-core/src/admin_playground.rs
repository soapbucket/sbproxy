//! Admin chat playground.
//!
//! Two routes on the admin server (operator-only, behind the admin auth
//! and RBAC gate) let an operator exercise any AI endpoint the server is
//! configured with, straight from the dashboard:
//!
//! - `GET /admin/api/playground/endpoints` lists every AI origin the live
//!   pipeline serves, with each provider's declared models.
//! - `POST /admin/api/playground/chat` runs a chat completion against a
//!   chosen endpoint via the same [`AiClient`](sbproxy_ai) the data plane
//!   uses, returning the upstream response plus token usage, cost, and
//!   latency.
//!
//! Both are handled in the async admin connection handler rather than the
//! blocking request dispatcher, because the chat call must await the AI
//! client. The chat route is a mutation, so the connection handler's RBAC
//! gate already restricts it to the `admin` role.

use serde_json::json;

/// Path for the playground chat endpoint (POST).
pub const CHAT_PATH: &str = "/admin/api/playground/chat";

/// Path listing the AI endpoints the server is configured with (GET).
pub const ENDPOINTS_PATH: &str = "/admin/api/playground/endpoints";

/// List every AI endpoint in the running pipeline: each AI origin with
/// its providers and their declared models. Read-only; sourced from the
/// live compiled pipeline, so a config reload updates it without a
/// restart. `models` may be empty when a provider defers to the upstream
/// catalog.
pub fn list_endpoints() -> (u16, &'static str, String) {
    use sbproxy_modules::Action;
    let pipeline = crate::reload::current_pipeline();
    let mut endpoints = Vec::new();
    for (idx, action) in pipeline.actions.iter().enumerate() {
        if let Action::AiProxy(ai) = action {
            let origin = pipeline
                .config
                .origins
                .get(idx)
                .map(|o| o.hostname.to_string())
                .unwrap_or_default();
            let providers: Vec<_> = ai
                .config
                .providers
                .iter()
                .map(|p| {
                    json!({
                        "name": p.name.as_str(),
                        "type": p.provider_type,
                        "models": p.models.iter().map(|m| m.as_str()).collect::<Vec<_>>(),
                        "default_model": p.default_model.as_ref().map(|m| m.as_str()),
                    })
                })
                .collect();
            endpoints.push(json!({ "origin": origin, "providers": providers }));
        }
    }
    (
        200,
        "application/json",
        json!({ "endpoints": endpoints }).to_string(),
    )
}

/// Run a chat completion against a chosen AI endpoint. Body:
/// `{ "origin": "<hostname>", "request": { <OpenAI chat body> } }`.
///
/// Returns the upstream response plus token usage, estimated cost, the
/// resolved model, and round-trip latency, or an error envelope. The
/// caller must have already enforced the `admin` role.
pub async fn handle_chat(body: Option<&str>) -> (u16, &'static str, String) {
    use sbproxy_modules::Action;

    let parsed: serde_json::Value = match body.and_then(|b| serde_json::from_str(b).ok()) {
        Some(v) => v,
        None => {
            return (
                400,
                "application/json",
                r#"{"error":"invalid JSON body; expected {origin, request}"}"#.to_string(),
            )
        }
    };
    let origin = parsed
        .get("origin")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let request = match parsed.get("request") {
        Some(r) if r.is_object() => r.clone(),
        _ => {
            return (
                400,
                "application/json",
                r#"{"error":"missing 'request' chat body"}"#.to_string(),
            )
        }
    };
    if origin.is_empty() {
        return (
            400,
            "application/json",
            r#"{"error":"missing 'origin'"}"#.to_string(),
        );
    }
    // WOR-1760: per-request debug. The playground calls the AI client
    // directly and does not traverse the data-plane pipeline that stamps
    // `x-sbproxy-debug-*` headers, so we return the same correlation
    // fields (a request id, logged server-side, plus the config revision)
    // in a `debug` block when the client opts in.
    let debug = parsed
        .get("debug")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Own the pipeline Arc so the borrow of the AI config stays valid
    // across the await (the load guard alone is not Send).
    let guard = crate::reload::current_pipeline();
    let pipeline = std::sync::Arc::clone(&guard);
    drop(guard);

    let idx = pipeline
        .config
        .origins
        .iter()
        .position(|o| o.hostname.as_str() == origin);
    let ai = idx.and_then(|i| match pipeline.actions.get(i) {
        Some(Action::AiProxy(ai)) => Some(ai),
        _ => None,
    });
    let ai = match ai {
        Some(a) => a,
        None => {
            return (
                404,
                "application/json",
                format!(
                    r#"{{"error":"no AI endpoint configured for origin '{}'"}}"#,
                    origin.replace('"', "'")
                ),
            )
        }
    };

    let client = crate::server::ai_client();
    let router = ai.config.router();
    let started = std::time::Instant::now();
    let resp = match client
        .forward_chat_request(&ai.config, &router, "/v1/chat/completions", &request)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                502,
                "application/json",
                format!(
                    r#"{{"error":"AI dispatch failed: {}"}}"#,
                    e.to_string().replace('"', "'")
                ),
            )
        }
    };
    let status = resp.status().as_u16();
    let upstream: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    let latency_ms = started.elapsed().as_secs_f64() * 1000.0;

    let usage = upstream.get("usage");
    let input = usage
        .and_then(|u| u.get("prompt_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let output = usage
        .and_then(|u| u.get("completion_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let model = upstream
        .get("model")
        .and_then(|v| v.as_str())
        .or_else(|| request.get("model").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();
    let cost = sbproxy_ai::budget::estimate_cost_for_usage(
        &model,
        &sbproxy_ai::budget::AiUsage::Tokens {
            input,
            output,
            cached_input: 0,
            cache_creation: 0,
        },
    );

    let mut out = json!({
        "origin": origin,
        "status": status,
        "model": model,
        "response": upstream,
        "usage": { "input_tokens": input, "output_tokens": output },
        "cost_usd": cost,
        "latency_ms": latency_ms,
    });
    if debug {
        let request_id = format!(
            "pg-{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        tracing::debug!(
            target: "sbproxy::admin::playground",
            request_id = %request_id,
            origin = %origin,
            model = %model,
            status,
            latency_ms,
            "playground chat (debug)"
        );
        if let Some(obj) = out.as_object_mut() {
            obj.insert(
                "debug".to_string(),
                json!({
                    "request_id": request_id,
                    "config_revision": pipeline.config_revision.as_str(),
                }),
            );
        }
    }

    (200, "application/json", out.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn chat_rejects_missing_body() {
        let (status, _, body) = handle_chat(None).await;
        assert_eq!(status, 400);
        assert!(body.contains("invalid JSON"));
    }

    #[tokio::test]
    async fn chat_rejects_missing_request() {
        let (status, _, body) = handle_chat(Some(r#"{"origin":"api.ai"}"#)).await;
        assert_eq!(status, 400);
        assert!(body.contains("request"));
    }

    #[tokio::test]
    async fn chat_rejects_missing_origin() {
        let (status, _, body) = handle_chat(Some(r#"{"request":{"model":"m"}}"#)).await;
        assert_eq!(status, 400);
        assert!(body.contains("origin"));
    }
}
