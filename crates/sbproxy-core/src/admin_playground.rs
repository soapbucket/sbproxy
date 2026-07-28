//! Admin chat playground.
//!
//! Three routes on the admin server (operator-only, behind the admin auth
//! and RBAC gate) let an operator exercise any AI endpoint the server is
//! configured with, straight from the dashboard:
//!
//! - `GET /admin/api/playground/endpoints` lists every AI origin the live
//!   pipeline serves, with each provider's declared models.
//! - `POST /admin/api/playground/chat` runs a chat completion against a
//!   chosen endpoint via the same [`AiClient`](sbproxy_ai) the data plane
//!   uses, returning the upstream response plus token usage, cost, and
//!   latency. It bypasses per-key governance and guardrails entirely,
//!   because it never traverses the data plane's own dispatch path.
//! - `POST /admin/api/playground/dispatch` runs the same shape of request
//!   through the *real* data-plane pipeline instead, impersonating a
//!   chosen virtual key via a short-lived [`ticket`] so key policy,
//!   governance, routing, and guardrails all apply exactly as they would
//!   for that key's real traffic. See its own doc comment and
//!   [`handle_dispatch`] for how impersonation is proven safe.
//!
//! All three are handled in the async admin connection handler rather
//! than the blocking request dispatcher, because the chat and dispatch
//! calls must await network I/O. Both mutating routes are POSTs, so the
//! connection handler's RBAC gate already restricts them to the `admin`
//! role.

use serde_json::json;

/// Path for the playground chat endpoint (POST).
pub const CHAT_PATH: &str = "/admin/api/playground/chat";

/// Path listing the AI endpoints the server is configured with (GET).
pub const ENDPOINTS_PATH: &str = "/admin/api/playground/endpoints";

/// Path for the real-dispatch impersonation endpoint (POST). Unlike
/// `CHAT_PATH`, which calls the engine / `AiClient` directly, this route
/// exercises the actual data-plane pipeline (key policy, governance,
/// routing, guardrails) for a chosen virtual key. See `handle_dispatch`.
pub const DISPATCH_PATH: &str = "/admin/api/playground/dispatch";

/// Ephemeral, single-use impersonation tickets backing `DISPATCH_PATH`.
///
/// An admin operator cannot recover a virtual key's real bearer secret to
/// exercise it (`admin_keys.rs`: shown once, never stored), so there is no
/// way to hand a chosen key's real credential to a loopback HTTP call.
/// Instead: `handle_dispatch` confirms the key is real and active, mints a
/// random ticket naming its `key_id`, and presents the ticket as the
/// bearer token on a genuine HTTP call back into this server's own
/// data-plane listener. `server::request_phase::resolve_inbound_key`
/// recognizes the ticket prefix, consumes the ticket (single-use), and on
/// a hit resolves straight to that key's real, stored `KeyRecord` via the
/// same `ctx.resolved_inbound_key` short-circuit an ordinarily-presented
/// minted key uses, so the rest of the pipeline (governance, routing,
/// guardrails) runs unmodified against the key's real policy. A ticket
/// proves nothing about the key's secret; it proves only that an
/// admin-authenticated operator asked to impersonate this key seconds
/// ago (the connection handler's RBAC gate already restricts this
/// route's POST to the `admin` role). On a miss (wrong prefix, unknown,
/// expired, or already consumed) the pre-auth sweep denies exactly like
/// an ordinary invalid key, so this can never be exploited as a bypass.
pub(crate) mod ticket {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    /// Prefix marking a bearer token as a playground impersonation
    /// ticket. Distinct in both shape and length from a minted virtual
    /// key (`sbproxy_keystore::crypto::TOKEN_PREFIX`, `sbp_...`) or a
    /// provider key, so it can never collide with either.
    pub(crate) const PREFIX: &str = "sbpgtkt_";

    /// Ticket lifetime. The loopback call that redeems a ticket completes
    /// in well under a second; this is generous headroom for that call,
    /// short enough that a ticket nobody redeems cannot be replayed
    /// minutes later.
    const TTL: Duration = Duration::from_secs(30);

    struct Ticket {
        key_id: String,
        expires_at: Instant,
    }

    fn store() -> &'static Mutex<HashMap<String, Ticket>> {
        static STORE: OnceLock<Mutex<HashMap<String, Ticket>>> = OnceLock::new();
        STORE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Mint a fresh single-use ticket naming `key_id`, valid for [`TTL`].
    /// Returns the full bearer token (`PREFIX` + random hex).
    pub(crate) fn mint(key_id: &str) -> String {
        mint_with_ttl(key_id, TTL)
    }

    fn mint_with_ttl(key_id: &str, ttl: Duration) -> String {
        // Same primitive `admin_session::SessionSigner` uses for its
        // per-process key and nonce: `rand::random` over a fixed-size
        // array, hex-encoded.
        let random_bytes: [u8; 32] = rand::random();
        let random = hex::encode(random_bytes);
        let mut guard = store().lock().expect("ticket store lock");
        // Opportunistic sweep: drop expired entries nobody redeemed so a
        // long-lived process does not accumulate them.
        let now = Instant::now();
        guard.retain(|_, ticket| ticket.expires_at > now);
        guard.insert(
            random.clone(),
            Ticket {
                key_id: key_id.to_string(),
                expires_at: now + ttl,
            },
        );
        format!("{PREFIX}{random}")
    }

    /// Consume `token` if it names a live, unexpired ticket. Single-use: a
    /// hit removes the entry immediately, so replaying the same token
    /// (even seconds later, still inside the TTL) denies exactly like an
    /// unknown key. Returns `None` for any token that is not ours,
    /// unknown, or expired.
    pub(crate) fn consume(token: &str) -> Option<String> {
        let random = token.strip_prefix(PREFIX)?;
        let mut guard = store().lock().expect("ticket store lock");
        let ticket = guard.remove(random)?;
        (ticket.expires_at > Instant::now()).then_some(ticket.key_id)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn mint_then_consume_resolves_the_key_id() {
            let token = mint("key-abc");
            assert!(token.starts_with(PREFIX));
            assert_eq!(consume(&token).as_deref(), Some("key-abc"));
        }

        #[test]
        fn a_ticket_is_single_use() {
            let token = mint("key-abc");
            assert_eq!(consume(&token).as_deref(), Some("key-abc"));
            assert_eq!(
                consume(&token),
                None,
                "replay of a consumed ticket must deny"
            );
        }

        #[test]
        fn an_unknown_token_is_denied() {
            assert_eq!(consume("sbpgtkt_deadbeef"), None);
        }

        #[test]
        fn a_non_ticket_token_is_not_ours() {
            assert_eq!(consume("sbp_abc_def"), None);
        }

        #[test]
        fn an_expired_ticket_is_denied() {
            let token = mint_with_ttl("key-abc", Duration::from_millis(0));
            std::thread::sleep(Duration::from_millis(5));
            assert_eq!(consume(&token), None);
        }

        #[test]
        fn two_mints_never_collide_and_resolve_independently() {
            let a = mint("key-a");
            let b = mint("key-b");
            assert_ne!(a, b);
            assert_eq!(consume(&a).as_deref(), Some("key-a"));
            assert_eq!(consume(&b).as_deref(), Some("key-b"));
        }
    }
}

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

    // A served / managed provider hosts its model on this box. The data
    // plane resolves the engine's loopback endpoint (and takes a
    // deployment admission permit) per request; without the same
    // resolution the provider registry falls back to a localhost URL
    // that points at the proxy itself and the chat 404s. Resolve here
    // and call the engine directly; cloud providers keep the shared
    // AiClient path below.
    let requested_model = request.get("model").and_then(|v| v.as_str());
    let managed_provider = ai
        .config
        .providers
        .iter()
        .find(|p| p.serve.is_some() || p.is_managed_model());
    if let Some(provider) = managed_provider {
        let origin_id = idx
            .and_then(|i| pipeline.config.origins.get(i))
            .map(|o| o.origin_id.to_string())
            .unwrap_or_else(|| origin.clone());
        match crate::server::model_host::managed_upstream(
            &origin_id,
            provider,
            requested_model,
            crate::server::model_host::lane_class_for(None),
        )
        .await
        {
            Ok(Some(upstream)) => {
                return managed_chat(&origin, upstream, request, debug, &pipeline).await;
            }
            Ok(None) => {}
            Err(e) => {
                // A mixed origin may pair a local provider with cloud
                // fallbacks; only fail hard when there is nothing to
                // fall through to.
                let has_cloud = ai
                    .config
                    .providers
                    .iter()
                    .any(|p| p.serve.is_none() && !p.is_managed_model());
                if !has_cloud {
                    return (
                        502,
                        "application/json",
                        format!(
                            r#"{{"error":"local engine unavailable: {}"}}"#,
                            e.replace('"', "'")
                        ),
                    );
                }
            }
        }
    }

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

/// Run a playground chat against a locally served engine. The permit on
/// `upstream` is held until the engine's response has been read, exactly
/// like the data plane's request context, so deployment concurrency
/// accounting sees the request. The engine speaks the OpenAI surface on
/// loopback and needs no auth header.
async fn managed_chat(
    origin: &str,
    upstream: crate::server::model_host::ManagedLocalUpstream,
    mut request: serde_json::Value,
    debug: bool,
    pipeline: &crate::pipeline::CompiledPipeline,
) -> (u16, &'static str, String) {
    let public_model = upstream.public_model.clone();
    if let Some(obj) = request.as_object_mut() {
        obj.insert(
            "model".to_string(),
            serde_json::Value::String(upstream.engine_model.clone()),
        );
    }
    let url = format!(
        "{}/chat/completions",
        upstream.base_url.trim_end_matches('/')
    );
    let started = std::time::Instant::now();
    let sent = reqwest::Client::new()
        .post(&url)
        .json(&request)
        .send()
        .await;
    let resp = match sent {
        Ok(r) => r,
        Err(e) => {
            return (
                502,
                "application/json",
                format!(
                    r#"{{"error":"local engine dispatch failed: {}"}}"#,
                    e.to_string().replace('"', "'")
                ),
            )
        }
    };
    let status = resp.status().as_u16();
    let mut upstream_body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    // Hold the admission permit until the response is fully read.
    drop(upstream.permit);
    let latency_ms = started.elapsed().as_secs_f64() * 1000.0;

    // The engine reports its internal model identifier; the public route
    // name is what operators (and the price table) know.
    if let Some(obj) = upstream_body.as_object_mut() {
        if obj.contains_key("model") {
            obj.insert(
                "model".to_string(),
                serde_json::Value::String(public_model.clone()),
            );
        }
    }
    let usage = upstream_body.get("usage");
    let input = usage
        .and_then(|u| u.get("prompt_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let output = usage
        .and_then(|u| u.get("completion_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let cost = sbproxy_ai::budget::estimate_cost_for_usage(
        &public_model,
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
        "model": public_model,
        "response": upstream_body,
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
            model = %public_model,
            status,
            latency_ms,
            "playground chat via managed engine (debug)"
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

/// Run a chat completion through the real data-plane dispatch path,
/// impersonating a chosen virtual key. Body:
/// `{ "key_id": "...", "origin": "<hostname>", "request": { <OpenAI chat body> } }`.
///
/// Unlike `handle_chat`, this never calls the engine or `AiClient`
/// directly: it confirms `key_id` names a real, active key (the same
/// cache-backed lookup `resolve_dynamic_virtual_key` uses at request
/// time, not a fabricated credential), mints a single-use [`ticket`],
/// then performs a genuine loopback HTTP call into this server's own
/// data-plane listener for `origin` with the ticket as the bearer token.
/// The pre-auth sweep in `server::request_phase` resolves the ticket to
/// the key's real, stored policy, so the response reflects real
/// key-policy, governance, routing, and guardrail behavior end to end.
///
/// Plain-HTTP origins only today: an origin with `force_ssl` set answers
/// `501`. Trusting this process's own certificate/SNI identity for a
/// loopback call to a `force_ssl` origin needs deeper plumbing than this
/// route implements; scoped down deliberately rather than guessed at.
/// The caller must have already enforced the `admin` role.
pub async fn handle_dispatch(body: Option<&str>) -> (u16, &'static str, String) {
    let parsed: serde_json::Value = match body.and_then(|b| serde_json::from_str(b).ok()) {
        Some(v) => v,
        None => {
            return (
                400,
                "application/json",
                r#"{"error":"invalid JSON body; expected {key_id, origin, request}"}"#.to_string(),
            )
        }
    };
    let key_id = parsed
        .get("key_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
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
    if key_id.is_empty() {
        return (
            400,
            "application/json",
            r#"{"error":"missing 'key_id'"}"#.to_string(),
        );
    }
    if origin.is_empty() {
        return (
            400,
            "application/json",
            r#"{"error":"missing 'origin'"}"#.to_string(),
        );
    }
    let debug = parsed
        .get("debug")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Confirm the key is real and active before minting a ticket for it.
    // Reuses the same cache-backed lookup the data plane's own auth path
    // uses, rather than reconstructing or bypassing key verification.
    let Some(plane) = crate::key_plane::current_key_plane() else {
        return (
            409,
            "application/json",
            r#"{"error":"key_management is not enabled"}"#.to_string(),
        );
    };
    match plane.cache().resolve_key(&key_id).await {
        Ok(Some(record)) if record.is_usable(chrono::Utc::now()) => {}
        Ok(Some(_)) => {
            return (
                403,
                "application/json",
                r#"{"error":"key is not active"}"#.to_string(),
            )
        }
        Ok(None) => {
            return (
                404,
                "application/json",
                r#"{"error":"key not found"}"#.to_string(),
            )
        }
        Err(error) => {
            tracing::error!(%error, "playground dispatch: key lookup failed");
            return (
                502,
                "application/json",
                r#"{"error":"key store unavailable"}"#.to_string(),
            );
        }
    }

    // Own the pipeline Arc across the await, same as `handle_chat`.
    let guard = crate::reload::current_pipeline();
    let pipeline = std::sync::Arc::clone(&guard);
    drop(guard);

    let Some(compiled_origin) = pipeline.config.resolve_origin(&origin) else {
        return (
            404,
            "application/json",
            format!(
                r#"{{"error":"no origin configured for hostname '{}'"}}"#,
                origin.replace('"', "'")
            ),
        );
    };
    if compiled_origin.force_ssl {
        return (
            501,
            "application/json",
            r#"{"error":"origin requires TLS; playground real-dispatch supports plain-HTTP origins only"}"#
                .to_string(),
        );
    }

    let token = ticket::mint(&key_id);
    let base = format!("http://127.0.0.1:{}", pipeline.config.server.http_bind_port);
    let started = std::time::Instant::now();
    let sent = reqwest::Client::new()
        .post(format!("{base}/v1/chat/completions"))
        // Loopback call to this process's own data-plane listener: the
        // listener resolves the origin by `Host` (falling back to the
        // URI authority for HTTP/2), the same as any other client.
        .header(reqwest::header::HOST, origin.as_str())
        .bearer_auth(&token)
        .json(&request)
        .send()
        .await;
    let resp = match sent {
        Ok(r) => r,
        Err(e) => {
            return (
                502,
                "application/json",
                format!(
                    r#"{{"error":"dispatch failed: {}"}}"#,
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
        "key_id": key_id,
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
            key_id = %key_id,
            model = %model,
            status,
            latency_ms,
            "playground dispatch (debug)"
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

    #[tokio::test]
    async fn dispatch_rejects_missing_body() {
        let (status, _, body) = handle_dispatch(None).await;
        assert_eq!(status, 400);
        assert!(body.contains("invalid JSON"));
    }

    #[tokio::test]
    async fn dispatch_rejects_missing_request() {
        let (status, _, body) = handle_dispatch(Some(r#"{"key_id":"k1","origin":"api.ai"}"#)).await;
        assert_eq!(status, 400);
        assert!(body.contains("request"));
    }

    #[tokio::test]
    async fn dispatch_rejects_missing_key_id() {
        let (status, _, body) =
            handle_dispatch(Some(r#"{"origin":"api.ai","request":{"model":"m"}}"#)).await;
        assert_eq!(status, 400);
        assert!(body.contains("key_id"));
    }

    #[tokio::test]
    async fn dispatch_rejects_missing_origin() {
        let (status, _, body) =
            handle_dispatch(Some(r#"{"key_id":"k1","request":{"model":"m"}}"#)).await;
        assert_eq!(status, 400);
        assert!(body.contains("origin"));
    }
}
