//! AI proxy request dispatch: the `handle_ai_proxy` entry point,
//! response relay (buffered + cached), and the streaming relay path.
//!
//! Extracted from `server.rs`. Behavior-preserving move:
//! `use super::*` re-imports the parent module's private items and
//! `use` aliases, so the moved code needs no rewiring.

use super::*;

/// Outcome of resolving an inbound bearer token against the dynamic key plane
/// (WOR-1551).
enum DynamicKeyOutcome {
    /// Not a virtual-key-shaped token (or no token); let other auth handle it.
    NotApplicable,
    /// Resolved to a usable key; proceed with this synthesized config.
    Resolved(Box<sbproxy_ai::identity::VirtualKeyConfig>),
    /// Deny the request with this status and message.
    Deny(u16, String),
}

/// Map a stored [`KeyRecord`](sbproxy_keystore::record::KeyRecord) onto the
/// gateway's `VirtualKeyConfig` so the existing per-key pipeline (principal
/// stamp, attribution, model gate, budget scope) runs unchanged regardless of
/// whether the key came from the dynamic store or the compiled config.
fn key_record_to_virtual_key(
    rec: &sbproxy_keystore::record::KeyRecord,
) -> sbproxy_ai::identity::VirtualKeyConfig {
    sbproxy_ai::identity::VirtualKeyConfig {
        // The public id, never the secret: used only as a fallback display name.
        key: rec.key_id.clone(),
        name: rec.name.clone(),
        allowed_models: rec.allowed_models.clone(),
        blocked_models: rec.blocked_models.clone(),
        allowed_providers: rec.allowed_providers.clone(),
        // Stored opaque on the record (this crate is the seam between the
        // keystore and the AI gateway); deserialize each selector here, dropping
        // any malformed entry rather than failing the whole resolve.
        principal_selectors: rec
            .principal_selectors
            .iter()
            .filter_map(|v| serde_json::from_value(v.clone()).ok())
            .collect(),
        require_pii_redaction: rec.require_pii_redaction.clone(),
        max_requests_per_minute: rec.max_requests_per_minute,
        budget: rec
            .budget
            .as_ref()
            .map(|b| sbproxy_ai::identity::KeyBudget {
                max_tokens: b.max_tokens,
                max_cost_usd: b.max_cost_usd,
            }),
        tags: rec.tags.clone(),
        project: rec.project.clone(),
        user: rec.user.clone(),
        metadata: rec
            .metadata
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        route_to_model: rec.route_to_model.clone(),
        inject_tools: rec.inject_tools.clone(),
        // WOR-1646: keystore-sourced keys do not carry a federation
        // injection ref today; it is a static-config surface.
        inject_mcp: None,
        enabled: true,
        bypass_prompt_injection: rec.bypass_prompt_injection,
    }
}

/// Process-global per-key rate limiter (WOR-1558). Accumulates request counts
/// per virtual key across requests; the limit itself is read per-request from
/// the resolved record, so a live PATCH changes enforcement without a reload.
fn key_rate_limiter() -> &'static sbproxy_ai::identity::KeyRateLimiter {
    static LIMITER: std::sync::OnceLock<sbproxy_ai::identity::KeyRateLimiter> =
        std::sync::OnceLock::new();
    LIMITER.get_or_init(sbproxy_ai::identity::KeyRateLimiter::new)
}

/// WOR-1555: map a verified OIDC/JWT identity to a stored virtual-key record's
/// policy, so the bearer-token and OIDC front doors converge on one record.
///
/// The JWT/OIDC auth provider already proved the identity, so no secret is
/// verified here: the configured claim's value names the record (key_id), and a
/// usable record's policy/attribution is applied. `NotApplicable` when mapping
/// is not configured or the token carries no mapped claim. A claim that names a
/// missing or inactive record DENIES: the identity declared itself governed by
/// that record, so revoking the record blocks the JWT rather than degrading it
/// to ungoverned access. A store outage fails closed unless
/// `failure_mode_allow` is set, mirroring the bearer path.
async fn resolve_oidc_mapped_key(
    plane: &crate::key_plane::KeyPlane,
    principal: &sbproxy_plugin::Principal,
) -> DynamicKeyOutcome {
    let Some(claim_field) = plane.oidc_claim_field() else {
        return DynamicKeyOutcome::NotApplicable;
    };
    let Some(key_id) = principal
        .attrs
        .claims
        .as_ref()
        .and_then(|claims| claims.get(claim_field))
        .and_then(|v| v.as_str())
    else {
        return DynamicKeyOutcome::NotApplicable;
    };
    match plane.cache().resolve_key(key_id).await {
        Err(e) => {
            if plane.failure_mode_allow() {
                tracing::warn!(error = %e, "key store unavailable; failure_mode_allow set, passing through");
                DynamicKeyOutcome::NotApplicable
            } else {
                DynamicKeyOutcome::Deny(503, "key store unavailable".to_string())
            }
        }
        // Same status for a missing record as the bearer path's unknown id.
        Ok(None) => DynamicKeyOutcome::Deny(401, "invalid key".to_string()),
        Ok(Some(rec)) => {
            if rec.is_usable(chrono::Utc::now()) {
                DynamicKeyOutcome::Resolved(Box::new(key_record_to_virtual_key(&rec)))
            } else {
                DynamicKeyOutcome::Deny(403, "key is not active".to_string())
            }
        }
    }
}

/// Resolve an inbound bearer token against the dynamic key plane: parse the
/// `sk-<key_id>-<secret>` shape, look the id up through the cache then store,
/// constant-time verify the secret, and gate on status/expiry. Fail-closed: a
/// store outage denies unless `failure_mode_allow` is set.
async fn resolve_dynamic_virtual_key(
    plane: &crate::key_plane::KeyPlane,
    raw_token: Option<&str>,
) -> DynamicKeyOutcome {
    let Some(token) = raw_token else {
        return DynamicKeyOutcome::NotApplicable;
    };
    let Some((key_id, secret)) = sbproxy_keystore::crypto::parse_token(token) else {
        // Not a virtual-key-shaped token; a different auth provider may own it.
        return DynamicKeyOutcome::NotApplicable;
    };
    let now = chrono::Utc::now();
    match plane.cache().resolve_key(key_id).await {
        Err(e) => {
            if plane.failure_mode_allow() {
                tracing::warn!(error = %e, "key store unavailable; failure_mode_allow set, passing through");
                DynamicKeyOutcome::NotApplicable
            } else {
                DynamicKeyOutcome::Deny(503, "key store unavailable".to_string())
            }
        }
        // Unknown id and a wrong secret return the same status so neither is an
        // existence oracle.
        Ok(None) => DynamicKeyOutcome::Deny(401, "invalid key".to_string()),
        Ok(Some(rec)) => {
            if !plane.crypto().verify_record(&rec, secret, now) {
                DynamicKeyOutcome::Deny(401, "invalid key".to_string())
            } else if !rec.is_usable(now) {
                DynamicKeyOutcome::Deny(403, "key is not active".to_string())
            } else {
                DynamicKeyOutcome::Resolved(Box::new(key_record_to_virtual_key(&rec)))
            }
        }
    }
}

pub(super) async fn handle_ai_proxy(
    session: &mut Session,
    config: &AiHandlerConfig,
    pipeline: &CompiledPipeline,
    hostname: &str,
    ctx: &mut RequestContext,
    origin_idx: Option<usize>,
) -> Result<()> {
    let method = session.req_header().method.clone();
    let method_str = method.as_str().to_string();
    let mut path = session.req_header().uri.path().to_string();

    // Classify the AI surface for observability. Phase 1 tags every
    // request with a surface label; per-surface dispatch handlers land
    // in later phases. See docs/ai-deep-integration-blueprint.md.
    let surface = sbproxy_ai::handler::classify_surface(&method_str, &path);
    let surface_label = surface.label();
    debug!(
        ai.surface = surface_label,
        method = %method_str,
        path = %path,
        "AI proxy: classified surface"
    );
    // Stamp the surface label onto the request context so the access
    // log line carries it alongside the existing `ai_provider`,
    // `ai_model`, and token-count fields.
    ctx.ai_surface = Some(surface_label.to_string());

    // WOR-1528 / WOR-1540: stash the configured usage sinks on the
    // context here, where the handler config is in scope. The
    // end-of-request `logging` hook emits one `LlmUsageEvent` to them
    // once the final status, tokens, cost, and latency are known. The
    // clone is a handful of `Arc` pointer bumps and only happens when an
    // operator has configured sinks (default: none), so the common path
    // is untouched.
    let usage_sinks = config.usage_sinks();
    if !usage_sinks.is_empty() {
        ctx.ai_usage_sinks = Some(usage_sinks.to_vec());
    }

    // WOR-1541: arm realized-outcome recording when this origin routes
    // with the outcome-aware strategy, so the end-of-request hook feeds
    // the global feedback store.
    if matches!(config.routing, sbproxy_ai::RoutingStrategy::OutcomeAware) {
        ctx.ai_record_routing_feedback = true;
    }

    // Create the top-level request span. The span is registered with
    // the subscriber (so OTel-style exporters see it as part of the
    // trace tree) but we do not `.enter()` it because the resulting
    // guard is `!Send` and `request_filter` is an async function that
    // must be `Send`. The surface field is carried by the explicit
    // `debug!` above and by the per-surface metrics below.
    let ai_span = sbproxy_ai::tracing_spans::ai_request_span(surface_label, &method_str);
    // WOR-1098: stamp the resolved tenant onto the request span so OTel
    // exporters can filter traces by tenant. The origin match has
    // already populated `ctx.tenant_id` (defaulting to `__default__`
    // when no tenant is configured) by the time dispatch runs.
    ai_span.record("sbproxy.tenant_id", ctx.tenant_id.as_str());

    // Increment the per-surface request counter and start the latency
    // clock. The latency guard records elapsed time at function exit
    // regardless of which dispatch path the request takes (success,
    // upstream error, early-return on validation failure).
    sbproxy_ai::ai_metrics::record_surface_request(surface_label, &method_str);
    let _ai_latency_guard =
        sbproxy_ai::ai_metrics::AiSurfaceLatencyGuard::new(surface_label, method_str.clone());

    // Phase 8: per-surface rate limit. Operators configure these via
    // `ai_handler_config.per_surface_rate_limits` keyed by the
    // surface label. Surfaces without a config entry are uncapped.
    // Returns 429 before any upstream call when the per-minute cap
    // has been reached.
    if let Some(surface_cfg) = config.per_surface_rate_limits.get(surface_label) {
        if !AI_SURFACE_RATE_LIMITER.check_rate(surface_label, surface_cfg) {
            warn!(
                ai.surface = surface_label,
                method = %method_str,
                "AI proxy: per-surface rate limit hit; returning 429"
            );
            sbproxy_ai::tracing_spans::record_error(
                &ai_span,
                sbproxy_ai::tracing_spans::error_type::RATE_LIMITED,
                "per-surface rate limit exceeded",
            );
            send_error(session, 429, "per-surface rate limit exceeded").await?;
            return Ok(());
        }
    }

    // Gate non-universal surfaces on provider capability. Surfaces
    // that aren't implemented by every provider (assistants, threads,
    // batches, fine-tuning, files, realtime, image, audio,
    // moderations, reranking, embeddings) are rejected with 501 when
    // no configured provider supports them. Chat completions, models,
    // and unrecognized paths bypass this gate; the former are
    // universal, the latter falls through to the existing dispatch
    // which 404s at the upstream.
    if !matches!(
        surface,
        sbproxy_ai::handler::AiSurface::ChatCompletions
            | sbproxy_ai::handler::AiSurface::Models
            | sbproxy_ai::handler::AiSurface::Unknown
    ) {
        let any_supports = config
            .providers
            .iter()
            .any(|p| sbproxy_ai::api_routes::provider_supports_surface(&p.name, &surface));
        if !any_supports {
            warn!(
                ai.surface = surface_label,
                method = %method_str,
                "AI proxy: no configured provider supports this surface; returning 501"
            );
            send_error(
                session,
                501,
                "no configured AI provider supports this surface",
            )
            .await?;
            return Ok(());
        }
    }

    // WOR-752 Finding B: an unrecognized (`Unknown`) path can only be
    // forwarded verbatim. That is correct forward-compat for an
    // OpenAI-format upstream (a new OpenAI path the catalog has not
    // learned yet still works), but for a translated-format provider
    // (Anthropic / Google / Bedrock) the upstream expects a different
    // wire shape and path, so a verbatim forward is guaranteed to fail
    // with a confusing upstream error (the #240 class). 501 the unknown
    // path when no configured provider is OpenAI-format, rather than
    // forwarding a doomed request.
    if matches!(surface, sbproxy_ai::handler::AiSurface::Unknown) {
        let has_passthrough = config.providers.iter().any(|p| {
            sbproxy_ai::client::provider_format(p) == sbproxy_ai::providers::ProviderFormat::OpenAi
        });
        if !has_passthrough {
            warn!(
                ai.surface = surface_label,
                method = %method_str,
                "AI proxy: unrecognized path with no OpenAI-format provider to pass it through; returning 501"
            );
            send_error(
                session,
                501,
                "unrecognized AI path: no OpenAI-compatible provider is configured to handle it",
            )
            .await?;
            return Ok(());
        }
    }

    // Build a router for provider selection.
    // WOR-798: the router is shared per-origin (persisted on the handler
    // config), so its per-provider latency / token / connection state
    // survives across requests. A per-request router would reset that
    // state every call and make the latency/usage-aware strategies inert.
    let router = config.router();

    // Handle GET requests (e.g. /v1/models) by forwarding to first enabled provider.
    if method == http::Method::GET {
        // LiteLLM-parity read-only endpoints served locally from config.
        if let Some(body) = ai_management_response(&path, config) {
            let bytes = serde_json::to_vec(&body).unwrap_or_default();
            send_response(session, 200, "application/json", &bytes).await?;
            return Ok(());
        }
        let provider_idx = router
            .select_with_allowed(
                &config.providers,
                ctx.principal
                    .virtual_key
                    .as_ref()
                    .map(|vk| vk.allowed_providers.as_slice())
                    .unwrap_or(&[]),
            )
            .ok_or_else(|| {
                warn!("AI proxy: no enabled providers");
                Error::new(ErrorType::HTTPStatus(502))
            })?;
        let provider = &config.providers[provider_idx];

        let resp = AI_CLIENT
            .load()
            .forward_get_request(provider, &path)
            .await
            .map_err(|e| {
                record_ai_transport_failure(
                    &ai_span,
                    Some(provider.name.as_str()),
                    &e,
                    "AI upstream GET request failed",
                );
                warn!(error = %e, "AI proxy: upstream GET request failed");
                Error::because(ErrorType::ConnectError, "AI upstream request failed", e)
            })?;
        record_ai_provider_response_failure(
            &ai_span,
            provider.name.as_str(),
            resp.status().as_u16(),
            None,
        );

        // GET endpoints (e.g. /v1/models) aren't translated yet:
        // Anthropic's models listing has a different shape and most
        // OpenAI clients don't depend on it for routing decisions.
        let format = sbproxy_ai::client::provider_format(provider);
        emit_ai_billing_event(
            surface_label,
            &provider.name,
            None,
            sbproxy_ai::budget::AiUsage::PerCall,
            0.0,
            Vec::new(),
            &ctx.attribution_tags,
            ctx.tenant_id.as_str(),
            ctx.principal.api_key_id(),
            &ai_span,
        );
        return relay_ai_response(
            session,
            resp,
            format,
            config.max_body_size,
            ctx.ai_inbound_format.as_deref(),
        )
        .await;
    }

    // Methods other than GET/POST forward through the method-aware
    // client without engaging the chat-completions body-parse pipeline
    // (no body for DELETE/HEAD; body preserved as-is for PUT/PATCH).
    // Per-surface guardrails, budget enforcement, and PII redaction for
    // these methods are deferred to later phases; for Phase 1 the goal
    // is to dispatch without misrouting DELETE as POST.
    if matches!(
        method,
        http::Method::DELETE
            | http::Method::HEAD
            | http::Method::PUT
            | http::Method::PATCH
            | http::Method::OPTIONS
    ) {
        let provider_idx = router
            .select_with_allowed(
                &config.providers,
                ctx.principal
                    .virtual_key
                    .as_ref()
                    .map(|vk| vk.allowed_providers.as_slice())
                    .unwrap_or(&[]),
            )
            .ok_or_else(|| {
                warn!("AI proxy: no enabled providers");
                Error::new(ErrorType::HTTPStatus(502))
            })?;
        let provider = &config.providers[provider_idx];

        // Read the body for methods that typically carry one. DELETE,
        // HEAD, OPTIONS go through without a body. For PUT / PATCH we
        // keep the raw bytes alongside the parsed JSON so the
        // idempotency middleware can hash the verbatim payload.
        let (body_opt, body_raw): (Option<serde_json::Value>, Vec<u8>) = if matches!(
            method,
            http::Method::PUT | http::Method::PATCH
        ) {
            let body_bytes = {
                let mut buf = bytes::BytesMut::new();
                while let Some(chunk) = session.read_request_body().await? {
                    buf.extend_from_slice(&chunk);
                }
                buf.freeze()
            };
            if body_bytes.is_empty() {
                (None, Vec::new())
            } else {
                match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                    Ok(v) => (Some(v), body_bytes.to_vec()),
                    Err(e) => {
                        warn!(error = %e, "AI proxy: invalid JSON body on method-aware request");
                        send_error(session, 400, "invalid JSON body").await?;
                        return Ok(());
                    }
                }
            }
        } else {
            (None, Vec::new())
        };

        // --- Idempotency middleware engagement (PUT / PATCH) ---
        //
        // Same four-branch flow as the POST path: replay cache hits
        // verbatim, return 409 on body conflict, capture-on-miss for
        // the response side, and stamp a SKIPPED marker when a cap
        // disengaged. The middleware only inspects the request body
        // on methods configured in `idempotency.methods` (PUT and
        // PATCH are in the default set), so DELETE / HEAD / OPTIONS
        // fall through unchanged.
        let (idem_skip_reason, idem_capture) =
            match engage_ai_idempotency(session, pipeline, origin_idx, &body_raw, false).await? {
                AiIdempotencyEngagement::Replayed | AiIdempotencyEngagement::Conflict => {
                    return Ok(());
                }
                AiIdempotencyEngagement::NotApplicable => (None, None),
                AiIdempotencyEngagement::Skipped { reason } => (Some(reason), None),
                AiIdempotencyEngagement::Miss {
                    idem,
                    workspace_id,
                    key,
                    body_hash,
                    permit,
                } => (
                    None,
                    Some(AiIdempotencyCapture {
                        idem,
                        workspace_id,
                        key,
                        body_hash,
                        _permit: permit,
                    }),
                ),
            };

        let resp = AI_CLIENT
            .load()
            .forward_with_method(provider, &method_str, &path, body_opt.as_ref())
            .await
            .map_err(|e| {
                record_ai_transport_failure(
                    &ai_span,
                    Some(provider.name.as_str()),
                    &e,
                    "AI upstream method-aware request failed",
                );
                warn!(
                    error = %e,
                    method = %method_str,
                    ai.surface = surface.label(),
                    "AI proxy: upstream method-aware request failed"
                );
                Error::because(ErrorType::ConnectError, "AI upstream request failed", e)
            })?;
        record_ai_provider_response_failure(
            &ai_span,
            provider.name.as_str(),
            resp.status().as_u16(),
            None,
        );

        let format = sbproxy_ai::client::provider_format(provider);
        emit_ai_billing_event(
            surface_label,
            &provider.name,
            None,
            sbproxy_ai::budget::AiUsage::PerCall,
            0.0,
            Vec::new(),
            &ctx.attribution_tags,
            ctx.tenant_id.as_str(),
            ctx.principal.api_key_id(),
            &ai_span,
        );
        // WOR-1044 PR3: the GET-method-aware path runs before the
        // request body is read, so there is no reversible PII
        // capture yet. Pass an empty pairs vector; restore is a
        // no-op short-circuit.
        return relay_ai_response_with_idempotency(
            session,
            resp,
            format,
            config.max_body_size,
            idem_skip_reason,
            idem_capture,
            ctx.ai_inbound_format.as_deref(),
            Vec::new(),
        )
        .await;
    }

    // POST requests: read the body, parse JSON, select provider, forward.
    // Drain the full body: Pingora returns it one chunk at a time, so a
    // single read truncates a multi-chunk (large) body and the JSON parse
    // then fails with a spurious 400 (WOR-795 body-buffering fix). The AI
    // dispatch builds its own upstream request, so draining here does not
    // affect forwarding.
    let body_bytes = {
        let mut buf = bytes::BytesMut::new();
        while let Some(chunk) = session.read_request_body().await? {
            buf.extend_from_slice(&chunk);
        }
        buf.freeze()
    };

    // WOR-229: stash the native body so the dispatcher can
    // byte-forward the inbound bytes to the upstream when the
    // upstream's wire format equals the inbound format. The
    // hub-mediated translation block immediately below rewrites
    // `body_bytes` to OpenAI Chat JSON; capturing here preserves the
    // original shape for the bypass branch in the dispatch for-loop.
    // The native target path is supplied by the `NativeBypass` enum
    // rather than the inbound path so the bypass works even when the
    // proxy is fronting an idiosyncratic inbound URL.
    let native_request_bytes_for_bypass: bytes::Bytes = body_bytes.clone();

    // --- Native-format inbound shim ---
    //
    // Anthropic Messages and OpenAI Responses arrive on their own
    // paths but the rest of the AI pipeline (router, guardrails,
    // budget, translator, semantic cache, idempotency) speaks the
    // canonical OpenAI Chat Completions shape. The shim parses the
    // inbound body through the matching `ChatFormat`, re-emits it as
    // OpenAI Chat Completions JSON, and rewrites the path so the
    // upstream selection and translator pipeline run unchanged. The
    // inbound format id is stamped on the request context so the
    // relay path can wrap the response body back into the format the
    // client expects.
    let body_bytes = match surface {
        sbproxy_ai::handler::AiSurface::Messages => {
            match sbproxy_ai::format::anthropic_messages::translate_anthropic_request_to_openai(
                body_bytes.as_ref(),
            ) {
                Ok(translated) => {
                    ctx.ai_inbound_format = Some("anthropic".into());
                    path = "/v1/chat/completions".into();
                    bytes::Bytes::from(translated)
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "AI proxy: failed to parse Anthropic Messages inbound body"
                    );
                    send_error(session, e.status(), e.message()).await?;
                    return Ok(());
                }
            }
        }
        sbproxy_ai::handler::AiSurface::Responses => {
            match sbproxy_ai::format::openai_responses::translate_responses_request_to_openai(
                body_bytes.as_ref(),
            ) {
                Ok(translated) => {
                    ctx.ai_inbound_format = Some("responses".into());
                    path = "/v1/chat/completions".into();
                    bytes::Bytes::from(translated)
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "AI proxy: failed to parse OpenAI Responses inbound body"
                    );
                    send_error(session, e.status(), e.message()).await?;
                    return Ok(());
                }
            }
        }
        _ => body_bytes,
    };

    // Multipart short-circuit: surfaces that carry multipart bodies
    // (audio transcriptions, image edits, image variations, file
    // uploads) must not be JSON-parsed. We byte-forward the body
    // verbatim with the inbound Content-Type preserved so the
    // upstream provider parses it normally.
    let request_content_type = session
        .req_header()
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let is_multipart_request = request_content_type
        .to_ascii_lowercase()
        .starts_with("multipart/");

    // --- Idempotency middleware engagement (POST) ---
    //
    // Engage before the upstream call (and before the multipart and
    // semantic-cache hooks) so a cache hit can serve byte-identical
    // to the original response without invoking any downstream
    // logic. Multipart bodies are explicitly skipped for v1
    // (see `engage_ai_idempotency`); the marker stamps the response
    // so operators can spot the case in dashboards.
    let (idem_skip_reason, mut idem_capture) = match engage_ai_idempotency(
        session,
        pipeline,
        origin_idx,
        body_bytes.as_ref(),
        is_multipart_request,
    )
    .await?
    {
        AiIdempotencyEngagement::Replayed | AiIdempotencyEngagement::Conflict => {
            return Ok(());
        }
        AiIdempotencyEngagement::NotApplicable => (None, None),
        AiIdempotencyEngagement::Skipped { reason } => (Some(reason), None),
        AiIdempotencyEngagement::Miss {
            idem,
            workspace_id,
            key,
            body_hash,
            permit,
        } => (
            None,
            Some(AiIdempotencyCapture {
                idem,
                workspace_id,
                key,
                body_hash,
                _permit: permit,
            }),
        ),
    };

    if is_multipart_request {
        let provider_idx = router
            .select_with_allowed(
                &config.providers,
                ctx.principal
                    .virtual_key
                    .as_ref()
                    .map(|vk| vk.allowed_providers.as_slice())
                    .unwrap_or(&[]),
            )
            .ok_or_else(|| {
                warn!("AI proxy: no enabled providers");
                Error::new(ErrorType::HTTPStatus(502))
            })?;
        let provider = &config.providers[provider_idx];

        let resp = AI_CLIENT
            .load()
            .forward_bytes(
                provider,
                &method_str,
                &path,
                body_bytes,
                &request_content_type,
            )
            .await
            .map_err(|e| {
                record_ai_transport_failure(
                    &ai_span,
                    Some(provider.name.as_str()),
                    &e,
                    "AI upstream multipart request failed",
                );
                warn!(
                    error = %e,
                    method = %method_str,
                    ai.surface = surface_label,
                    content_type = %request_content_type,
                    "AI proxy: upstream multipart request failed"
                );
                Error::because(ErrorType::ConnectError, "AI upstream request failed", e)
            })?;

        let format = sbproxy_ai::client::provider_format(provider);

        // For audio_transcription requests, peek at the response body
        // to extract `duration` (present when the operator requests
        // verbose_json output) so the billing event reflects the real
        // audio length instead of falling back to PerCall. Other
        // multipart surfaces (image edits/variations, file upload)
        // continue to emit PerCall here; their per-unit usage is
        // captured on the request side and emitted in the chat path.
        if surface_label == "audio_transcription" {
            let status = resp.status().as_u16();
            let resp_ct = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/json")
                .to_string();
            let resp_bytes = read_capped_response_body(resp, config.max_body_size).await?;
            record_ai_provider_response_failure(
                &ai_span,
                provider.name.as_str(),
                status,
                Some(resp_bytes.as_ref()),
            );
            // Whisper is the only OpenAI transcription model today;
            // the inbound body is multipart so the model is not in a
            // JSON field. Default to `whisper-1` for cost lookup; a
            // future commit that parses multipart fields can refine.
            let model = Some("whisper-1".to_string());
            let duration = serde_json::from_slice::<serde_json::Value>(&resp_bytes)
                .ok()
                .and_then(|v| v.get("duration").and_then(|d| d.as_f64()));
            let usage = match duration {
                Some(secs) => sbproxy_ai::budget::AiUsage::AudioSeconds { seconds: secs },
                None => sbproxy_ai::budget::AiUsage::PerCall,
            };
            let cost = sbproxy_ai::budget::estimate_cost_for_usage("whisper-1", &usage);
            let cost_micros = emit_ai_billing_event(
                surface_label,
                &provider.name,
                model,
                usage,
                cost,
                Vec::new(),
                &ctx.attribution_tags,
                ctx.tenant_id.as_str(),
                ctx.principal.api_key_id(),
                &ai_span,
            );
            if cost_micros > 0 {
                ctx.ai_cost_usd_micros = Some(cost_micros);
            }
            let extra: Option<(&str, &str)> =
                idem_skip_reason.map(|r| ("x-sbproxy-idempotency", r));
            return send_response_with_extra(session, status, &resp_ct, &resp_bytes, extra).await;
        }

        emit_ai_billing_event(
            surface_label,
            &provider.name,
            None,
            sbproxy_ai::budget::AiUsage::PerCall,
            0.0,
            Vec::new(),
            &ctx.attribution_tags,
            ctx.tenant_id.as_str(),
            ctx.principal.api_key_id(),
            &ai_span,
        );
        record_ai_provider_response_failure(
            &ai_span,
            provider.name.as_str(),
            resp.status().as_u16(),
            None,
        );
        // Multipart never captures for idempotency (engagement
        // skipped with SKIPPED-MULTIPART). Pass the skip reason
        // through so the marker still lands on the response.
        //
        // WOR-1044 PR3: multipart bodies are not JSON-parsed for
        // reversible PII capture (the redactor walks JSON), so the
        // capture is empty and the restore call short-circuits.
        return relay_ai_response_with_idempotency(
            session,
            resp,
            format,
            config.max_body_size,
            idem_skip_reason,
            None,
            ctx.ai_inbound_format.as_deref(),
            ctx.ai_reversible_redactions.clone(),
        )
        .await;
    }

    let mut body: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "AI proxy: invalid JSON body");
            send_error(session, 400, "invalid JSON body").await?;
            return Ok(());
        }
    };

    // PII redaction (request body): walk the parsed JSON in place so
    // every downstream code path - guardrails, classifier, semantic
    // cache key derivation, upstream forward - sees redacted text.
    // Skipped when no `pii` block is configured or `redact_request`
    // is false. Replaces email, SSN, credit-card-with-Luhn, phone,
    // IPv4, and common API-key shapes with `[REDACTED:<KIND>]`
    // markers; see `sbproxy_security::pii::PiiRedactor`.
    if let Some(pii_cfg) = config.pii.as_ref() {
        if pii_cfg.enabled && pii_cfg.redact_request {
            if let Some(redactor) = config.pii_redactor() {
                // WOR-1044: capture-aware path so reversible rules can be
                // restored on the response. Capture lives on the request
                // context; the response handler reads it via `ctx`.
                // Non-reversible rules behave identically to the old
                // `redact_json` (replace with the static replacement;
                // capture is unused for them).
                let mut capture = sbproxy_security::pii::ReversibleCapture::new();
                redactor.redact_json_with_capture(&mut body, &mut capture);
                if !capture.is_empty() {
                    ctx.ai_reversible_redactions = capture.pairs;
                }
                tracing::debug!("AI proxy: applied request-body PII redaction");
            }
        }
    }

    // --- WOR-800: versioned prompt store ---
    //
    // When the body references a stored prompt via `"prompt":
    // "name@version"` (or bare `"name"` for the pinned default version),
    // render it server-side with the request variables and prepend it as
    // a system message. The resolved name + version are recorded on the
    // context for the run metadata. A bad reference or a missing template
    // variable is a 400 (rendering is strict-undefined).
    //
    // WOR-800 PR2: lookup order is RUNTIME OVERLAY first, then the
    // config-declared store. The runtime overlay (mutable via the
    // library API at sbproxy_ai::prompts) shadows config so an
    // operator can mint or pin a prompt at runtime without a full
    // config reload. A miss on both layers leaves the prompt field
    // untouched (the request proceeds with no synthesized system
    // message, same as today's "no `prompt` field" path).
    if let Some(reference) = body
        .get("prompt")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
    {
        let request_ctx = build_prompt_request_ctx(session, &body);
        let overlay = sbproxy_ai::prompts::current_runtime_overlay();
        let result = overlay
            .resolve(hostname, &reference, &request_ctx)
            .or_else(|| {
                config
                    .prompts
                    .as_ref()
                    .map(|store| store.render(&reference, &request_ctx))
            });
        if let Some(outcome) = result {
            match outcome {
                Ok(rendered) => {
                    prepend_system_message(&mut body, &rendered.text);
                    ctx.ai_prompt_name = Some(rendered.name);
                    ctx.ai_prompt_version = Some(rendered.version);
                    // Drop the gateway-only `prompt` field so it is not
                    // forwarded to the provider.
                    if let Some(obj) = body.as_object_mut() {
                        obj.remove("prompt");
                    }
                }
                Err(e) => {
                    warn!(reference = %reference, error = %e, "AI proxy: prompt render failed");
                    send_error(session, 400, &format!("prompt error: {e}")).await?;
                    return Ok(());
                }
            }
        }
    }

    // Extract model name from the body, or use default.
    let mut model = body
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Check model allow/block lists.
    if !model.is_empty() && !config.is_model_allowed(&model) {
        let msg = format!("model '{}' is not allowed", model);
        warn!(model = %model, "AI proxy: model blocked");
        send_error(session, 403, &msg).await?;
        return Ok(());
    }

    // --- WOR-894: virtual-key identity resolution ---
    //
    // When the request's `Authorization: Bearer <key>` (or bare key)
    // matches a configured virtual key, surface that key's `project`,
    // `user`, and `metadata` onto the request context so the access log
    // can attribute spend / usage to them. Missing / unknown keys
    // silently no-op (auth itself is enforced by the configured auth
    // provider, not here). Skipped when no virtual_keys are declared.
    {
        let auth_value = req_header_value(session, "authorization");
        let raw_key = auth_value.as_deref().map(|h| {
            h.strip_prefix("Bearer ")
                .or_else(|| h.strip_prefix("bearer "))
                .unwrap_or(h)
                .trim()
                .to_string()
        });
        // Resolve the inbound virtual key. When the dynamic key plane is
        // enabled it is the source of truth (hashed at rest, instant revoke,
        // per-request cache->store); otherwise fall back to the compiled
        // `virtual_keys:` list.
        let resolved_vk: Option<sbproxy_ai::identity::VirtualKeyConfig> =
            if let Some(plane) = crate::key_plane::current_key_plane() {
                match resolve_dynamic_virtual_key(&plane, raw_key.as_deref()).await {
                    DynamicKeyOutcome::Resolved(vk) => Some(*vk),
                    // No virtual-key bearer token: fall back to OIDC/JWT claim
                    // mapping so a verified identity resolves the same record.
                    DynamicKeyOutcome::NotApplicable => {
                        match resolve_oidc_mapped_key(&plane, &ctx.principal).await {
                            DynamicKeyOutcome::Resolved(vk) => Some(*vk),
                            DynamicKeyOutcome::NotApplicable => None,
                            DynamicKeyOutcome::Deny(status, msg) => {
                                warn!(
                                    status,
                                    reason = %msg,
                                    "AI proxy: OIDC-mapped virtual key denied"
                                );
                                send_error(session, status, &msg).await?;
                                return Ok(());
                            }
                        }
                    }
                    DynamicKeyOutcome::Deny(status, msg) => {
                        warn!(status, reason = %msg, "AI proxy: dynamic virtual key denied");
                        send_error(session, status, &msg).await?;
                        return Ok(());
                    }
                }
            } else if !config.virtual_keys.is_empty() {
                raw_key.as_deref().and_then(|key| {
                    config
                        .virtual_keys
                        .iter()
                        .find(|vk| vk.enabled && vk.key == key)
                        .cloned()
                })
            } else {
                None
            };
        if let Some(vk) = resolved_vk {
            {
                if !vk.matches_principal(&ctx.principal) {
                    let vk_name = vk.name.as_deref().unwrap_or("<unnamed>");
                    warn!(
                        credential = %vk_name,
                        principal_source = %ctx.principal.source.as_str(),
                        principal_sub = %ctx.principal.sub,
                        "AI proxy: credential principal selector miss"
                    );
                    send_error(session, 403, "credential is not allowed for this principal")
                        .await?;
                    return Ok(());
                }
                if !vk.require_pii_redaction.is_empty()
                    && !config.satisfies_pii_redaction_requirement(&vk.require_pii_redaction)
                {
                    let vk_name = vk.name.as_deref().unwrap_or("<unnamed>");
                    warn!(
                        credential = %vk_name,
                        required_rules = ?vk.require_pii_redaction,
                        "AI proxy: credential requires request PII redaction but origin redaction is inactive or missing required rules"
                    );
                    send_error(
                        session,
                        500,
                        "credential requires active request PII redaction",
                    )
                    .await?;
                    return Ok(());
                }
                // Stamp the matched VK onto the unified Principal so
                // the rest of the pipeline (access log, attribution
                // metric, policy scripts, MCP RBAC) all read through
                // one shape. The Principal carries the attribution
                // attrs plus a `virtual_key` reference that downstream
                // code uses to enforce `allowed_providers`.
                let mut attrs = sbproxy_plugin::PrincipalAttrs {
                    project: vk.project.clone(),
                    user: vk.user.clone(),
                    team: None,
                    tags: vk.tags.clone(),
                    metadata: vk
                        .metadata
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                    roles: Vec::new(),
                    claims: None,
                    // Per-credential reporting id for the virtual key.
                    // The operator-supplied stable name only; never the
                    // raw `vk.key` secret. `None` when the key is
                    // unnamed so the metric falls back to the
                    // un-credentialed bucket rather than leaking key
                    // material.
                    key_id: vk.name.clone(),
                };
                // Reflect the matched key name into `sub` so the
                // access-log + principal_kind columns can show which
                // VK served the request.
                let vk_name = vk.name.clone().unwrap_or_else(|| vk.key.clone());
                let _ = &mut attrs;
                ctx.principal = sbproxy_plugin::Principal {
                    tenant_id: sbproxy_plugin::TenantId::from(ctx.tenant_id.as_str()),
                    sub: vk_name.clone(),
                    source: sbproxy_plugin::PrincipalSource::VirtualKey,
                    virtual_key: Some(sbproxy_plugin::VirtualKeyRef {
                        name: vk_name,
                        allowed_providers: vk.allowed_providers.clone(),
                    }),
                    attrs,
                };
                // Resolve business attribution tags once now that the
                // credential principal is set: credential `attrs:`
                // defaults merged with the inbound SB-Attr-* headers.
                // Fanned out to the per-attribution spend metric and the
                // access log so spend pivots on project / feature / team
                // / customer / environment / agent_type / risk_tier.
                ctx.attribution_tags =
                    crate::server::ai_support::resolve_attribution_tags(session, &ctx.principal);
                // WOR-1558: enforce the key's live requests-per-minute limit.
                // The limit is read from the resolved record (via the cache),
                // so a PATCH to a dynamic key's rate takes effect on the next
                // request without a reload. The bucket is keyed by the stable
                // key id, never the secret.
                if vk.max_requests_per_minute.is_some()
                    && !key_rate_limiter().check_rate(&vk.key, &vk)
                {
                    warn!(
                        key = %vk.name.as_deref().unwrap_or(&vk.key),
                        "AI proxy: per-key requests-per-minute limit exceeded"
                    );
                    send_error(session, 429, "rate limit exceeded for this key").await?;
                    return Ok(());
                }
                // WOR-1563: record the request into the cross-replica rate
                // counter (mesh CRDT) so a key's fleet-wide rate is visible to
                // every replica. No-op unless the mesh tier is enabled.
                if let Some(counters) = crate::mesh_counters::current_mesh_counters() {
                    counters.record_request(&vk.key);
                }
                // WOR-893: per-key model routing. When the key pins a
                // model, overwrite the request body's `model` field so
                // the downstream allow/block, routing, budget, and
                // model-extraction steps all see the pinned value (and
                // a client-supplied `model` is ignored). Composes
                // naturally with `allowed_models` / `blocked_models`:
                // if the pinned model is itself blocked or not on the
                // allow-list, the existing gate still rejects.
                if let Some(route_to) = &vk.route_to_model {
                    if let Some(obj) = body.as_object_mut() {
                        obj.insert(
                            "model".to_string(),
                            serde_json::Value::String(route_to.clone()),
                        );
                    }
                }
                // WOR-893 PR2 + WOR-1646: per-key tool injection. The
                // key's tool set REPLACES any client-supplied `tools`
                // so the key fully owns the tool surface the caller
                // exposes. Static `inject_tools` JSON and a
                // federation-sourced `inject_mcp` compose: the live
                // MCP catalogue (RBAC-filtered by this principal,
                // converted to the requested provider shape) is
                // appended to the static set.
                let mut injected: Vec<serde_json::Value> = vk.inject_tools.clone();
                if let Some(inject) = &vk.inject_mcp {
                    match sbproxy_modules::action::lookup_inject_source(&inject.reference) {
                        Some(source) => {
                            injected.extend(source.resolve_tools(
                                &ctx.principal,
                                &inject.filter,
                                inject.format,
                            ));
                        }
                        None => {
                            warn!(
                                mcp_ref = %inject.reference,
                                "AI proxy: inject_mcp references an unknown MCP gateway; no tools injected"
                            );
                        }
                    }
                }
                if !injected.is_empty() {
                    if let Some(obj) = body.as_object_mut() {
                        obj.insert("tools".to_string(), serde_json::Value::Array(injected));
                    }
                }
                // Per-key model gate. Enforce the matched key's
                // `allowed_models` / `blocked_models` against the
                // effective model (after any `route_to_model` rewrite),
                // mirroring the action-level gate above but scoped to
                // this virtual key. A key allow-listed to a subset of
                // the gateway's models is rejected with 403 when it asks
                // for a model outside that subset; the block-list takes
                // precedence over the allow-list.
                let effective_model = body
                    .get("model")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if !effective_model.is_empty() {
                    let blocked = vk.blocked_models.iter().any(|m| m == &effective_model);
                    let allowed = vk.allowed_models.is_empty()
                        || vk.allowed_models.iter().any(|m| m == &effective_model);
                    if blocked || !allowed {
                        let msg =
                            format!("model '{}' is not allowed for this key", effective_model);
                        warn!(model = %effective_model, "AI proxy: model blocked for virtual key");
                        send_error(session, 403, &msg).await?;
                        return Ok(());
                    }
                }
            }
        }
    }

    // --- Budget enforcement (pre-dispatch) ---
    //
    // Consult the process-wide BudgetTracker against every configured
    // limit. The first limit that fires decides the action: `block`
    // returns 402, `log` warns and continues, `downgrade` rewrites the
    // request's model to the limit's `downgrade_to` (or the cheapest
    // configured model when unset). Scope keys for `User`, `ApiKey`,
    // and `Tag` are derived from common request headers; missing
    // headers cause those limits to be skipped silently.
    let budget_keys: Vec<(usize, String)> = if let Some(ref budget_cfg) = config.budget {
        let auth_header = req_header_value(session, "authorization");
        let user_header = req_header_value(session, "x-user-id")
            .or_else(|| req_header_value(session, "x-end-user"));
        let tag_header = req_header_value(session, "x-sbproxy-tag");
        let model_for_scope = if model.is_empty() {
            None
        } else {
            Some(model.as_str())
        };
        let keys = budget_scope_keys(
            budget_cfg,
            hostname,
            auth_header.as_deref(),
            user_header.as_deref(),
            model_for_scope,
            Some(hostname),
            tag_header.as_deref(),
        );
        // WOR-1722: pre-fetch the cluster-shared spend for these keys so
        // the preflight enforces against the fleet total (empty map, hence
        // local-only, when shared budgets are off).
        let shared_spend = super::budget_share::read_shared_for_keys(&keys).await;
        match budget_preflight(budget_cfg, &keys, &config.providers, &shared_spend) {
            BudgetGate::Allow => {
                // WOR-1544: predictive soft-landing. Below the hard cap,
                // warn and then downgrade as a scope approaches its
                // window limit, instead of a cliff at 100%.
                if budget_cfg.soft_landing.is_some() {
                    let decision = BUDGET_TRACKER.soft_landing(budget_cfg, &keys);
                    ctx.ai_budget_fraction = decision.fraction;
                    match decision.action {
                        sbproxy_ai::budget::SoftLandingAction::Warn => {
                            tracing::warn!(
                                fraction = decision.fraction,
                                "AI budget: approaching limit (soft-landing warn)"
                            );
                            keys
                        }
                        sbproxy_ai::budget::SoftLandingAction::Downgrade { to } => {
                            let target = to.or_else(|| {
                                let mut candidates: Vec<String> = Vec::new();
                                for p in &config.providers {
                                    for m in &p.models {
                                        candidates.push(m.as_str().to_string());
                                    }
                                }
                                sbproxy_ai::cheapest_model(&candidates)
                            });
                            match target {
                                Some(new_model) if new_model != model => {
                                    tracing::warn!(
                                        fraction = decision.fraction,
                                        new_model = %new_model,
                                        "AI budget: soft-landing downgrade before hard cap"
                                    );
                                    model = new_model.clone();
                                    body["model"] = serde_json::Value::String(new_model);
                                    // Record the soft-landing in the usage
                                    // record / ledger via the policy tag,
                                    // without clobbering an explicit tag.
                                    ctx.ai_policy_sink_tag
                                        .get_or_insert_with(|| "budget_soft_landing".to_string());
                                    budget_scope_keys(
                                        budget_cfg,
                                        hostname,
                                        auth_header.as_deref(),
                                        user_header.as_deref(),
                                        Some(model.as_str()),
                                        Some(hostname),
                                        tag_header.as_deref(),
                                    )
                                }
                                _ => keys,
                            }
                        }
                        sbproxy_ai::budget::SoftLandingAction::None => keys,
                    }
                } else {
                    keys
                }
            }
            BudgetGate::Block { status, body: err } => {
                sbproxy_ai::tracing_spans::record_error(
                    &ai_span,
                    sbproxy_ai::tracing_spans::error_type::BUDGET_EXCEEDED,
                    "AI budget exceeded",
                );
                send_response(session, status, "application/json", &err).await?;
                return Ok(());
            }
            BudgetGate::Downgrade { model: new_model } => {
                model = new_model.clone();
                body["model"] = serde_json::Value::String(new_model);
                // Recompute scope keys against the rewritten model so
                // post-dispatch usage records on the chosen model
                // rather than the original.
                budget_scope_keys(
                    budget_cfg,
                    hostname,
                    auth_header.as_deref(),
                    user_header.as_deref(),
                    Some(model.as_str()),
                    Some(hostname),
                    tag_header.as_deref(),
                )
            }
        }
    } else {
        Vec::new()
    };

    sbproxy_ai::tracing_spans::record_request_params(
        &ai_span,
        body.get("temperature").and_then(serde_json::Value::as_f64),
        body.get("max_tokens").and_then(serde_json::Value::as_u64),
        body.get("top_p").and_then(serde_json::Value::as_f64),
    );

    // --- Pre-request token estimate + TPM reservation ---
    //
    // For chat completions only: we have the parsed `messages` array,
    // so we can pass it through the tiktoken-rs estimator. Other
    // surfaces (embeddings, images, audio, ...) book a token-free
    // reservation that exercises only the RPM / RPD / concurrent axes;
    // their byte-size budgets land at reconcile time the same way the
    // WOR-223 default path handles them.
    //
    // The reservation is keyed on the hashed authorization value the
    // budget block already extracted shape-for-shape (or an empty
    // string when no header was sent). When `model_rate_limits` does
    // not list the resolved model, the limiter still books a per-key
    // reservation against a zero-cap bucket and admits the request
    // without gating, so the cost of a miss is one HashMap lookup.
    if let Some(rate_cfg) = config.model_rate_limits.get(&model) {
        let apikey = req_header_value(session, "authorization").unwrap_or_default();
        let parsed_messages = body
            .get("messages")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| serde_json::from_value::<sbproxy_ai::Message>(m.clone()).ok())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let estimated = sbproxy_ai::estimate_tokens(&model, &parsed_messages);
        match AI_MODEL_RATE_LIMITER.admit_with_tenant(
            &apikey,
            &model,
            ctx.tenant_id.as_ref(),
            rate_cfg,
            Some(estimated),
        ) {
            Ok(admission) => {
                ctx.ai_admission = Some(admission);
            }
            Err(rej) => {
                warn!(
                    ai.surface = surface_label,
                    model = %model,
                    axis = rej.reason.axis_label(),
                    retry_after = rej.retry_after_secs,
                    estimated_tokens = estimated,
                    "AI proxy: model rate limit hit pre-flight; returning 429"
                );
                let retry = rej.retry_after_secs.to_string();
                let extra: Option<(&str, &str)> = Some(("retry-after", &retry));
                sbproxy_ai::tracing_spans::record_error(
                    &ai_span,
                    sbproxy_ai::tracing_spans::error_type::RATE_LIMITED,
                    "model rate limit exceeded",
                );
                send_response_with_extra(
                    session,
                    429,
                    "application/json",
                    br#"{"error":{"message":"rate limit exceeded","type":"rate_limit_error"}}"#,
                    extra,
                )
                .await?;
                return Ok(());
            }
        }
    }

    // --- Prompt classifier hook (fail-open) ---
    //
    // If the enterprise prompt classifier is wired into the pipeline, call
    // it here with a best-effort extraction of the last user-visible prompt
    // text. Any failure (None verdict, panic, transport error) is swallowed
    // silently: the request continues on the normal path.
    //
    // Arc-clone so we release the borrow on `pipeline.hooks` before any
    // await that might need mutable state from the pipeline elsewhere.
    // Keep a single extraction available to both the prompt classifier
    // and the intent detection hook so we do not re-parse the body twice.
    let extracted_prompt = extract_prompt_text(&body);
    let trace_content = AiTraceContentArgs::from_config(config);

    // WOR-1228: emit the prompt as the OpenInference `input.value` span
    // attribute when the origin opts into content capture. Off by default;
    // the text is routed through the always-on secret redactor and the
    // origin's PII redactor (if any) before it lands on the span, so a
    // trace backend never sees raw secrets or PII.
    if trace_content.enabled() && !extracted_prompt.is_empty() {
        let trace_messages = extract_prompt_trace_messages(&body);
        record_ai_input_trace(&ai_span, trace_content, &extracted_prompt, &trace_messages);
    }

    if let Some(hook) = pipeline.hooks.prompt_classifier.as_ref().cloned() {
        if !extracted_prompt.is_empty() {
            let model_id = if model.is_empty() {
                None
            } else {
                Some(model.clone())
            };
            // WOR-1035: the extractor in `ai_support::extract_prompt_text`
            // covers tool-use, multimodal (image/audio), system prompts,
            // OpenAI Responses input/output/summary text, Anthropic
            // thinking blocks, and OpenAI reasoning items. New vendor
            // shapes hit the generic `_` arm that pulls `text` / recurses
            // into `content`.
            let classify_req = crate::hooks::ClassifyRequest {
                origin: hostname.to_string(),
                model_id,
                prompt: extracted_prompt.clone(),
                headers: snapshot_request_headers(session),
            };
            if let Some(verdict) = hook.classify_prompt(&classify_req).await {
                debug!(
                    origin = %hostname,
                    labels = ?verdict.labels,
                    confidence = verdict.confidence,
                    "AI proxy: prompt classified"
                );
                // Attach verdict fields to the current tracing span so log
                // sinks and trace exporters pick them up without a
                // bespoke metric.
                let span = tracing::Span::current();
                span.record("classifier.labels", tracing::field::debug(&verdict.labels));
                span.record("classifier.confidence", verdict.confidence);
                // F5: stash the verdict onto the request context so
                // downstream modifiers, transforms, routing, and metrics
                // can branch on it without re-running the classifier.
                ctx.classifier_prompt = Some(verdict);
            }
        }
    }

    // --- Intent detection hook (F5, fail-open) ---
    //
    // Separate hook from prompt classification: `IntentDetectionHook` maps
    // the raw prompt to a coarse task category (coding, vision, analysis,
    // summarization, general) that is useful for provider routing. A
    // missing result is silently ignored so the AI request still flows.
    if let Some(hook) = pipeline.hooks.intent_detection.as_ref().cloned() {
        if !extracted_prompt.is_empty() {
            if let Some(cat) = hook.detect(&extracted_prompt).await {
                debug!(
                    origin = %hostname,
                    intent = ?cat,
                    "AI proxy: intent detected"
                );
                let span = tracing::Span::current();
                span.record("classifier.intent", tracing::field::debug(&cat));
                ctx.classifier_intent = Some(cat);
            }
        }
    }

    // WOR-1154: input guardrails run BEFORE the semantic-cache
    // lookup below, so a prompt a guardrail would block cannot be
    // served from a cache hit that short-circuits the request.
    // --- Input guardrails: check messages before forwarding ---
    if let Some(ref guardrails_config) = config.guardrails {
        // WOR-1529: external HTTP guardrail providers (Presidio / Lakera /
        // Aporia / custom) run before the built-in pipeline. Input-mode
        // guardrails inspect the request content and block on a not-allowed
        // verdict; `logging_only` records only, and errors honor each
        // guardrail's `fail_open` flag.
        if !guardrails_config.external.is_empty() {
            let input_text = {
                let messages: Vec<sbproxy_ai::Message> = body
                    .get("messages")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|m| {
                                serde_json::from_value::<sbproxy_ai::Message>(m.clone()).ok()
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                if messages.is_empty() {
                    sbproxy_ai::handler::extract_input_text(&surface, &body).unwrap_or_default()
                } else {
                    sbproxy_ai::guardrails::message_text(&messages)
                }
            };
            if !input_text.is_empty() {
                if let Some((name, reason)) =
                    sbproxy_ai::external_guardrail::run_input_external_guardrails(
                        &guardrails_config.external,
                        &input_text,
                    )
                    .await
                {
                    warn!(
                        guardrail = %name,
                        reason = %reason,
                        "AI proxy: external input guardrail blocked request"
                    );
                    sbproxy_ai::tracing_spans::record_error(
                        &ai_span,
                        sbproxy_ai::tracing_spans::error_type::GUARDRAIL_BLOCKED,
                        &reason,
                    );
                    ctx.ai_outcome = Some("guardrail_block".to_string());
                    let error_body = serde_json::json!({
                        "error": {
                            "message": reason,
                            "type": "guardrail_violation",
                            "code": name,
                        }
                    });
                    let body_bytes = serde_json::to_vec(&error_body).unwrap_or_default();
                    send_response(session, 400, "application/json", &body_bytes).await?;
                    return Ok(());
                }
            }
        }
        if let Some(pipeline) = cached_guardrails_pipeline(guardrails_config) {
            if pipeline.has_input() {
                // Parse messages from the body. WOR-1145: deserialize
                // each element independently rather than the whole array
                // at once. A single malformed entry (e.g. a numeric
                // `role`) must not make `from_value::<Vec<Message>>` fail
                // and yield an EMPTY vec, which would silently skip the
                // input guardrails on the remaining valid messages. The
                // body-aware `check_input_body` below still scans the raw
                // body, so content in an unparseable element is not lost.
                let messages: Vec<sbproxy_ai::Message> = body
                    .get("messages")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|m| {
                                serde_json::from_value::<sbproxy_ai::Message>(m.clone()).ok()
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                // WOR-1543: when a guardrail mesh is configured, run the
                // messages-path detectors as a cascade, collect the full
                // verdict set, and fuse it (block on a quorum, optional
                // redact-and-continue). The label set is stashed on the
                // context so the AI policy plane can reason over it.
                // Otherwise fall back to the serial block-on-any check.
                if let Some(mesh_cfg) = guardrails_config.mesh.clone() {
                    let mesh = sbproxy_ai::guardrails::GuardrailMesh::new(mesh_cfg);
                    let text = sbproxy_ai::guardrails::message_text(&messages);
                    let decision = mesh.evaluate_input(&pipeline, &messages, &text);
                    ctx.ai_guardrail_labels = decision.labels.clone();
                    if decision.block {
                        warn!(
                            guardrails = ?decision.labels,
                            "AI proxy: guardrail mesh blocked request"
                        );
                        let reason = decision.reasons.join("; ");
                        sbproxy_ai::tracing_spans::record_error(
                            &ai_span,
                            sbproxy_ai::tracing_spans::error_type::GUARDRAIL_BLOCKED,
                            &reason,
                        );
                        ctx.ai_outcome = Some("guardrail_block".to_string());
                        let error_body = serde_json::json!({
                            "error": {
                                "message": reason,
                                "type": "guardrail_violation",
                                "code": decision.labels.join(","),
                            }
                        });
                        let body_bytes = serde_json::to_vec(&error_body).unwrap_or_default();
                        send_response(session, 400, "application/json", &body_bytes).await?;
                        return Ok(());
                    }
                    if decision.redact {
                        if let Some(redactor) = config.pii_redactor() {
                            redactor.redact_json(&mut body);
                        }
                    }
                } else if let Some(block) = pipeline.check_input(&messages) {
                    warn!(
                        guardrail = %block.name,
                        reason = %block.reason,
                        "AI proxy: input guardrail blocked request"
                    );
                    sbproxy_ai::tracing_spans::record_error(
                        &ai_span,
                        sbproxy_ai::tracing_spans::error_type::GUARDRAIL_BLOCKED,
                        &block.reason,
                    );
                    // WOR-1496: a guardrail block surfaces as a generic
                    // 400, so stamp the precise outcome for the
                    // value-vs-waste metric.
                    ctx.ai_outcome = Some("guardrail_block".to_string());
                    let error_body = serde_json::json!({
                        "error": {
                            "message": block.reason,
                            "type": "guardrail_violation",
                            "code": block.name,
                        }
                    });
                    let body_bytes = serde_json::to_vec(&error_body).unwrap_or_default();
                    send_response(session, 400, "application/json", &body_bytes).await?;
                    return Ok(());
                }

                // WOR-801: body-aware input guardrails (today only
                // `agent_alignment`, which reads `messages[].tool_calls`
                // out of the raw body because the `Message` struct
                // strips them). Runs after the text-shaped check so
                // the cheap path short-circuits first.
                // WOR-1645: pass the principal so the agent-alignment
                // guardrail's shared MCP rbac_policy is evaluated
                // against each model-emitted tool call, the same deny
                // rule the mcp action enforces on tools/call.
                if let Some(block) =
                    pipeline.check_input_body_with_principal(&body, Some(&ctx.principal))
                {
                    warn!(
                        guardrail = %block.name,
                        reason = %block.reason,
                        "AI proxy: body-aware input guardrail blocked request"
                    );
                    sbproxy_ai::tracing_spans::record_error(
                        &ai_span,
                        sbproxy_ai::tracing_spans::error_type::GUARDRAIL_BLOCKED,
                        &block.reason,
                    );
                    // WOR-1496: a guardrail block surfaces as a generic
                    // 400, so stamp the precise outcome for the
                    // value-vs-waste metric.
                    ctx.ai_outcome = Some("guardrail_block".to_string());
                    let error_body = serde_json::json!({
                        "error": {
                            "message": block.reason,
                            "type": "guardrail_violation",
                            "code": block.name,
                        }
                    });
                    let body_bytes = serde_json::to_vec(&error_body).unwrap_or_default();
                    send_response(session, 400, "application/json", &body_bytes).await?;
                    return Ok(());
                }

                // Per-surface input guardrails: image generation,
                // audio speech, reranking, and moderations carry user
                // input in a non-messages field (`prompt`, `input`,
                // `query`). The same guardrail pipeline applies to
                // that text via check_input_text. Chat-shape surfaces
                // are already covered by the messages check above.
                if let Some(text) = sbproxy_ai::handler::extract_input_text(&surface, &body) {
                    if let Some(block) = pipeline.check_input_text(&text) {
                        warn!(
                            ai.surface = surface_label,
                            guardrail = %block.name,
                            reason = %block.reason,
                            "AI proxy: per-surface input guardrail blocked request"
                        );
                        sbproxy_ai::tracing_spans::record_error(
                            &ai_span,
                            sbproxy_ai::tracing_spans::error_type::GUARDRAIL_BLOCKED,
                            &block.reason,
                        );
                        // WOR-1496: stamp the precise outcome (the wire
                        // status is a generic 400).
                        ctx.ai_outcome = Some("guardrail_block".to_string());
                        let error_body = serde_json::json!({
                            "error": {
                                "message": block.reason,
                                "type": "guardrail_violation",
                                "code": block.name,
                            }
                        });
                        let body_bytes = serde_json::to_vec(&error_body).unwrap_or_default();
                        send_response(session, 400, "application/json", &body_bytes).await?;
                        return Ok(());
                    }
                }
            }
        }
    }

    // --- WOR-1542: unified AI policy plane ---
    //
    // After guardrail evaluation and before provider selection, evaluate
    // one sandboxed CEL expression over the AI decision signals and apply
    // its closed action set (block / redact / route_to / set_sink_tag /
    // audit). Default off: the hook only runs when an `ai_policy` block is
    // configured and compiled. A policy bug fails open (see `on_error`).
    if let Some(policy) = config.ai_policy() {
        let view = sbproxy_ai::ai_policy::AiDecisionView {
            surface: surface_label.to_string(),
            model: model.clone(),
            provider: config
                .providers
                .first()
                .map(|p| p.name.to_string())
                .unwrap_or_default(),
            tenant: ctx.tenant_id.to_string(),
            api_key_id: ctx.principal.api_key_id().to_string(),
            // The risk tier rides on the attribution tags resolved at the
            // handler entry. Guardrail labels and the budget fraction are
            // populated by the guardrail mesh and predictive budgets
            // respectively; until those land they are empty/zero and the
            // policy keys on principal / surface / model.
            tier: ctx.attribution_tags.risk_tier.clone().unwrap_or_default(),
            // Populated by the guardrail mesh (WOR-1543) when configured.
            guardrail_labels: ctx.ai_guardrail_labels.clone(),
            // Populated by predictive soft-landing (WOR-1544).
            budget_fraction: ctx.ai_budget_fraction,
            budget_exceeded: ctx.ai_budget_fraction >= 1.0,
            input_tokens_est: ctx.ai_prompt_tokens_est.unwrap_or(0) as i64,
        };
        let decision = policy.evaluate(&view);

        if let Some(priority) = decision.audit_priority() {
            info!(
                ai.surface = surface_label,
                ai.policy_priority = priority,
                ai.policy_actions = ?decision.actions,
                "AI policy: audit event"
            );
        }

        if decision.is_block() {
            warn!(ai.surface = surface_label, "AI policy: blocked request");
            ctx.ai_outcome = Some("policy_block".to_string());
            let error_body = serde_json::json!({
                "error": {
                    "message": "blocked by AI policy",
                    "type": "ai_policy_block",
                }
            });
            let body_bytes = serde_json::to_vec(&error_body).unwrap_or_default();
            send_response(session, 403, "application/json", &body_bytes).await?;
            return Ok(());
        }

        if decision.redact() {
            if let Some(redactor) = config.pii_redactor() {
                redactor.redact_json(&mut body);
            }
        }

        if let Some(target) = decision.route_model() {
            if !target.is_empty() && target != model {
                info!(from = %model, to = %target, "AI policy: route_to override");
                model = target.to_string();
                body["model"] = serde_json::Value::String(target.to_string());
                ctx.ai_model = Some(target.to_string());
            }
        }

        if let Some(tag) = decision.sink_tag() {
            ctx.ai_policy_sink_tag = Some(tag.to_string());
        }
    }

    // --- Semantic lookup hook (A21/F3+F4, fail-open) ---
    //
    // When the enterprise semantic cache is wired, ask the hook whether
    // an equivalent response is already cached. On HIT we short-circuit
    // the upstream dispatch by replaying the cached status, headers, and
    // body directly to the client. The return path here matches the OSS
    // `response_cache` replay in `request_filter`: write the response
    // header, then write the body with `end_of_stream = true`. Callers
    // in `handle_action` treat a successful return from `handle_ai_proxy`
    // as a short-circuit (Ok(true)), so no additional signaling is
    // required.
    //
    // On MISS, we remember the composed cache `miss_key` plus the per-
    // origin gating policy (`cacheable_status`, `max_response_size`) so
    // the write-on-miss branch further down can persist the upstream
    // response into the cache without re-running the embedding + LSH
    // pipeline.
    //
    // When populated, the relay path below dispatches a `hook.store`
    // after the upstream call completes (subject to status + size gates).
    let mut semcache_miss: Option<PendingSemcacheMiss> = None;
    if let Some(hook) = pipeline.hooks.semantic_lookup.as_ref().cloned() {
        if !extracted_prompt.is_empty() {
            let model_id = if model.is_empty() {
                None
            } else {
                Some(model.clone())
            };
            let lookup_req = crate::hooks::LookupRequest {
                origin: hostname.to_string(),
                model_id: model_id.clone(),
                prompt: extracted_prompt.clone(),
                request_headers: snapshot_request_headers(session),
                request_body: body_bytes.clone(),
                method: method.as_str().to_string(),
                path: path.clone(),
            };
            let outcome = hook.lookup(&lookup_req).await;
            if let Some(cached) = outcome.hit {
                debug!(
                    origin = %hostname,
                    status = cached.status,
                    body_len = cached.body.len(),
                    "AI proxy: semantic cache HIT; replaying cached response"
                );

                // Build a Pingora ResponseHeader from the cached entry.
                // Size hint: cached headers + x-semcache marker.
                let mut header = pingora_http::ResponseHeader::build(
                    cached.status,
                    Some(cached.headers.len() + 1),
                )
                .map_err(|e| {
                    Error::because(
                        ErrorType::InternalError,
                        "semantic cache: failed to build response header",
                        e,
                    )
                })?;
                for (name, value) in &cached.headers {
                    // Skip hop-by-hop / framing headers that Pingora will
                    // recompute for us. We intentionally preserve content-type
                    // and any origin-provided response metadata.
                    let lname = name.to_ascii_lowercase();
                    if lname == "transfer-encoding" || lname == "connection" {
                        continue;
                    }
                    let _ = header.insert_header(name.clone(), value.clone());
                }
                // Always emit the debug marker so operators and integration
                // tests can distinguish a replayed hit from an upstream
                // response. Matches OSS `x-sbproxy-cache: HIT` convention.
                let _ = header.insert_header("x-semcache", "HIT");

                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                session
                    .write_response_body(Some(cached.body.clone()), true)
                    .await?;
                return Ok(());
            }
            // MISS with a usable key: remember enough state to populate the
            // cache once we get the upstream response back.
            if let Some(key) = outcome.miss_key {
                semcache_miss = Some((
                    hook,
                    key,
                    outcome.cacheable_status,
                    outcome.max_response_size,
                    model_id,
                ));
            }
        }
    }

    // --- WOR-796: OSS embedding semantic cache (lookup) ---
    //
    // Runs only when the enterprise `SemanticLookupHook` is absent, so
    // the two never double-cache. On a miss we embed the prompt once,
    // cosine-scan the cache, and replay the closest response that meets
    // the configured threshold. A miss remembers the key + vector so
    // the relay can store the upstream response. Embedding failures
    // fail open (proceed to the upstream uncached).
    let mut embed_miss: Option<PendingEmbedMiss> = None;
    if pipeline.hooks.semantic_lookup.is_none() {
        if let Some(cache) = config.embedding_cache() {
            // WOR-1142: scope cache entries to the caller so one
            // tenant/credential never receives another's cached response.
            let cache_scope = sbproxy_ai::EmbeddingCache::scope_key(
                ctx.tenant_id.as_str(),
                req_header_value(session, "authorization").as_deref(),
            );
            if !extracted_prompt.is_empty() {
                // WOR-1223: vectorize the prompt via the configured source.
                // Provider hits the embedding API (costs money, egresses the
                // prompt); sidecar uses the local classifier sidecar (free, no
                // egress). Any error falls through to an uncached upstream call.
                let query_vec_result: anyhow::Result<Vec<f32>> = match cache.source() {
                    sbproxy_ai::semantic_cache::EmbeddingSource::Provider => {
                        match config.providers.iter().find(|p| p.name == cache.provider()) {
                            Some(provider) => {
                                let ai_client = AI_CLIENT.load_full();
                                sbproxy_ai::semantic_cache::compute_embedding(
                                    &ai_client,
                                    provider,
                                    cache.model(),
                                    &extracted_prompt,
                                )
                                .await
                            }
                            None => Err(anyhow::anyhow!(
                                "semantic cache embedding provider {} not found in providers list",
                                cache.provider()
                            )),
                        }
                    }
                    sbproxy_ai::semantic_cache::EmbeddingSource::Sidecar => {
                        match cache.sidecar_config() {
                            Some(sc) => {
                                sbproxy_ai::semantic_cache::compute_embedding_sidecar(
                                    sc,
                                    &extracted_prompt,
                                )
                                .await
                            }
                            None => Err(anyhow::anyhow!(
                                "semantic cache sidecar source has no sidecar config"
                            )),
                        }
                    }
                    sbproxy_ai::semantic_cache::EmbeddingSource::Inprocess => {
                        #[cfg(feature = "inprocess-embed")]
                        {
                            match cache.inprocess_config() {
                                Some(cfg) => crate::server::ai_support::inprocess_embed(
                                    cfg,
                                    &extracted_prompt,
                                ),
                                None => Err(anyhow::anyhow!(
                                    "inprocess embedding source has no inprocess config"
                                )),
                            }
                        }
                        #[cfg(not(feature = "inprocess-embed"))]
                        {
                            Err(anyhow::anyhow!(
                                "in-process embedding not compiled in this build; rebuild with \
                                 --features inprocess-embed or use source: sidecar"
                            ))
                        }
                    }
                    sbproxy_ai::semantic_cache::EmbeddingSource::Openai => {
                        match cache.openai_config() {
                            Some(oc) => {
                                sbproxy_ai::semantic_cache::compute_embedding_openai(
                                    oc,
                                    &extracted_prompt,
                                )
                                .await
                            }
                            None => Err(anyhow::anyhow!(
                                "semantic cache openai source has no openai config"
                            )),
                        }
                    }
                };
                let source_label: &str = match cache.source() {
                    sbproxy_ai::semantic_cache::EmbeddingSource::Provider => "provider",
                    sbproxy_ai::semantic_cache::EmbeddingSource::Sidecar => "sidecar",
                    sbproxy_ai::semantic_cache::EmbeddingSource::Inprocess => "inprocess",
                    sbproxy_ai::semantic_cache::EmbeddingSource::Openai => "openai",
                };
                match query_vec_result {
                    Ok(query_vec) => {
                        if let Some(hit) = cache.lookup(&query_vec, &cache_scope) {
                            sbproxy_ai::ai_metrics::record_cache_result(
                                cache.provider(),
                                "semantic",
                                true,
                            );
                            sbproxy_observe::metrics::record_semantic_cache(
                                ctx.tenant_id.as_str(),
                                hostname,
                                source_label,
                                "hit",
                            );
                            sbproxy_ai::ai_metrics::record_semantic_similarity(
                                cache.provider(),
                                hit.score,
                            );
                            debug!(
                                tenant = %ctx.tenant_id,
                                origin = %hostname,
                                score = hit.score,
                                status = hit.response.status,
                                "AI proxy: embedding semantic cache HIT; replaying"
                            );
                            let mut header = pingora_http::ResponseHeader::build(
                                hit.response.status,
                                Some(hit.response.headers.len() + 1),
                            )
                            .map_err(|e| {
                                Error::because(
                                    ErrorType::InternalError,
                                    "embedding cache: failed to build response header",
                                    e,
                                )
                            })?;
                            for (name, value) in &hit.response.headers {
                                if name == "transfer-encoding" || name == "connection" {
                                    continue;
                                }
                                let _ = header.insert_header(name.clone(), value.clone());
                            }
                            let _ = header.insert_header("x-semcache", "HIT");
                            // `hit.response` is a shared `Arc` (WOR-1703);
                            // materialize the body for replay off the
                            // cache lock rather than deep-cloning the
                            // response inside the critical section.
                            let body = bytes::Bytes::from(hit.response.body.clone());
                            // WOR-1094: a cache hit is a zero-cost
                            // ledger transaction, not an absent one.
                            // Record the served tokens under the
                            // cache_read dimension so the hit still
                            // shows up as savings.
                            crate::server::ai_support::record_cache_hit_savings(
                                ctx.tenant_id.as_str(),
                                ctx.principal.api_key_id(),
                                hostname,
                                cache.provider(),
                                cache.model(),
                                surface_label,
                                &body,
                                &ctx.attribution_tags,
                            );
                            session
                                .write_response_header(Box::new(header), false)
                                .await?;
                            session.write_response_body(Some(body), true).await?;
                            return Ok(());
                        }
                        sbproxy_ai::ai_metrics::record_cache_result(
                            cache.provider(),
                            "semantic",
                            false,
                        );
                        sbproxy_observe::metrics::record_semantic_cache(
                            ctx.tenant_id.as_str(),
                            hostname,
                            source_label,
                            "miss",
                        );
                        embed_miss = Some((
                            std::sync::Arc::clone(cache),
                            sbproxy_ai::EmbeddingCache::prompt_key(&cache_scope, &extracted_prompt),
                            query_vec,
                            cache_scope,
                        ));
                    }
                    Err(e) => {
                        sbproxy_observe::metrics::record_semantic_cache(
                            ctx.tenant_id.as_str(),
                            hostname,
                            source_label,
                            "error",
                        );
                        warn!(
                            tenant = %ctx.tenant_id,
                            origin = %hostname,
                            error = %e,
                            "AI proxy: embedding cache lookup failed (fail-open)"
                        );
                    }
                }
            }
        }
    }

    // Check if streaming is requested.
    let is_stream = body
        .get("stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // WOR-1545: LLM-aware context-window compression. When enabled, fit an
    // over-long prompt to the resolved model's context window before
    // dispatch, dropping the oldest non-system turns, so the request
    // succeeds on the same model instead of being rejected with a
    // context-length error. No-op for unknown models, non-chat surfaces, or
    // prompts that already fit.
    if let Some(llm) = config
        .resilience
        .as_ref()
        .and_then(|r| r.llm_aware.as_ref())
    {
        if llm.context_compress && !model.is_empty() {
            if let Some(messages) = body.get("messages").and_then(|v| v.as_array()) {
                let reserve = llm.completion_reserve_tokens.unwrap_or(1024);
                if let Some(trimmed) =
                    sbproxy_ai::context_compress::fit_messages_to_model(messages, &model, reserve)
                {
                    let removed = messages.len().saturating_sub(trimmed.len());
                    if removed > 0 {
                        warn!(
                            model = %model,
                            removed,
                            "AI proxy: context-window compress, trimmed oldest messages to fit"
                        );
                        body["messages"] = serde_json::Value::Array(trimmed);
                    }
                }
            }
        }
    }

    // Build a list of providers to try, in priority order for failover.
    let is_failover = matches!(config.routing, sbproxy_ai::RoutingStrategy::FallbackChain);
    // Default retry-on-status codes for failover.
    let retry_statuses: Vec<u16> = vec![500, 502, 503];
    // WOR-1545 / WOR-1524: optional per-error-class retry policy. When set,
    // the failover loop classifies each failure and consults it in addition
    // to the status-code set above.
    let retry_policy = config
        .resilience
        .as_ref()
        .and_then(|r| r.retry_policy.as_ref());

    // Surface-specific request-body inspection captured once before
    // the failover loop so each attempt's BudgetRecorderArgs carries
    // the same record. For image_generation, we capture the `size`
    // field so the response-side billing event can emit an
    // `Images { count, resolution }` variant with a real resolution.
    let image_resolution_for_billing: Option<String> =
        if matches!(surface, sbproxy_ai::handler::AiSurface::ImageGeneration) {
            body.get("size").and_then(|v| v.as_str()).map(String::from)
        } else {
            None
        };

    // For audio speech, capture the input character count once
    // before the failover loop. The TTS provider bills per character
    // of `input` text; counting at the request boundary is exact and
    // doesn't require parsing the binary audio response body.
    let audio_speech_characters_for_billing: Option<u64> =
        if matches!(surface, sbproxy_ai::handler::AiSurface::AudioSpeech) {
            body.get("input")
                .and_then(|v| v.as_str())
                .map(|s| s.chars().count() as u64)
        } else {
            None
        };

    // For reranking, capture the document count from the request
    // body. The provider bills per document scored; counting at the
    // request boundary is exact (reranking responses always return
    // exactly as many results as documents in the request).
    let rerank_documents_for_billing: Option<u64> =
        if matches!(surface, sbproxy_ai::handler::AiSurface::Reranking) {
            body.get("documents")
                .and_then(|v| v.as_array())
                .map(|a| a.len() as u64)
        } else {
            None
        };

    // WOR-1146: pre-compute an estimated prompt-token count for
    // chat_completions, captured once from the request body before the
    // failover loop. The response handler uses it to debit the budget
    // from an estimate when a 2xx response carries no parseable `usage`
    // block (a usage-less 200 would otherwise run unlimited token
    // volume against the cap). Parsed per-element so one malformed
    // message does not zero the estimate (mirrors the input-guardrail
    // message parse).
    let estimated_prompt_tokens_for_budget: Option<u64> =
        if matches!(surface, sbproxy_ai::handler::AiSurface::ChatCompletions) {
            body.get("messages").and_then(|v| v.as_array()).map(|arr| {
                let msgs: Vec<sbproxy_ai::Message> = arr
                    .iter()
                    .filter_map(|m| serde_json::from_value::<sbproxy_ai::Message>(m.clone()).ok())
                    .collect();
                let model = body.get("model").and_then(|v| v.as_str()).unwrap_or("");
                // WOR-1499: stamp the request-path prompt accounting on
                // the context: the estimate (also reused as the
                // failed/blocked-request token volume in WOR-1497) and a
                // salted, non-reversible fingerprint that lets identical
                // prompts be correlated without persisting prompt text.
                ctx.ai_prompt_fingerprint = Some(sbproxy_ai::prompt_fingerprint(model, &msgs));
                sbproxy_ai::estimate_tokens(model, &msgs)
            })
        } else {
            None
        };
    ctx.ai_prompt_tokens_est = estimated_prompt_tokens_for_budget;

    // WOR-1545: content-policy fallback re-routes a refusal to the next
    // (more permissive) provider, so it needs the loop to iterate the
    // provider order even when the strategy is not a fallback chain.
    let content_policy_fallback = config
        .resilience
        .as_ref()
        .map(|r| r.content_policy_fallback)
        .unwrap_or(false);

    // Parse retry config from the action config's routing.retry section.
    // This is done by inspecting the raw handler config.
    let max_attempts = if is_failover || content_policy_fallback {
        config.providers.len()
    } else {
        1
    };

    // Build sorted provider list for failover (by priority).
    let mut provider_order: Vec<usize> = config
        .providers
        .iter()
        .enumerate()
        .filter(|(_, p)| p.enabled)
        .collect::<Vec<_>>()
        .into_iter()
        .map(|(i, _)| i)
        .collect();

    // WOR-799: disallow_prompt_training routing filter. When the
    // request opts out of training (header
    // `x-sbproxy-disallow-prompt-training: true`), route only to
    // providers the operator declared `no_prompt_training`. There is
    // no standardized per-request training opt-out header across
    // providers, so this gateway-side filter is the enforcement
    // point: fail closed (400) when no compliant provider qualifies
    // rather than send the prompt to a training-eligible upstream.
    let disallow_training = session
        .req_header()
        .headers
        .get("x-sbproxy-disallow-prompt-training")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);
    if disallow_training {
        provider_order.retain(|&i| config.providers[i].no_prompt_training);
        if provider_order.is_empty() {
            let err = serde_json::json!({"error": {
                "message": "disallow_prompt_training requested but no configured provider is marked no_prompt_training",
                "type": "no_compliant_provider",
            }});
            let body_bytes = serde_json::to_vec(&err).unwrap_or_default();
            send_response(session, 400, "application/json", &body_bytes).await?;
            return Ok(());
        }
    }
    // WOR-1534: model-based provider routing. When the requested model is
    // declared in one or more providers' `models` lists, restrict the routing
    // set to those providers so the model name selects the vendor (a provider
    // that enumerates no models acts as a wildcard and stays eligible). If no
    // provider declares the model, the order is left unchanged so unenumerated
    // models still pass straight through to the configured providers. This runs
    // before the strategy below, so round_robin / fallback_chain / cost_quality
    // all choose from the model-eligible set.
    if let Some(eligible) = model_eligible_providers(&provider_order, &config.providers, &model) {
        provider_order = eligible;
    }

    // WOR-797: cost/quality routing. When configured, score the inbound
    // prompt's difficulty and pin the routing set to the cheap or
    // frontier provider. Composes after the disallow filter: if the
    // chosen provider is not in the (possibly filtered) eligible set, we
    // log and fall through to the default order rather than override it.
    if let Some(cq) = router.cost_quality_config() {
        let prompt = sbproxy_ai::cost_quality::prompt_text_for_scoring(&body);
        let difficulty = sbproxy_ai::cost_quality::heuristic_difficulty(&prompt);
        let tier = sbproxy_ai::cost_quality::route_tier(cq, difficulty);
        let target = match tier {
            sbproxy_ai::cost_quality::Tier::Cheap => cq.cheap_provider.clone(),
            sbproxy_ai::cost_quality::Tier::Frontier => cq.frontier_provider.clone(),
        };
        match provider_order
            .iter()
            .copied()
            .find(|&i| config.providers[i].name == target)
        {
            Some(idx) => {
                tracing::info!(
                    event = "ai.cost_quality.route",
                    tier = tier.label(),
                    difficulty = difficulty,
                    provider = %target,
                    "cost/quality routing selected provider"
                );
                provider_order = vec![idx];
            }
            None => {
                tracing::warn!(
                    event = "ai.cost_quality.route_miss",
                    tier = tier.label(),
                    provider = %target,
                    "cost/quality target provider not eligible; using default order"
                );
            }
        }
    }
    if is_failover {
        provider_order.sort_by_key(|&i| config.providers[i].priority.unwrap_or(u32::MAX));
    }
    // WOR-798: honor latency/usage/rotation strategies on the failover
    // path. For strategies that pick a primary via the router
    // (peak_ewma, least_token_usage, lowest_latency, round_robin, ...),
    // move the router-selected provider to the front of the failover
    // order; the remaining providers stay as fallbacks. Failover
    // (priority sort above), cascade, and cost_quality manage their own
    // ordering and are left untouched.
    if !is_failover && router.cascade_config().is_none() && router.cost_quality_config().is_none() {
        // WOR-798: prefix-affinity strategies (self-hosted vLLM /
        // SGLang KV-cache reuse) need the request's prompt prefix
        // to hash to a sticky upstream. Other strategies ignore the
        // prefix and select() handles them.
        let primary = if router.is_prefix_affinity() {
            let prefix = extract_prefix_key(&body, 1024);
            router.select_with_prefix(&config.providers, &prefix)
        } else {
            router.select_with_allowed(
                &config.providers,
                ctx.principal
                    .virtual_key
                    .as_ref()
                    .map(|vk| vk.allowed_providers.as_slice())
                    .unwrap_or(&[]),
            )
        };
        if let Some(primary) = primary {
            if let Some(pos) = provider_order.iter().position(|&i| i == primary) {
                let p = provider_order.remove(pos);
                provider_order.insert(0, p);
            }
        }
    }
    // Cascade + streaming: cascade does not retry mid-stream, so
    // we dispatch to tier 1 only and let the streaming relay
    // handle the response unchanged. The model substitution is
    // applied to the request body below in the per-provider loop.
    if let Some(cascade_cfg) = router.cascade_config().filter(|_| !disallow_training) {
        if is_stream {
            if let Some(first_tier) = cascade_cfg.tiers.first() {
                if let Some(idx) = config
                    .providers
                    .iter()
                    .position(|p| p.enabled && p.name == first_tier.provider_id)
                {
                    provider_order = vec![idx];
                    if let Some(obj) = body.as_object_mut() {
                        obj.insert(
                            "model".to_string(),
                            serde_json::Value::String(first_tier.model.clone()),
                        );
                    }
                }
            }
        }
    }

    let mut last_resp: Option<reqwest::Response> = None;
    let mut last_format: sbproxy_ai::providers::ProviderFormat =
        sbproxy_ai::providers::ProviderFormat::OpenAi;
    let mut last_error: Option<anyhow::Error> = None;
    let mut last_error_type: &'static str = sbproxy_ai::tracing_spans::error_type::PROVIDER_ERROR;
    // Track the upstream URL host of the provider that produced
    // `last_resp`. Used by the streaming usage parser's `auto`
    // resolver so a Vertex / Bedrock / Cohere host picks the right
    // parser without operators having to override `usage_parser`.
    let mut last_upstream_host: Option<String> = None;
    // Track the provider name that produced `last_resp` so the
    // billing event emission outside the for loop can attribute the
    // request to the right provider without re-deriving from
    // `provider_idx`.
    let mut last_provider_name: String = String::new();

    // --- Cascade routing ---
    //
    // When the configured strategy is `Cascade`, dispatch through
    // the dedicated tier-by-tier path which reads each response
    // body, checks `confidence_score` against the tier's threshold,
    // and retries on the next tier when the score is sub-threshold,
    // empty, or refused. Streaming requests fall through to the
    // standard dispatch loop below; mid-stream retry is out of
    // scope for v1. The cascade path writes the response back to
    // the client directly because it already has the body bytes;
    // skipping `relay_ai_response_with_cache` also means cascade
    // does not engage the semantic cache write or idempotency
    // capture in v1, which is documented in the example README.
    if let Some(cascade_cfg) = router.cascade_config().filter(|_| !disallow_training) {
        if !is_stream {
            let outcome = AI_CLIENT
                .load()
                .forward_cascade(
                    config,
                    cascade_cfg,
                    &path,
                    &body,
                    &ctx.attribution_tags,
                    surface_label,
                )
                .await;
            match outcome {
                Ok(o) => {
                    ctx.ai_provider = Some(o.provider_name.clone());
                    if !o.model.is_empty() {
                        ctx.ai_model = Some(o.model.clone());
                    }
                    let content_type = o
                        .headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                        .map(|(_, v)| v.clone())
                        .unwrap_or_else(|| "application/json".to_string());
                    let translated = sbproxy_ai::format::rewrap_response_for_inbound(
                        ctx.ai_inbound_format.as_deref(),
                        &o.body,
                    );
                    emit_ai_billing_event(
                        surface_label,
                        &o.provider_name,
                        Some(o.model.clone()),
                        sbproxy_ai::budget::AiUsage::PerCall,
                        0.0,
                        Vec::new(),
                        &ctx.attribution_tags,
                        ctx.tenant_id.as_str(),
                        ctx.principal.api_key_id(),
                        &ai_span,
                    );
                    // Drop any idempotency capture: cascade does not
                    // engage the idempotency cache write in v1
                    // because the response body is already
                    // materialized outside the relay path.
                    let _ = idem_capture.take();
                    let _ = idem_skip_reason;
                    return send_response(session, o.status, &content_type, &translated).await;
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "AI proxy: cascade dispatch failed; returning 502"
                    );
                    return Err(Error::because(
                        ErrorType::ConnectError,
                        "AI cascade failed",
                        e,
                    ));
                }
            }
        }
    }

    // --- Hedged / raced dispatch (WOR-1545) ---
    //
    // When the configured strategy is `race`, fan the request out to every
    // eligible provider concurrently and keep the first 2xx response,
    // dropping (cancelling) the losers. This trades extra upstream calls
    // for lower tail latency. Streaming and single-provider requests fall
    // through to the sequential path below (mid-stream racing is out of
    // scope); the operator opted into the extra calls, so a raced request
    // does not also run the sequential failover loop afterward.
    let race_mode = router.is_race() && !is_stream && provider_order.len() >= 2;
    if race_mode {
        use futures::stream::{FuturesUnordered, StreamExt as _};
        let client = AI_CLIENT.load();
        let race_start = std::time::Instant::now();
        let mut futs = FuturesUnordered::new();
        for &idx in &provider_order {
            let provider = &config.providers[idx];
            let mut attempt_body = body.clone();
            if !model.is_empty() {
                let mapped = provider.map_model(&model);
                if mapped != model {
                    attempt_body["model"] = serde_json::Value::String(mapped);
                }
            }
            let path_ref = path.as_str();
            let cl = &client;
            futs.push(async move {
                let r = cl.forward_request(provider, path_ref, &attempt_body).await;
                (idx, r)
            });
        }

        // Keep the first 2xx; hold the first non-2xx response as a
        // fallback so the client still sees an upstream error rather than a
        // synthetic one when every candidate fails.
        let mut winner: Option<(usize, reqwest::Response)> = None;
        let mut fallback: Option<(usize, reqwest::Response)> = None;
        while let Some((idx, res)) = futs.next().await {
            match res {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    router.record_latency(idx, race_start.elapsed().as_micros() as u64);
                    let outcome = if (200..300).contains(&status) {
                        "success"
                    } else {
                        "error"
                    };
                    sbproxy_observe::metrics::record_provider_attempt(
                        &config.providers[idx].name,
                        outcome,
                    );
                    if (200..300).contains(&status) {
                        winner = Some((idx, resp));
                        break;
                    } else if fallback.is_none() {
                        fallback = Some((idx, resp));
                    }
                }
                Err(e) => {
                    sbproxy_observe::metrics::record_provider_attempt(
                        &config.providers[idx].name,
                        "error",
                    );
                    last_error_type = ai_transport_error_type(&e);
                    last_error = Some(e);
                }
            }
        }
        // Dropping the stream cancels any still-in-flight loser request.
        drop(futs);
        drop(client);

        if let Some((idx, resp)) = winner.or(fallback) {
            let provider = &config.providers[idx];
            let resolved_model = if model.is_empty() {
                String::new()
            } else {
                provider.map_model(&model)
            };
            ctx.ai_provider = Some(provider.name.to_string());
            if !resolved_model.is_empty() {
                ctx.ai_model = Some(resolved_model.clone());
            }
            ai_span.record("gen_ai.system", provider.name.as_str());
            ai_span.record("llm.provider", provider.name.as_str());
            if !resolved_model.is_empty() {
                ai_span.record("gen_ai.request.model", resolved_model.as_str());
                ai_span.record("llm.model_name", resolved_model.as_str());
            }
            sbproxy_ai::ai_metrics::record_model_latency(
                &provider.name,
                ctx.ai_model.as_deref().unwrap_or(""),
                surface_label,
                ctx.tenant_id.as_str(),
                ctx.principal.api_key_id(),
                race_start.elapsed().as_secs_f64(),
            );
            last_format = sbproxy_ai::client::provider_format(provider);
            last_upstream_host = url::Url::parse(&provider.effective_base_url())
                .ok()
                .and_then(|u| u.host_str().map(|h| h.to_string()));
            last_provider_name = provider.name.to_string();
            last_resp = Some(resp);
        }
    }

    for (attempt, &provider_idx) in provider_order.iter().enumerate() {
        // The raced dispatch above already produced `last_resp` (or an
        // error); skip the sequential failover loop entirely.
        if race_mode {
            break;
        }
        if attempt >= max_attempts {
            break;
        }
        // WOR-1680: a provider with a serve: block hosts its model on
        // this box. Resolve its live loopback engine port and route
        // there instead of a base_url (which a served provider does not
        // carry). Bring the engine to ready on demand. If it cannot be
        // brought up, treat this like a failed attempt and fail over to
        // the next provider (a lone served provider that fails then
        // yields the "no provider succeeded" 502 after the loop).
        let mut resolved_provider = config.providers[provider_idx].clone();
        if resolved_provider.serve.is_some() {
            let requested = (!model.is_empty()).then_some(model.as_str());
            match crate::server::model_host::served_upstream(config, &resolved_provider, requested)
                .await
            {
                Ok(Some(url)) => resolved_provider.base_url = Some(url),
                Ok(None) => {}
                Err(e) => {
                    sbproxy_observe::metrics::record_provider_attempt(
                        &resolved_provider.name,
                        "error",
                    );
                    warn!(
                        provider = %resolved_provider.name,
                        attempt = %attempt,
                        "AI proxy: local engine unavailable, failing over: {e}. \
                         Run `sbproxy doctor` to check local-serving prerequisites \
                         (GPU, inference engine, weights)"
                    );
                    continue;
                }
            }
        }
        let provider = &resolved_provider;

        // Map model name for this provider.
        let mut attempt_body = body.clone();
        let resolved_model = if !model.is_empty() {
            let mapped = provider.map_model(&model);
            if mapped != model {
                debug!(original = %model, mapped = %mapped, provider = %provider.name, "AI proxy: mapped model name");
                attempt_body["model"] = serde_json::Value::String(mapped.clone());
            }
            mapped
        } else {
            String::new()
        };

        // Stamp the resolved provider + model on the context so the
        // access log captures them even when the upstream errors out
        // before the body decode runs. Token counts land later in
        // the response-handling path (see `extract_usage`).
        ctx.ai_provider = Some(provider.name.to_string());
        if !resolved_model.is_empty() {
            ctx.ai_model = Some(resolved_model.clone());
        }
        // WOR-1809: mark served-provider attempts so the response
        // handler can rewrite the engine's `model` field (a local
        // engine reports its weights file path there) back to the
        // serve-entry name the client asked for. Reset per attempt so
        // a failover to a hosted lane clears it.
        ctx.ai_serve_model = (provider.serve.is_some() && !resolved_model.is_empty())
            .then(|| resolved_model.clone());
        ai_span.record("gen_ai.system", provider.name.as_str());
        ai_span.record("llm.provider", provider.name.as_str());
        if !resolved_model.is_empty() {
            ai_span.record("gen_ai.request.model", resolved_model.as_str());
            ai_span.record("llm.model_name", resolved_model.as_str());
        }

        // WOR-229: native-format bypass. When the inbound client
        // format equals the upstream provider's wire format, send
        // the inbound body verbatim to the upstream's native path
        // and skip the hub round-trip. `native_bypass_for` returns
        // `None` for any mismatched pair, in which case the existing
        // hub-mediated `forward_request` call below runs. Streaming
        // bypass is out of scope for this iteration; the upstream
        // returns native SSE that the streaming relay would need to
        // emit as-is, which is a separate code path. Track this as a
        // follow-up.
        let provider_format = sbproxy_ai::client::provider_format(provider);
        let bypass = if is_stream {
            None
        } else {
            sbproxy_ai::format::native_bypass_for(
                ctx.ai_inbound_format.as_deref(),
                provider_format,
                &provider.name,
            )
        };
        let upstream_call: Option<(bytes::Bytes, &'static str)> = match bypass {
            Some(sbproxy_ai::format::NativeBypass::AnthropicMessages) => {
                // Anthropic Messages -> Anthropic upstream: re-emit
                // the native body bytes (with the resolved model
                // substituted in) to the upstream's `/v1/messages`
                // path. The OpenAI Chat hub body that lives in
                // `attempt_body` is discarded for this iteration.
                match make_native_bypass_body(&native_request_bytes_for_bypass, &resolved_model) {
                    Ok(body) => {
                        sbproxy_ai::ai_metrics::record_native_bypass(
                            sbproxy_ai::format::NativeBypass::AnthropicMessages.inbound_label(),
                            sbproxy_ai::format::NativeBypass::AnthropicMessages.provider_label(),
                        );
                        ctx.ai_native_bypass = true;
                        Some((
                            body,
                            sbproxy_ai::format::NativeBypass::AnthropicMessages.native_path(),
                        ))
                    }
                    Err(e) => {
                        // If the native body fails to parse here
                        // something is very wrong; fall back to the
                        // hub path so the request still has a chance
                        // of succeeding.
                        warn!(
                            error = %e,
                            provider = %provider.name,
                            "WOR-229: native bypass body remap failed; falling back to hub path"
                        );
                        ctx.ai_native_bypass = false;
                        None
                    }
                }
            }
            Some(sbproxy_ai::format::NativeBypass::OpenAiChat) => {
                // OpenAI Chat -> OpenAI-compatible upstream: the
                // current hub path is already a byte forward for
                // this pair, so the bypass is just a metric tag.
                // `attempt_body` already carries the model remap; we
                // leave the hub call below to run unchanged.
                sbproxy_ai::ai_metrics::record_native_bypass(
                    sbproxy_ai::format::NativeBypass::OpenAiChat.inbound_label(),
                    sbproxy_ai::format::NativeBypass::OpenAiChat.provider_label(),
                );
                ctx.ai_native_bypass = true;
                None
            }
            None => None,
        };

        let attempt_start = std::time::Instant::now();
        // WOR-1103: wrap each upstream attempt in its own span so a
        // forced failover shows one child span per provider tried, with
        // the attempt index and outcome visible in the trace (the
        // matching per-provider attempt counter is recorded below). The
        // call future is `.instrument`ed rather than entered with a
        // guard because the dispatch task must stay `Send` across the
        // await.
        use tracing::Instrument as _;
        let attempt_span = tracing::debug_span!(
            "ai.provider.attempt",
            provider = %provider.name,
            attempt = attempt,
        );
        let result = async {
            if let Some((bypass_body, native_path)) = upstream_call {
                AI_CLIENT
                    .load()
                    .forward_native_bypass(provider, &method_str, native_path, bypass_body)
                    .await
            } else {
                AI_CLIENT
                    .load()
                    .forward_request(provider, &path, &attempt_body)
                    .await
            }
        }
        .instrument(attempt_span)
        .await;

        match result {
            Ok(resp) => {
                // WOR-798: feed the latency-aware LB. Record the upstream
                // round-trip latency for this provider so `peak_ewma` /
                // `lowest_latency` reflect live data on the next request.
                router.record_latency(provider_idx, attempt_start.elapsed().as_micros() as u64);
                let status = resp.status().as_u16();
                // WOR-1545 / WOR-1524: retry on the default status-code set,
                // or on a per-error-class policy decision when configured.
                // Classification from status alone is enough for the
                // retryable classes (timeout / rate-limit / server error);
                // the body-refined classes (context-window, content-policy)
                // are not retried in place anyway.
                let retry_by_status = status >= 500 && retry_statuses.contains(&status);
                let retry_by_policy = retry_policy.is_some_and(|p| {
                    p.should_retry(
                        sbproxy_ai::failure_cause::FailureCause::classify(status, ""),
                        attempt,
                    )
                });
                if is_failover && (retry_by_status || retry_by_policy) && attempt + 1 < max_attempts
                {
                    // WOR-1103: record the failed attempt so per-provider
                    // load distribution and failure rates are visible,
                    // not just the fact that a failover happened.
                    sbproxy_observe::metrics::record_provider_attempt(&provider.name, "error");
                    // WOR-1535: count the handover so sbproxy_ai_failovers_total
                    // reflects real failovers (it was defined but never recorded).
                    let to_provider = provider_order
                        .get(attempt + 1)
                        .map(|&i| config.providers[i].name.clone())
                        .unwrap_or_default();
                    sbproxy_ai::ai_metrics::record_failover(
                        &provider.name,
                        &to_provider,
                        &format!("http_{status}"),
                    );
                    warn!(
                        provider = %provider.name,
                        status = %status,
                        attempt = %attempt,
                        "AI proxy: provider returned error, trying next"
                    );
                    // Consume the response body to avoid connection leak.
                    let _ = resp.bytes().await;
                    continue;
                }
                // WOR-1545: content-policy fallback. A 4xx may be a
                // content-policy / safety refusal rather than a client
                // error; route it to the next (more permissive) provider
                // instead of returning the refusal. Classifying requires
                // the body, which consumes the response, so a 4xx that is
                // NOT a content-policy refusal (or that has no more
                // permissive provider left) is returned here as a
                // passthrough rather than re-wrapped through the relay.
                if content_policy_fallback && (400..500).contains(&status) {
                    let content_type = resp
                        .headers()
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("application/json")
                        .to_string();
                    let body_bytes = resp.bytes().await.unwrap_or_default();
                    let cause = sbproxy_ai::failure_cause::FailureCause::classify(
                        status,
                        &String::from_utf8_lossy(&body_bytes),
                    );
                    if cause == sbproxy_ai::failure_cause::FailureCause::ContentPolicy
                        && attempt + 1 < provider_order.len()
                        && attempt + 1 < max_attempts
                    {
                        ctx.ai_outcome = Some("content_filter".to_string());
                        let to_provider = provider_order
                            .get(attempt + 1)
                            .map(|&i| config.providers[i].name.clone())
                            .unwrap_or_default();
                        sbproxy_observe::metrics::record_provider_attempt(&provider.name, "error");
                        sbproxy_ai::ai_metrics::record_failover(
                            &provider.name,
                            &to_provider,
                            "content_policy",
                        );
                        warn!(
                            provider = %provider.name,
                            to = %to_provider,
                            "AI proxy: content-policy refusal, failing over to a more permissive provider"
                        );
                        continue;
                    }
                    sbproxy_observe::metrics::record_provider_attempt(&provider.name, "error");
                    return send_response(session, status, &content_type, &body_bytes).await;
                }
                // WOR-1103: this provider's response is the one we keep.
                // HTTP error statuses still count as provider-attempt
                // errors even when they are not retried, so metrics agree
                // with the request span's final ERROR classification.
                let provider_attempt_outcome = if status >= 400 { "error" } else { "success" };
                sbproxy_observe::metrics::record_provider_attempt(
                    &provider.name,
                    provider_attempt_outcome,
                );
                last_format = sbproxy_ai::client::provider_format(provider);
                last_upstream_host = match url::Url::parse(&provider.effective_base_url()) {
                    Ok(u) => u.host_str().map(|h| h.to_string()),
                    Err(e) => {
                        // WOR-1104: a malformed base URL silently degraded
                        // the streaming usage parser to auto-detection.
                        // Surface it at debug so the cause is traceable.
                        debug!(
                            provider = %provider.name,
                            error = %e,
                            "AI proxy: provider base URL did not parse; streaming usage parser will auto-detect"
                        );
                        None
                    }
                };
                // WOR-1501: capture upstream model latency for the
                // accepted response, keyed by the same authoritative
                // identity dimensions as the spend metrics so p95
                // latency is sliceable per tenant / credential / model
                // (not just globally per provider/model). Measured once
                // per request, on the attempt we keep.
                sbproxy_ai::ai_metrics::record_model_latency(
                    &provider.name,
                    ctx.ai_model.as_deref().unwrap_or(""),
                    surface_label,
                    ctx.tenant_id.as_str(),
                    ctx.principal.api_key_id(),
                    attempt_start.elapsed().as_secs_f64(),
                );
                last_provider_name = provider.name.to_string();
                last_resp = Some(resp);
                break;
            }
            Err(e) => {
                // WOR-1103: a transport-level failure is an attempt
                // outcome too; count it per provider.
                sbproxy_observe::metrics::record_provider_attempt(&provider.name, "error");
                warn!(
                    error = %e,
                    provider = %provider.name,
                    attempt = %attempt,
                    "AI proxy: upstream request failed"
                );
                last_error_type = ai_transport_error_type(&e);
                sbproxy_ai::ai_metrics::record_provider_error(
                    &provider.name,
                    ai_metric_error_kind_for_span_error_type(last_error_type),
                );
                last_error = Some(e);
                if attempt + 1 >= max_attempts {
                    break;
                }
                // WOR-1535: count the transport-failure handover.
                let to_provider = provider_order
                    .get(attempt + 1)
                    .map(|&i| config.providers[i].name.clone())
                    .unwrap_or_default();
                sbproxy_ai::ai_metrics::record_failover(&provider.name, &to_provider, "transport");
                continue;
            }
        }
    }

    if let Some(resp) = last_resp {
        if is_stream {
            // SSE streaming with idempotency engaged: drop the capture
            // (releases the per-origin pool permit) and abandon
            // caching for this request. v1 does not buffer SSE
            // chunks into the idempotency cache because framing-aware
            // capture is out of scope here; the response headers
            // have already been written when the relay realizes
            // we'd exceed the cap on a chunked body, so the
            // skip marker is not visible to the client. The
            // operator-visible signal is the absence of a cache hit
            // on retry, plus the debug log line below.
            if idem_capture.take().is_some() {
                debug!(
                    "AI proxy: idempotency miss on streaming request; abandoning cache record (SSE framing-aware capture is out of scope for v1)"
                );
            }
            let _ = idem_skip_reason;
            let model_id = if model.is_empty() {
                None
            } else {
                Some(model.clone())
            };
            // NOTE: semantic-cache write-on-miss is intentionally skipped
            // for streaming responses. Accumulating an SSE stream into a
            // single cache entry would change its delivery semantics;
            // supporting it requires framing-aware capture that is out of
            // scope for F4. Any stashed `semcache_miss` state is simply
            // dropped here.
            //
            // SSE event-shape translation for non-OpenAI providers
            // (Anthropic `content_block_delta` to OpenAI `delta`) is
            // also out of scope for the first translator landing; non-
            // OpenAI streams pass through in their native shape today
            // and this is documented as a known limitation in
            // docs/providers.md.
            // The semcache_miss tuple captures the key the lookup hook
            // composed for a non-streaming MISS path. We do not write
            // the assembled SSE body back into the literal semantic
            // cache (framing-aware capture is out of scope here), but
            // we do hand the same key to the streaming cache recorder
            // so the enterprise impl can record the chunk stream
            // against it.
            let semcache_key: Option<String> =
                semcache_miss.as_ref().map(|(_, key, _, _, _)| key.clone());
            let _ = semcache_miss;
            // SSE event-shape translation for non-OpenAI providers
            //. When the upstream emits Anthropic
            // `event: content_block_delta`, Gemini
            // `streamGenerateContent`, or Bedrock Converse-stream
            // payloads, the relay reframes them into the hub
            // vocabulary and re-emits in the inbound format's wire
            // shape so clients see a uniform stream. The
            // OpenAI-in-OpenAI-out branch stays a pure byte forward.
            let stream_inbound_format: Option<String> = ctx.ai_inbound_format.clone();
            // Opaque pass-through of the AI handler's
            // `semantic_cache.streaming` block. The OSS proxy never
            // validates this; the enterprise recorder reads whatever
            // shape it expects (e.g. `enabled`, `replay_pacing`).
            let stream_policy = config
                .semantic_cache
                .as_ref()
                .and_then(|sc| sc.get("streaming"))
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let request_id = ctx.request_id.to_string();
            let origin_id = origin_idx.map(|i| i.to_string()).unwrap_or_default();
            // The streaming relay receives the same budget recorder the
            // non-streaming path does so a stream that emits a terminal
            // `usage` block (OpenAI) or a `message_delta` (Anthropic)
            // still charges the configured scopes after it closes.
            let stream_recorder = config.budget.as_ref().map(|b| BudgetRecorderArgs {
                config: b,
                keys: &budget_keys,
                model: model.as_str(),
                surface_label,
                provider_name: last_provider_name.as_str(),
                image_resolution: image_resolution_for_billing.clone(),
                audio_speech_characters: audio_speech_characters_for_billing,
                rerank_documents: rerank_documents_for_billing,
                attribution_tags: ctx.attribution_tags.clone(),
                tenant_id: ctx.tenant_id.to_string(),
                api_key_id: ctx.principal.api_key_id().to_string(),
                estimated_prompt_tokens: estimated_prompt_tokens_for_budget,
            });
            let stream_router_sink = RouterTokenSink {
                router: &router,
                config_providers: &config.providers,
                provider_name: last_provider_name.as_str(),
            };
            // Capture parser hints from the upstream response before it
            // gets moved into relay_ai_stream. The streaming relay
            // resolves `usage_parser: auto` against these hints.
            let resp_content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let resp_x_provider = resp
                .headers()
                .get("x-provider")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let usage_parser_cfg = config.usage_parser.clone();
            let upstream_host = last_upstream_host.clone();
            // WOR-1044 PR2: snapshot the reversible-PII capture for
            // the streaming relay. The chunk loop reads it through
            // `StreamingReversibleRestore`. Cloned because the
            // streaming relay owns the vec for the life of the SSE
            // session and the dispatcher still needs `ctx` after
            // this call returns. The vec is small (one entry per
            // reversible match this request fired) so the clone is
            // cheap.
            let stream_reversible_pairs: Vec<(String, String, String)> =
                ctx.ai_reversible_redactions.clone();
            relay_ai_stream(
                session,
                resp,
                pipeline,
                hostname,
                model_id,
                origin_idx,
                StreamCacheRecorderArgs {
                    request_id,
                    origin_id,
                    semantic_key: semcache_key,
                    policy: stream_policy,
                },
                stream_recorder,
                stream_router_sink,
                StreamUsageParserArgs {
                    configured: usage_parser_cfg,
                    upstream_host,
                    content_type: resp_content_type,
                    x_provider: resp_x_provider,
                },
                StreamFormatArgs {
                    upstream_format: last_format,
                    inbound_format: stream_inbound_format,
                },
                ai_span.clone(),
                trace_content,
                stream_reversible_pairs,
                // WOR-1141: streaming output guardrails (only when the
                // origin declares output guardrails).
                config
                    .guardrails
                    .as_ref()
                    .and_then(cached_guardrails_pipeline)
                    .filter(|p| p.has_output()),
            )
            .await
        } else {
            // Non-streaming: relay plus optional cache write on miss.
            // When a miss_key was captured during the lookup phase and
            // the upstream response passes the status + size gates, we
            // dispatch `hook.store` best-effort (fail-open).
            let recorder = config.budget.as_ref().map(|b| BudgetRecorderArgs {
                config: b,
                keys: &budget_keys,
                model: model.as_str(),
                surface_label,
                provider_name: last_provider_name.as_str(),
                image_resolution: image_resolution_for_billing.clone(),
                audio_speech_characters: audio_speech_characters_for_billing,
                rerank_documents: rerank_documents_for_billing,
                attribution_tags: ctx.attribution_tags.clone(),
                tenant_id: ctx.tenant_id.to_string(),
                api_key_id: ctx.principal.api_key_id().to_string(),
                estimated_prompt_tokens: estimated_prompt_tokens_for_budget,
            });
            let cache_router_sink = RouterTokenSink {
                router: &router,
                config_providers: &config.providers,
                provider_name: last_provider_name.as_str(),
            };
            relay_ai_response_with_cache(
                session,
                resp,
                last_format,
                hostname,
                semcache_miss,
                embed_miss,
                config.max_body_size,
                recorder,
                cache_router_sink,
                Some(ctx),
                ai_span.clone(),
                trace_content,
                idem_skip_reason,
                idem_capture,
                // WOR-1141: enforce OUTPUT guardrails on the response.
                // Only pass the pipeline when it actually declares
                // output guardrails, so origins without them pay no
                // per-response cost.
                config
                    .guardrails
                    .as_ref()
                    .and_then(cached_guardrails_pipeline)
                    .filter(|p| p.has_output()),
                // WOR-1529: external output guardrails (post_call) run on the
                // response after the sync pipeline; empty when none configured.
                config
                    .guardrails
                    .as_ref()
                    .map(|g| g.external.clone())
                    .unwrap_or_default(),
            )
            .await
        }
    } else if let Some(e) = last_error {
        sbproxy_ai::tracing_spans::record_error(
            &ai_span,
            last_error_type,
            "AI upstream request failed (all providers)",
        );
        Err(Error::because(
            ErrorType::ConnectError,
            "AI upstream request failed (all providers)",
            e,
        ))
    } else {
        warn!("AI proxy: no enabled providers");
        sbproxy_ai::tracing_spans::record_error(
            &ai_span,
            sbproxy_ai::tracing_spans::error_type::PROVIDER_ERROR,
            "no enabled AI providers",
        );
        Err(Error::new(ErrorType::HTTPStatus(502)))
    }
}

fn record_ai_transport_failure(
    span: &tracing::Span,
    provider: Option<&str>,
    error: &anyhow::Error,
    message: &str,
) {
    let kind = ai_transport_error_type(error);
    sbproxy_ai::tracing_spans::record_error(span, kind, message);
    if let Some(provider) = provider.filter(|p| !p.is_empty()) {
        sbproxy_ai::ai_metrics::record_provider_error(
            provider,
            ai_metric_error_kind_for_span_error_type(kind),
        );
    }
}

fn ai_transport_error_type(error: &anyhow::Error) -> &'static str {
    if error
        .downcast_ref::<reqwest::Error>()
        .is_some_and(reqwest::Error::is_timeout)
    {
        sbproxy_ai::tracing_spans::error_type::TIMEOUT
    } else {
        sbproxy_ai::tracing_spans::error_type::PROVIDER_ERROR
    }
}

fn record_ai_provider_response_failure(
    span: &tracing::Span,
    provider: &str,
    status: u16,
    body: Option<&[u8]>,
) {
    let Some(kind) = ai_provider_response_error_type(status, body) else {
        return;
    };
    let message = ai_provider_response_error_message(status, kind);
    sbproxy_ai::tracing_spans::record_error(span, kind, message.as_str());
    if !provider.is_empty() {
        sbproxy_ai::ai_metrics::record_provider_error(
            provider,
            ai_metric_error_kind_for_span_error_type(kind),
        );
    }
}

fn ai_provider_response_error_type(status: u16, body: Option<&[u8]>) -> Option<&'static str> {
    if status == 429 {
        return Some(sbproxy_ai::tracing_spans::error_type::RATE_LIMITED);
    }
    if body.is_some_and(ai_response_body_indicates_content_filter) {
        return Some(sbproxy_ai::tracing_spans::error_type::CONTENT_FILTER);
    }
    if (500..=599).contains(&status) {
        return Some(sbproxy_ai::tracing_spans::error_type::UPSTREAM_5XX);
    }
    if !(200..300).contains(&status) {
        return Some(sbproxy_ai::tracing_spans::error_type::PROVIDER_ERROR);
    }
    None
}

fn ai_provider_response_error_message(status: u16, kind: &str) -> String {
    match kind {
        k if k == sbproxy_ai::tracing_spans::error_type::RATE_LIMITED => {
            format!("AI provider returned rate limit status {status}")
        }
        k if k == sbproxy_ai::tracing_spans::error_type::CONTENT_FILTER => {
            "AI provider content filter rejected the generation".to_string()
        }
        k if k == sbproxy_ai::tracing_spans::error_type::UPSTREAM_5XX => {
            format!("AI provider returned upstream 5xx status {status}")
        }
        _ => format!("AI provider returned HTTP status {status}"),
    }
}

fn ai_metric_error_kind_for_span_error_type(kind: &str) -> &'static str {
    match kind {
        k if k == sbproxy_ai::tracing_spans::error_type::RATE_LIMITED => "rate_limited",
        k if k == sbproxy_ai::tracing_spans::error_type::CONTENT_FILTER => "content_filter",
        k if k == sbproxy_ai::tracing_spans::error_type::UPSTREAM_5XX => "upstream_5xx",
        k if k == sbproxy_ai::tracing_spans::error_type::TIMEOUT => "timeout",
        k if k == sbproxy_ai::tracing_spans::error_type::BUDGET_EXCEEDED => "budget_exceeded",
        k if k == sbproxy_ai::tracing_spans::error_type::GUARDRAIL_BLOCKED => "guardrail_blocked",
        _ => "transport",
    }
}

fn ai_response_body_indicates_content_filter(body: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    ai_json_value_indicates_content_filter(&value)
}

fn ai_json_value_indicates_content_filter(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(_) => false,
        serde_json::Value::Array(items) => items.iter().any(ai_json_value_indicates_content_filter),
        serde_json::Value::Object(map) => map.iter().any(|(key, value)| {
            let key = key.as_str();
            let nested = matches!(key, "error" | "innererror" | "inner_error" | "details");
            let field = matches!(
                key,
                "code" | "type" | "reason" | "message" | "finish_reason" | "stop_reason"
            );
            match value {
                serde_json::Value::String(s) if nested || field => {
                    ai_string_indicates_content_filter(s)
                }
                serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                    ai_json_value_indicates_content_filter(value)
                }
                _ => false,
            }
        }),
        _ => false,
    }
}

fn ai_string_indicates_content_filter(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase().replace(['-', ' '], "_");
    normalized.contains("content_filter")
        || normalized.contains("content_filtered")
        || normalized.contains("content_policy")
        || normalized.contains("responsibleai")
}

/// Relay a non-streaming AI response back to the client. When the
/// upstream provider speaks a non-OpenAI wire format, the response
/// body is translated back into OpenAI shape so OpenAI SDK clients
/// see a uniform interface. `max_body_size` caps the bytes read from
/// the upstream response; an oversized body is rejected with a 502 so
/// a misbehaving provider cannot exhaust gateway memory.
pub(super) async fn relay_ai_response(
    session: &mut Session,
    resp: reqwest::Response,
    format: sbproxy_ai::providers::ProviderFormat,
    max_body_size: Option<usize>,
    inbound_format: Option<&str>,
) -> Result<()> {
    let status = resp.status().as_u16();

    // Collect relevant headers from upstream.
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();

    let resp_body = read_capped_response_body(resp, max_body_size).await?;

    let translated = sbproxy_ai::translators::translate_response_bytes(format, &resp_body);
    let translated = sbproxy_ai::format::rewrap_response_for_inbound(inbound_format, &translated);
    send_response(session, status, &content_type, &translated).await
}

/// Read the upstream response body with an optional byte cap. When the
/// upstream advertises `Content-Length` larger than `max_body_size` we
/// short-circuit before any bytes are buffered. When the framed body
/// is unsized (chunked) we drain the byte stream but stop accumulating
/// once the cap is exceeded and surface a 502 to the caller so an
/// honest upstream cannot OOM the gateway.
pub(super) async fn read_capped_response_body(
    resp: reqwest::Response,
    max_body_size: Option<usize>,
) -> Result<bytes::Bytes> {
    let cap = match max_body_size {
        Some(c) if c > 0 => c,
        _ => {
            return resp.bytes().await.map_err(|e| {
                warn!(error = %e, "AI proxy: failed to read upstream response body");
                Error::because(ErrorType::ReadError, "failed to read upstream response", e)
            });
        }
    };

    if let Some(len) = resp.content_length() {
        if len as usize > cap {
            warn!(
                content_length = %len,
                cap = %cap,
                "AI proxy: upstream Content-Length exceeds max_body_size; refusing to relay"
            );
            return Err(Error::new(ErrorType::HTTPStatus(502)));
        }
    }

    use futures::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf = bytes::BytesMut::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            warn!(error = %e, "AI proxy: failed to read upstream response body");
            Error::because(ErrorType::ReadError, "failed to read upstream response", e)
        })?;
        if buf.len().saturating_add(chunk.len()) > cap {
            warn!(
                cap = %cap,
                read = %buf.len(),
                "AI proxy: upstream response body exceeded max_body_size; refusing to relay"
            );
            return Err(Error::new(ErrorType::HTTPStatus(502)));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf.freeze())
}

/// Relay a non-streaming AI response and, when `miss_info` is present,
/// write the response back into the semantic cache on behalf of the hook.
///
/// `miss_info` is populated only when the preceding lookup missed and
/// produced a usable key. The write is gated by:
///
/// * `cacheable_status`: defaults to `[200]` when empty.
/// * `max_response_size`: defaults to no cap when `None`.
///
/// All failures (read, encode, store) are logged and swallowed so that
/// a cache write problem never turns into a client-visible error. The
/// actual `store` call is dispatched on the existing async runtime; the
/// underlying `RedisSemanticCacheStore` already performs its blocking
/// I/O via `spawn_blocking`, so no additional wrapping is needed here.
#[allow(clippy::too_many_arguments)]
pub(super) async fn relay_ai_response_with_cache(
    session: &mut Session,
    resp: reqwest::Response,
    format: sbproxy_ai::providers::ProviderFormat,
    hostname: &str,
    miss_info: Option<PendingSemcacheMiss>,
    embed_miss: Option<PendingEmbedMiss>,
    max_body_size: Option<usize>,
    budget_recorder: Option<BudgetRecorderArgs<'_>>,
    router_sink: RouterTokenSink<'_>,
    mut ctx: Option<&mut RequestContext>,
    ai_span: tracing::Span,
    trace_content: AiTraceContentArgs<'_>,
    idem_skip_reason: Option<&'static str>,
    idem_capture: Option<AiIdempotencyCapture>,
    output_guardrails: Option<std::sync::Arc<sbproxy_ai::guardrails::GuardrailPipeline>>,
    output_external: Vec<sbproxy_ai::external_guardrail::ExternalGuardrailConfig>,
) -> Result<()> {
    let status = resp.status().as_u16();

    // Collect relevant headers from upstream. We preserve the full header
    // map (lossy to String/String) for the cache entry separately from
    // the single `content-type` we relay via `send_response`, because
    // `send_response` currently only emits `content-type` + recomputed
    // `content-length`. Future work can switch to a richer relay that
    // forwards all upstream headers.
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();

    // Snapshot headers before we consume the response body.
    let mut captured_headers: std::collections::HashMap<String, String> =
        std::collections::HashMap::with_capacity(resp.headers().len());
    for (name, value) in resp.headers() {
        if let Ok(v) = value.to_str() {
            let n = name.as_str().to_ascii_lowercase();
            // Skip hop-by-hop / framing headers so replayed hits don't
            // smuggle e.g. a stale `transfer-encoding: chunked` that no
            // longer matches the replay body.
            if matches!(
                n.as_str(),
                "connection"
                    | "transfer-encoding"
                    | "keep-alive"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailer"
                    | "upgrade"
            ) {
                continue;
            }
            captured_headers.insert(n, v.to_string());
        }
    }

    let raw_body = read_capped_response_body(resp, max_body_size).await?;

    // Translate the upstream body into OpenAI shape once, then both
    // cache and serve the translated form. Caching the translated body
    // means semantic-cache hits replay correctly to OpenAI clients
    // without re-running the translator on every hit.
    let resp_body: bytes::Bytes = if sbproxy_ai::translators::requires_translation(format) {
        bytes::Bytes::from(sbproxy_ai::translators::translate_response_bytes(
            format, &raw_body,
        ))
    } else {
        raw_body
    };

    // WOR-1809: a served (local) engine reports its weights file path
    // in the response's `model` field. Rewrite it to the serve-entry
    // name the client asked for, before the rewrap and the cache
    // writes, so local lanes echo a model id exactly like hosted
    // lanes. Streaming responses keep the engine's string for now
    // (the SSE relay does not materialize chunks).
    let resp_body: bytes::Bytes = match ctx
        .as_ref()
        .and_then(|c| c.ai_serve_model.as_deref())
        .filter(|_| (200..300).contains(&status))
    {
        Some(serve_name) => rewrite_response_model(resp_body, serve_name),
        None => resp_body,
    };

    // Native-format inbound rewrap. When the client entered
    // on a `/v1/messages` or `/v1/responses` path the cached body stays
    // in OpenAI Chat shape (so cross-format cache hits remain cheap)
    // and only the bytes leaving the gateway are re-emitted in the
    // client-expected wire shape.
    //
    // WOR-229 native bypass: when the inbound format matched the
    // upstream provider's wire format, the response is already in the
    // client's expected shape (it came directly from the native
    // upstream path), so the rewrap step is skipped.
    let inbound_format: Option<String> = ctx.as_ref().and_then(|c| c.ai_inbound_format.clone());
    let native_bypass = ctx.as_ref().map(|c| c.ai_native_bypass).unwrap_or(false);
    // WOR-1044: snapshot the reversible redaction pairs before any
    // later branch in this function moves `ctx`. The vec is small
    // (one entry per reversible match this request fired), so the
    // clone is cheap and the borrow rules stay simple.
    let reversible_pairs: Vec<(String, String, String)> = ctx
        .as_ref()
        .map(|c| c.ai_reversible_redactions.clone())
        .unwrap_or_default();
    let resp_body: bytes::Bytes = if native_bypass {
        resp_body
    } else {
        match inbound_format.as_deref() {
            Some("anthropic") | Some("responses") => {
                bytes::Bytes::from(sbproxy_ai::format::rewrap_response_for_inbound(
                    inbound_format.as_deref(),
                    &resp_body,
                ))
            }
            _ => resp_body,
        }
    };

    record_ai_provider_response_failure(
        &ai_span,
        router_sink.provider_name,
        status,
        Some(resp_body.as_ref()),
    );

    if (200..300).contains(&status) {
        record_ai_response_span_metadata(&ai_span, &resp_body);
    }

    // --- WOR-1141: enforce OUTPUT guardrails ---
    //
    // Run the configured output guardrails against the materialized
    // response body BEFORE it is cached (semantic / embedding / idem)
    // or sent, so a violating response is neither stored nor delivered.
    // The check runs on the full response text (shape-agnostic across
    // provider formats); a PII / toxicity / jailbreak / regex match
    // anywhere in the model's output blocks the response. Only 2xx
    // bodies are checked (error envelopes are pass-through). On a block
    // we return a 403 with a `guardrail_violation` envelope and skip
    // every cache write below via the early return.
    // WOR-1529: an output-guardrail block can come from the compiled sync
    // pipeline or from an external provider (`post_call` / `during_call`).
    // Only 2xx text is checked; external runs only when the sync pipeline
    // did not already block, and works even when no sync pipeline is set.
    let output_block: Option<sbproxy_ai::guardrails::GuardrailBlock> = if (200..300)
        .contains(&status)
    {
        match std::str::from_utf8(&resp_body) {
            Ok(text) => {
                let sync_block = output_guardrails
                    .as_ref()
                    .and_then(|g| g.check_output(text));
                if sync_block.is_some() {
                    sync_block
                } else if output_external.is_empty() {
                    None
                } else {
                    sbproxy_ai::external_guardrail::run_output_external_guardrails(
                        &output_external,
                        text,
                    )
                    .await
                    .map(|(name, reason)| sbproxy_ai::guardrails::GuardrailBlock { name, reason })
                }
            }
            Err(_) => None,
        }
    } else {
        None
    };
    if let Some(block) = output_block {
        warn!(
            guardrail = %block.name,
            reason = %block.reason,
            "AI proxy: output guardrail blocked response"
        );
        sbproxy_ai::tracing_spans::record_error(
            &ai_span,
            sbproxy_ai::tracing_spans::error_type::GUARDRAIL_BLOCKED,
            &block.reason,
        );
        // WOR-1496: the block returns a 403, which the
        // status-derived outcome would mislabel as
        // `auth_denied`; stamp the precise outcome so the
        // value-vs-waste metric attributes it correctly.
        if let Some(c) = ctx.as_mut() {
            c.ai_outcome = Some("guardrail_block".to_string());
        }
        // WOR-1093: the upstream already produced (and
        // billed) this 2xx response; an output guardrail
        // then rejected it, so the spend bought no served
        // outcome. Flag the consumed tokens as
        // `validation_failed` waste, reusing the usage
        // already parsed for billing. Observational only.
        if let Some(args) = budget_recorder.as_ref() {
            let (prompt_tokens, completion_tokens, cached_input, cache_creation) =
                extract_usage_full(&resp_body);
            let wasted = prompt_tokens.saturating_add(completion_tokens);
            if wasted > 0 {
                let usage = sbproxy_ai::budget::AiUsage::Tokens {
                    input: prompt_tokens,
                    output: completion_tokens,
                    cached_input,
                    cache_creation,
                };
                let cost = sbproxy_ai::budget::estimate_cost_for_usage(args.model, &usage);
                sbproxy_ai::ai_metrics::record_waste(
                    sbproxy_ai::ai_metrics::WasteKind::ValidationFailed,
                    args.provider_name,
                    args.model,
                    args.surface_label,
                    &args.attribution_tags,
                    wasted,
                    cost,
                );
            }
        }
        let error_body = serde_json::json!({
            "error": {
                "message": block.reason,
                "type": "guardrail_violation",
                "code": block.name,
            }
        });
        let body_bytes = serde_json::to_vec(&error_body).unwrap_or_default();
        return send_response(session, 403, "application/json", &body_bytes).await;
    }

    // --- WOR-796: OSS embedding cache write on miss ---
    //
    // Store the upstream response under the prompt's embedding so a
    // future near-duplicate prompt replays it. Only 200 responses are
    // cached. Mutually exclusive with the enterprise hook store below
    // (the lookup gates on the hook being absent). `captured_headers`
    // is cloned here so the enterprise branch can still move it.
    if let Some((cache, key, embedding, cache_scope)) = embed_miss {
        if status == 200 {
            let cached = sbproxy_ai::CachedHttpResponse {
                status,
                headers: captured_headers
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
                body: resp_body.to_vec(),
            };
            cache.store(key, &embedding, cached, cache_scope);
            debug!(
                origin = %hostname,
                body_len = resp_body.len(),
                "AI proxy: embedding semantic cache write-on-miss stored"
            );
        }
    }

    // --- Semantic cache write on miss ---
    //
    // We write before relaying so the cache entry is durable even if
    // the client disconnects mid-body. `store` is async but non-blocking
    // for our purposes: the Redis-backed implementation already uses
    // `spawn_blocking` internally.
    if let Some((hook, key, cacheable_status, max_size, model_id)) = miss_info {
        let status_ok = if cacheable_status.is_empty() {
            status == 200
        } else {
            cacheable_status.contains(&status)
        };
        let size_ok = max_size.map(|cap| resp_body.len() <= cap).unwrap_or(true);
        if status_ok && size_ok {
            let cached = crate::hooks::CachedResponse {
                status,
                headers: captured_headers,
                body: resp_body.clone(),
                cached_at: std::time::SystemTime::now(),
            };
            let store_req = crate::hooks::StoreRequest {
                origin: hostname.to_string(),
                model_id,
                key: key.clone(),
            };
            // Fire-and-forget. Any error is logged and does not affect
            // the client response.
            match hook.store(store_req, cached).await {
                Ok(()) => {
                    debug!(
                        origin = %hostname,
                        key = %key,
                        body_len = resp_body.len(),
                        "AI proxy: semantic cache write-on-miss succeeded"
                    );
                }
                Err(e) => {
                    warn!(
                        origin = %hostname,
                        error = %e,
                        "AI proxy: semantic cache write-on-miss failed (fail-open)"
                    );
                }
            }
        } else {
            debug!(
                origin = %hostname,
                status = %status,
                body_len = resp_body.len(),
                status_ok = %status_ok,
                size_ok = %size_ok,
                "AI proxy: semantic cache write-on-miss skipped (gate failed)"
            );
        }
    }

    // Record token + cost usage against the configured budget scopes
    // for this request. Best-effort: if the upstream omits a `usage`
    // block (some providers, error responses) we simply skip the
    // record and the limit fires later when a billable response lands.
    if let Some(args) = budget_recorder.as_ref() {
        if (200..300).contains(&status) {
            let (prompt_tokens, completion_tokens, cached_input, cache_creation) =
                extract_usage_full(&resp_body);
            // WOR-1146: when a 2xx chat_completions response carries no
            // parseable `usage`, debit the budget (and feed the router)
            // from an estimate so a usage-less 200 cannot run unlimited
            // token volume against the cap. The measured-usage surfaces
            // below (reconcile, ctx.ai_tokens_*, attribution, the
            // billing event) stay on the real (0,0); the dedicated
            // `sbproxy_ai_usage_parse_miss_total` metric is the signal
            // that an estimate was used, so spend reports never silently
            // mix estimated and measured tokens. Limited to
            // chat_completions for now (the clearest foot-gun and a
            // simple response shape to estimate); embeddings / native
            // `messages` + `responses` / streaming are follow-ups.
            let (budget_prompt_tokens, budget_completion_tokens) = if prompt_tokens == 0
                && completion_tokens == 0
                && args.surface_label == "chat_completions"
            {
                let est_prompt = args.estimated_prompt_tokens.unwrap_or(0);
                let est_completion = estimate_completion_tokens(args.model, &resp_body);
                if est_prompt + est_completion > 0 {
                    sbproxy_observe::metrics::record_ai_usage_parse_miss(
                        args.provider_name,
                        args.surface_label,
                    );
                    (est_prompt, est_completion)
                } else {
                    (prompt_tokens, completion_tokens)
                }
            } else {
                (prompt_tokens, completion_tokens)
            };
            // WOR-232 reconcile: hand the real `usage.prompt_tokens`
            // back to the rate-limit reservation so TPM math settles
            // against the truth. Reservations that never see a usage
            // block fall through to the `Drop` path which refunds the
            // full reservation.
            if let Some(ctx_ref) = ctx.as_mut() {
                if let Some(adm) = ctx_ref.ai_admission.take() {
                    adm.reconcile(prompt_tokens);
                }
            }
            // Stamp the token counts onto the request context so the
            // access log records them alongside the rest of the AI
            // gateway envelope.
            //
            // Emit per-credential attribution to Prometheus alongside
            // the access-log stamp. One row per direction; tag-bearing
            // virtual keys fan out so a multi-tag key shows up under
            // each declared tag. Empty `project` / `user` / `tag`
            // serialise as empty labels and roll up to a Prometheus
            // catch-all bucket.
            if let Some(ctx) = ctx.as_mut() {
                ctx.ai_tokens_in = Some(prompt_tokens);
                ctx.ai_tokens_out = Some(completion_tokens);
                let project = ctx.principal.attrs.project.as_deref().unwrap_or("");
                let user = ctx.principal.attrs.user.as_deref().unwrap_or("");
                if ctx.principal.attrs.tags.is_empty() {
                    sbproxy_observe::metrics::record_tokens_attributed(
                        project,
                        user,
                        "",
                        "input",
                        prompt_tokens,
                    );
                    sbproxy_observe::metrics::record_tokens_attributed(
                        project,
                        user,
                        "",
                        "output",
                        completion_tokens,
                    );
                } else {
                    for tag in &ctx.principal.attrs.tags {
                        sbproxy_observe::metrics::record_tokens_attributed(
                            project,
                            user,
                            tag,
                            "input",
                            prompt_tokens,
                        );
                        sbproxy_observe::metrics::record_tokens_attributed(
                            project,
                            user,
                            tag,
                            "output",
                            completion_tokens,
                        );
                    }
                }
            }
            // WOR-798: feed the router's per-provider token counter
            // so the `LeastTokenUsage` / `TokenRate` strategies see
            // the load this provider just absorbed. The minute
            // window resets via the existing `reset_tokens` ticker
            // (sbproxy-ai/src/routing.rs).
            router_sink.record(budget_prompt_tokens + budget_completion_tokens);
            record_budget_usage(
                args.config,
                args.keys,
                args.model,
                budget_prompt_tokens,
                budget_completion_tokens,
            );
            // WOR-1722: also accumulate into the cluster-shared counters
            // (no-op without a shared store) so other replicas enforce
            // against this spend.
            super::budget_share::record_shared_budget_usage(
                args.config,
                args.keys,
                args.model,
                budget_prompt_tokens,
                budget_completion_tokens,
            )
            .await;
            // Emit a surface-tagged AiBillingEvent alongside the
            // existing budget recording. Token-bearing responses
            // emit a Tokens variant. Image generation responses use
            // the captured request resolution plus a count parsed
            // from the response's `data` array. Other non-token
            // surfaces (audio speech, moderations through the POST
            // path) fall back to PerCall.
            let usage = if prompt_tokens != 0 || completion_tokens != 0 {
                sbproxy_ai::budget::AiUsage::Tokens {
                    input: prompt_tokens,
                    output: completion_tokens,
                    cached_input,
                    cache_creation,
                }
            } else if args.surface_label == "image_generation" {
                let count = serde_json::from_slice::<serde_json::Value>(&resp_body)
                    .ok()
                    .and_then(|v| v.get("data").and_then(|d| d.as_array()).map(|a| a.len()))
                    .unwrap_or(0) as u32;
                sbproxy_ai::budget::AiUsage::Images {
                    count,
                    resolution: args
                        .image_resolution
                        .clone()
                        .unwrap_or_else(|| "1024x1024".to_string()),
                }
            } else if args.surface_label == "audio_speech" {
                sbproxy_ai::budget::AiUsage::Characters {
                    count: args.audio_speech_characters.unwrap_or(0),
                }
            } else if args.surface_label == "reranking" {
                sbproxy_ai::budget::AiUsage::RerankUnits {
                    documents: args.rerank_documents.unwrap_or(0),
                }
            } else {
                sbproxy_ai::budget::AiUsage::PerCall
            };
            let cost = sbproxy_ai::budget::estimate_cost_for_usage(args.model, &usage);
            let scope_keys = args.keys.iter().map(|(_, k)| k.clone()).collect::<Vec<_>>();
            let cost_micros = emit_ai_billing_event(
                args.surface_label,
                args.provider_name,
                Some(args.model.to_string()),
                usage,
                cost,
                scope_keys,
                &args.attribution_tags,
                args.tenant_id.as_str(),
                args.api_key_id.as_str(),
                &ai_span,
            );
            if cost_micros > 0 {
                if let Some(ctx_ref) = ctx.as_mut() {
                    ctx_ref.ai_cost_usd_micros = Some(cost_micros);
                }
            }
        }
    } else if let Some(ctx) = ctx {
        // Even without a budget recorder we still want the access log
        // to capture token usage when the upstream returned a body.
        if (200..300).contains(&status) {
            let (prompt_tokens, completion_tokens, cached_input, cache_creation) =
                extract_usage_full(&resp_body);
            // WOR-232 reconcile: mirror the budget-recorder branch so
            // origins without a configured budget still settle their
            // TPM reservation against the upstream's reported usage.
            if let Some(adm) = ctx.ai_admission.take() {
                adm.reconcile(prompt_tokens);
            }
            if prompt_tokens != 0 || completion_tokens != 0 {
                ctx.ai_tokens_in = Some(prompt_tokens);
                ctx.ai_tokens_out = Some(completion_tokens);
                let usage = sbproxy_ai::budget::AiUsage::Tokens {
                    input: prompt_tokens,
                    output: completion_tokens,
                    cached_input,
                    cache_creation,
                };
                let model = ctx.ai_model.clone().unwrap_or_default();
                let cost = sbproxy_ai::budget::estimate_cost_for_usage(&model, &usage);
                let provider = ctx
                    .ai_provider
                    .clone()
                    .unwrap_or_else(|| router_sink.provider_name.to_string());
                let surface = ctx.ai_surface.clone().unwrap_or_default();
                let model_for_event = (!model.is_empty()).then_some(model);
                let cost_micros = emit_ai_billing_event(
                    surface.as_str(),
                    provider.as_str(),
                    model_for_event,
                    usage,
                    cost,
                    Vec::new(),
                    &ctx.attribution_tags,
                    ctx.tenant_id.as_str(),
                    ctx.principal.api_key_id(),
                    &ai_span,
                );
                if cost_micros > 0 {
                    ctx.ai_cost_usd_micros = Some(cost_micros);
                }
            }
            // WOR-798: feed the router's per-provider token counter
            // even on no-budget origins. The previous wire only
            // fired when `budget_recorder` was Some, which made
            // `LeastTokenUsage` invisible to origins that opted out
            // of budgets. The wire is independent of budgeting.
            router_sink.record(prompt_tokens + completion_tokens);
        }
    } else {
        // No budget AND no ctx (rare; the dispatch path almost always
        // hands one). Still record router observations off the
        // upstream usage block so the router stays accurate for
        // unattached requests.
        if (200..300).contains(&status) {
            let (prompt_tokens, completion_tokens) = extract_usage(&resp_body);
            router_sink.record(prompt_tokens + completion_tokens);
        }
    }

    // WOR-1044: reversible PII restoration. The request-side capture
    // recorded `(rule, placeholder, original)` triples on `ctx`; walk
    // the body once and replace each placeholder with its original.
    // After replacement, scan for any remaining `<placeholder:...>`
    // shapes; each is a synthetic placeholder the LLM emitted that
    // the gateway never inserted (hallucination or prompt injection
    // probe), so increment the miss counter and leave the shape in
    // the body.
    //
    // WOR-1044 PR3: restore runs BEFORE the idempotency cache write
    // so a replay surfaces the same restored bytes the original
    // caller saw. The idempotency cache keys on a hash of the
    // request body, so a genuine hit guarantees byte-identical
    // request body which guarantees the same capture map; caching
    // the restored body avoids running restore on every replay and
    // keeps placeholder shapes out of the cache surface.
    //
    // WOR-1044 PR4: the semantic-cache write above is unreachable
    // for reversible-PII origins because the AI handler config
    // disables `semantic_cache` at compile time when any rule on
    // the same origin sets `reversible: true` (see
    // `AiHandlerConfig::from_config`). So the masked body never
    // reaches the semantic cache even though it is written above
    // in the order-of-operations sense.
    let resp_body = restore_reversible_pii(&resp_body, &reversible_pairs);
    if (200..300).contains(&status) && trace_content.enabled() {
        let completion = extract_completion_text(&resp_body);
        record_ai_output_trace(&ai_span, trace_content, &completion);
    }

    // --- Idempotency record on miss ---
    //
    // Honour the per-origin response body cap; bodies above the cap
    // skip the record with `SKIPPED-OVERSIZE-RESPONSE` stamped on the
    // outgoing response (best-effort visible via logs since headers
    // for a non-streaming response have not yet flushed at this
    // point).
    let final_skip_reason = match idem_capture {
        Some(cap) => {
            if resp_body.len() > cap.idem.max_response_body_bytes {
                debug!(
                    body_len = resp_body.len(),
                    max_bytes = cap.idem.max_response_body_bytes,
                    "AI proxy: idempotency response body exceeds cap; abandoning cache record"
                );
                Some("SKIPPED-OVERSIZE-RESPONSE")
            } else {
                let recorded_headers: Vec<(String, String)> =
                    vec![("content-type".to_string(), content_type.clone())];
                cap.record(status, recorded_headers, resp_body.to_vec());
                idem_skip_reason
            }
        }
        None => idem_skip_reason,
    };

    let extra: Option<(&str, &str)> = final_skip_reason.map(|r| ("x-sbproxy-idempotency", r));
    send_response_with_extra(session, status, &content_type, &resp_body, extra).await
}

/// WOR-1044: restore reversible PII placeholders. Walks the body and
/// replaces every `placeholder` from `pairs` with the captured
/// `original`. After the substitution pass scans the body for any
/// remaining `<placeholder:<rule>:<n>>` shape; each match increments
/// `sbproxy_ai_reversible_redaction_miss_total{rule}` so operators
/// can see when the LLM emitted a synthetic placeholder the gateway
/// never inserted. The unmatched placeholder is left in the body so
/// the caller sees the synthetic value verbatim rather than have the
/// gateway silently substitute it.
///
/// The pairs vector is the request-scoped capture from the context;
/// when it is empty (the common no-reversible-rules case) the
/// function short-circuits before touching the body.
pub(super) fn restore_reversible_pii(
    body: &bytes::Bytes,
    pairs: &[(String, String, String)],
) -> bytes::Bytes {
    use regex::Regex;
    use std::sync::OnceLock;
    // Format mirrors the default `mask_template` shape so the miss
    // scan catches both the default and any operator-supplied
    // template that follows the `<placeholder:<rule>:<digits>>`
    // convention. Operator templates that deviate from the
    // convention are not scanned for misses; they still get restored
    // when present in the capture.
    static PLACEHOLDER_RE: OnceLock<Regex> = OnceLock::new();
    let placeholder_re = PLACEHOLDER_RE
        .get_or_init(|| Regex::new(r"<placeholder:([a-zA-Z0-9_\-]+):\d+>").expect("static regex"));

    if pairs.is_empty() {
        return body.clone();
    }

    // Restore: walk the body once per (placeholder, original) pair.
    // A reversible request has a small handful of pairs; this is
    // cheaper than building an Aho-Corasick over them.
    let text = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => {
            // Body is not UTF-8; do not attempt restoration. This is
            // expected for non-text upstreams (e.g. binary tool
            // outputs) which would not have been masked in the first
            // place.
            return body.clone();
        }
    };
    let mut out = text.to_string();
    let mut known_placeholders: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (_rule, placeholder, original) in pairs {
        known_placeholders.insert(placeholder.as_str());
        if out.contains(placeholder.as_str()) {
            out = out.replace(placeholder.as_str(), original.as_str());
        }
    }

    // Miss scan: any default-shape placeholder still in the output
    // is a miss. We label the metric by the rule slug parsed out of
    // the placeholder shape so dashboards can attribute hallucinated
    // placeholders to specific rules.
    for caps in placeholder_re.captures_iter(&out) {
        // The full match did not get restored above (it would have
        // been replaced) and was not in the known set (we already
        // restored those). Treat as a miss.
        let full = caps.get(0).map(|m| m.as_str()).unwrap_or("");
        if known_placeholders.contains(full) {
            continue;
        }
        let rule = caps.get(1).map(|m| m.as_str()).unwrap_or("unknown");
        sbproxy_observe::metrics::record_reversible_redaction_miss(rule);
    }

    bytes::Bytes::from(out)
}

/// WOR-1044 PR2: state for restoring reversible PII placeholders
/// across SSE chunk boundaries. A placeholder like
/// `<placeholder:email:3>` can land half in one chunk and half in the
/// next; this state buffers the trailing bytes of each chunk that
/// might be the start of a placeholder and prepends them to the next
/// chunk before restoring.
///
/// The buffer is bounded by [`StreamingReversibleRestore::MAX_PLACEHOLDER_LEN`].
/// Once the trailing buffer contains a closing `>` (a complete
/// placeholder candidate) or grows past the cap, the buffer flushes:
/// the closer case runs the substitution pass, the cap case emits the
/// buffer verbatim (it was not a placeholder after all).
pub(super) struct StreamingReversibleRestore {
    pairs: Vec<(String, String, String)>,
    /// Bytes we held back from the previous chunk because they could
    /// be the prefix of a placeholder shape. Empty when the previous
    /// chunk ended on a complete-or-no-placeholder boundary.
    carry: String,
}

impl StreamingReversibleRestore {
    /// Maximum bytes we ever buffer waiting for a placeholder closer.
    /// `<placeholder:` is 13 chars + rule slug (capped to 32) + `:` +
    /// up to 10 digits + `>` = 57. Round up to 64 for slack.
    pub const MAX_PLACEHOLDER_LEN: usize = 64;

    /// Construct from the request-time capture. No-op semantics when
    /// the capture is empty (callers can short-circuit with
    /// [`Self::is_noop`]).
    pub fn new(pairs: Vec<(String, String, String)>) -> Self {
        Self {
            pairs,
            carry: String::new(),
        }
    }

    /// True when no restoration is configured. Hot-path callers
    /// short-circuit on this to skip the chunk-buffer machinery for
    /// the common no-reversible-rules case.
    pub fn is_noop(&self) -> bool {
        self.pairs.is_empty()
    }

    /// Process one chunk of bytes. Returns the bytes ready for emit;
    /// any tail bytes that might be the prefix of a placeholder are
    /// held in `self.carry` and prepended to the next call.
    ///
    /// Non-UTF-8 chunks bypass restoration (no placeholder text in a
    /// binary stream) and are returned unchanged. The carry from the
    /// previous chunk is flushed verbatim ahead of the binary chunk
    /// so emit order is preserved.
    pub fn process_chunk(&mut self, chunk: &[u8]) -> bytes::Bytes {
        if self.pairs.is_empty() {
            return bytes::Bytes::copy_from_slice(chunk);
        }
        // Attach any carry from the previous chunk.
        let mut buf = std::mem::take(&mut self.carry);
        match std::str::from_utf8(chunk) {
            Ok(s) => buf.push_str(s),
            Err(_) => {
                // Non-UTF-8: emit carry + chunk verbatim. We give up
                // on placeholder restoration the moment we see binary
                // bytes because a placeholder shape is ASCII text.
                let mut out = bytes::BytesMut::with_capacity(buf.len() + chunk.len());
                out.extend_from_slice(buf.as_bytes());
                out.extend_from_slice(chunk);
                return out.freeze();
            }
        }

        // Find the last `<` in the combined buffer. Anything after it
        // (including the `<`) might be the start of an unterminated
        // placeholder; hold it back. Everything before is safe to
        // restore-and-emit.
        let split = match buf.rfind('<') {
            Some(idx) => {
                // Check whether the suffix could still be an open
                // placeholder. If it already contains a closer (`>`)
                // the placeholder is complete and we can emit the
                // whole buffer through restore. If the suffix is
                // already at or past the cap, it cannot be a real
                // placeholder either; flush it.
                let suffix = &buf[idx..];
                if suffix.contains('>') || suffix.len() >= Self::MAX_PLACEHOLDER_LEN {
                    buf.len()
                } else {
                    idx
                }
            }
            None => buf.len(),
        };

        let emit_slice = &buf[..split];
        let restored = if emit_slice.is_empty() {
            String::new()
        } else {
            let mut out = emit_slice.to_string();
            let mut known: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for (_rule, placeholder, original) in &self.pairs {
                known.insert(placeholder.as_str());
                if out.contains(placeholder.as_str()) {
                    out = out.replace(placeholder.as_str(), original.as_str());
                }
            }
            // Miss scan: any default-shape placeholder still in the
            // emit slice after restore is a synthetic placeholder
            // the LLM produced that the request never captured.
            // Mirrors the non-streaming `restore_reversible_pii`
            // behaviour so streaming dashboards see hallucinated
            // placeholders too. The shape is left verbatim in the
            // emitted bytes; only the metric fires.
            use regex::Regex;
            use std::sync::OnceLock;
            static PLACEHOLDER_RE: OnceLock<Regex> = OnceLock::new();
            let re = PLACEHOLDER_RE.get_or_init(|| {
                Regex::new(r"<placeholder:([a-zA-Z0-9_\-]+):\d+>").expect("static regex")
            });
            for caps in re.captures_iter(&out) {
                let full = caps.get(0).map(|m| m.as_str()).unwrap_or("");
                if known.contains(full) {
                    continue;
                }
                let rule = caps.get(1).map(|m| m.as_str()).unwrap_or("unknown");
                sbproxy_observe::metrics::record_reversible_redaction_miss(rule);
            }
            out
        };

        // Carry the tail (might be a placeholder prefix). When the
        // emit slice covered the whole buffer the tail is empty.
        self.carry = buf[split..].to_string();

        bytes::Bytes::copy_from_slice(restored.as_bytes())
    }

    /// Flush any remaining carry. Called when the upstream stream
    /// ends. Any unmatched placeholder shape is left as-is and
    /// emitted; the miss counter is incremented per rule slug found
    /// so dashboards still see synthetic placeholders that landed in
    /// the final chunk.
    pub fn finish(mut self) -> bytes::Bytes {
        if self.carry.is_empty() {
            return bytes::Bytes::new();
        }
        let mut out = std::mem::take(&mut self.carry);
        for (_rule, placeholder, original) in &self.pairs {
            if out.contains(placeholder.as_str()) {
                out = out.replace(placeholder.as_str(), original.as_str());
            }
        }
        // Miss scan against the default placeholder shape so any
        // shape that did not match a captured pair still increments
        // the miss counter.
        use regex::Regex;
        use std::sync::OnceLock;
        static PLACEHOLDER_RE: OnceLock<Regex> = OnceLock::new();
        let re = PLACEHOLDER_RE.get_or_init(|| {
            Regex::new(r"<placeholder:([a-zA-Z0-9_\-]+):\d+>").expect("static regex")
        });
        for caps in re.captures_iter(&out) {
            let rule = caps.get(1).map(|m| m.as_str()).unwrap_or("unknown");
            sbproxy_observe::metrics::record_reversible_redaction_miss(rule);
        }
        bytes::Bytes::copy_from_slice(out.as_bytes())
    }
}

/// Bundled inputs for post-dispatch budget recording on a relayed AI
/// response. Carried through `relay_ai_response*` so the response
/// body can be parsed for `usage` and recorded against every scope
/// computed at pre-flight time.
pub(super) struct BudgetRecorderArgs<'a> {
    /// Reference to the AI handler's `BudgetConfig`. Used to look up
    /// each fired limit's scope label for the utilization gauge.
    config: &'a sbproxy_ai::BudgetConfig,
    /// Pre-computed scope keys. One entry per limit that produced a
    /// usable key for this request.
    keys: &'a [(usize, String)],
    /// Model the request actually ran against (after any downgrade).
    /// Drives cost estimation via the embedded price catalog.
    model: &'a str,
    /// Classified AI surface (`chat_completions`, `embeddings`,
    /// `assistants`, `image_generation`, ...). Carried through so
    /// the relay function can emit a surface-tagged
    /// `AiBillingEvent` alongside the budget recording.
    surface_label: &'a str,
    /// Provider that received the dispatched request. Same source
    /// of truth as the `provider` field in the access log.
    provider_name: &'a str,
    /// For image generation requests, the resolution requested
    /// (e.g. `1024x1024`, `1024x1792`). Captured from the inbound
    /// request body at dispatch time and threaded here so the
    /// relay function can emit an `Images { count, resolution }`
    /// billing event with the resolution from the request.
    image_resolution: Option<String>,
    /// For audio speech requests, the character count of the input
    /// text (`body["input"]`). Captured at dispatch time so the
    /// relay function can emit a `Characters { count }` billing
    /// event scaled to the TTS provider's per-character rate.
    audio_speech_characters: Option<u64>,
    /// For reranking requests, the number of documents to score
    /// (length of `body["documents"]`). Captured at dispatch time
    /// so the relay function can emit a `RerankUnits { documents }`
    /// billing event scaled to the provider's per-document rate.
    rerank_documents: Option<u64>,
    /// Business attribution tags resolved at the handler entry
    /// (`ctx.attribution_tags`). Carried by value so the relay
    /// functions can stamp the per-attribution spend metric without
    /// borrowing `ctx`, which they hold only as an `Option<&mut>`.
    attribution_tags: sbproxy_ai::attribution::AttributionTags,
    /// Resolved tenant id for the request. Carried by value so the
    /// relay can emit tenant-labelled cost metrics without borrowing
    /// the request context.
    tenant_id: String,
    /// Resolved per-credential reporting id (the API key that injected
    /// the policy). Carried by value alongside `tenant_id` so the relay
    /// can emit the authoritative identity dimensions on the spend
    /// metric without borrowing the request context. Empty string when
    /// the request was not credentialed.
    api_key_id: String,
    /// WOR-1146: estimated prompt tokens for a chat_completions
    /// request, captured from the request body at dispatch. Used only
    /// as the prompt side of the fallback budget debit when a 2xx
    /// response carries no parseable `usage` block. `None` for
    /// non-chat surfaces.
    estimated_prompt_tokens: Option<u64>,
}

/// WOR-798: the bundle a relay needs to feed
/// [`sbproxy_ai::Router::record_tokens_for_provider`] once the
/// upstream `usage` block is in hand. Always present at the call
/// site (router / provider list / provider name are all local at
/// dispatch time), so the relay takes it by value rather than as
/// `Option<...>`. Lets both the budget-recorder path and the
/// no-budget path share one wire; previously the wire only fired
/// when an origin had a configured `budget:` block.
pub(super) struct RouterTokenSink<'a> {
    /// AI router for this origin. Owns the `tokens_used` counter
    /// the `LeastTokenUsage` / `TokenRate` strategies read from.
    router: &'a sbproxy_ai::Router,
    /// Provider list the router was built against; passed
    /// alongside `router` so `record_tokens_for_provider` can
    /// resolve `provider_name` -> index without a second lookup.
    config_providers: &'a [sbproxy_ai::ProviderConfig],
    /// Provider that received the dispatched request. Same source
    /// of truth as the `provider` field in the access log.
    provider_name: &'a str,
}

impl<'a> RouterTokenSink<'a> {
    /// Charge `tokens` against the chosen provider's `tokens_used`
    /// counter. Zero is a no-op; an unknown provider name silently
    /// no-ops (a hot reload mid-flight could leave a stale name).
    fn record(&self, tokens: u64) {
        self.router
            .record_tokens_for_provider(self.config_providers, self.provider_name, tokens);
    }
}

/// Inputs to the streaming-cache recorder hook, bundled to keep
/// [`relay_ai_stream`]'s parameter list short.
///
/// The OSS proxy never inspects these fields beyond passing them to
/// [`crate::hooks::StreamCacheRecorderHook::start_session`]; all policy
/// decisions live in the enterprise impl.
pub(super) struct StreamCacheRecorderArgs {
    request_id: String,
    origin_id: String,
    semantic_key: Option<String>,
    policy: serde_json::Value,
}

/// Inputs the streaming relay needs to construct the right
/// [`sbproxy_ai::SseUsageParser`]. `configured` is the operator's
/// `usage_parser` value (`auto`, `openai`, ...); the remaining
/// fields feed [`sbproxy_ai::UsageParserHints`] when `configured ==
/// "auto"`.
pub(super) struct StreamUsageParserArgs {
    /// Operator-configured `usage_parser` value.
    configured: String,
    /// Effective upstream URL host (e.g. `api.openai.com`).
    upstream_host: Option<String>,
    /// Response `Content-Type` header.
    content_type: Option<String>,
    /// Response `X-Provider` header (when upstream sets one).
    x_provider: Option<String>,
}

/// Wire-format args the streaming relay consults to decide whether
/// the upstream SSE bytes need translation into the hub vocabulary
/// before being re-emitted in the inbound format's shape.
///
/// `upstream_format` is the provider's native wire format (`OpenAi`,
/// `Anthropic`, `Google`, `Bedrock`, `Custom`). `inbound_format` is
/// the wire shape the client expects on the response (`None` /
/// `Some("openai")` for OpenAI Chat Completions; `Some("anthropic")`
/// for `/v1/messages`; `Some("responses")` for `/v1/responses`).
///
/// The relay translates whenever `upstream_format` is non-OpenAI
/// (the upstream emits a native shape we must parse) regardless of
/// the inbound format. Pure pass-through (OpenAI in / OpenAI out)
/// continues to byte-forward without buffering or parsing.
#[derive(Debug, Clone)]
pub(super) struct StreamFormatArgs {
    /// Upstream provider wire format.
    upstream_format: sbproxy_ai::providers::ProviderFormat,
    /// Inbound format id the client expects on the response wire.
    inbound_format: Option<String>,
}

/// Relay a streaming (SSE) AI response back to the client.
///
/// # Stream safety integration
///
/// If the pipeline has a `StreamSafetyHook` wired (enterprise opt-in), a
/// bidirectional classifier session is opened before any bytes are
/// forwarded. The safety policy is:
///
/// * **Session start: FAIL-CLOSED.** If `start_session` returns `None`,
///   the stream is refused with an error. We will not forward protected
///   content without a live classifier session.
/// * **Mid-stream: FAIL-OPEN.** If the channel is full, if the verdict
///   receiver returns a negative `allow`, or if the sidecar lags, we log
///   and still forward the chunk. This is intentional (per the design
///   spec section 5 row 9) to avoid interrupting an in-flight user
///   response on a transient classifier hiccup.
///
/// # Stream cache recorder integration
///
/// If the pipeline has a `StreamCacheRecorderHook` wired, a recorder
/// session is opened at stream start. Every chunk forwarded to the
/// client is also fanned into the recorder's channel; the terminal
/// `End { complete }` event reports whether the stream finished
/// cleanly (true) or aborted mid-stream (false). All caching policy
/// decisions (deterministic tool calls only, image data by reference
/// only, replay pacing) live in the enterprise impl. OSS just
/// forwards.
//
// Eight inputs is one over Clippy's default limit but each is doing
// real work: enterprise hooks (safety + cache recorder), OSS budget
// recorder, and the per-request identifiers the recorder session
// needs. Splitting them into a struct would just move the noise.
/// Build the native-stream translator + inbound emitter pair for a
/// given `(upstream, inbound)` format combination.
///
/// Returns `(None, None)` for the no-translation pass-through path
/// (upstream is OpenAI-compatible). Returns `(Some(translator),
/// Some(emitter))` when the upstream emits a non-OpenAI native shape
/// and the bytes need reframing. The OpenAI Chat emitter is the
/// default inbound shape because every existing client speaks OpenAI
/// Chat Completions; `/v1/messages` and `/v1/responses` inbound
/// surfaces override.
pub(super) fn build_stream_translator(
    args: &StreamFormatArgs,
) -> (
    Option<sbproxy_ai::format::NativeStreamTranslator>,
    Option<Box<dyn sbproxy_ai::format::ChatFormat>>,
) {
    use sbproxy_ai::format::{
        AnthropicMessagesFormat, ChatFormat, NativeStreamFormat, NativeStreamTranslator,
        OpenAiChatFormat, OpenAiResponsesFormat,
    };
    use sbproxy_ai::providers::ProviderFormat;
    let native = match args.upstream_format {
        ProviderFormat::Anthropic => Some(NativeStreamFormat::Anthropic),
        ProviderFormat::Google => Some(NativeStreamFormat::Gemini),
        ProviderFormat::Bedrock => Some(NativeStreamFormat::Bedrock),
        // OpenAI / Custom: zero-cost pass-through for an OpenAI inbound,
        // but when a native-inbound surface (/v1/messages, /v1/responses)
        // streams against an OpenAI-format upstream, parse the OpenAI
        // SSE back into the hub so the inbound emitter re-frames it in
        // Anthropic / Responses shape (WOR-799).
        ProviderFormat::OpenAi | ProviderFormat::Custom => match args.inbound_format.as_deref() {
            Some("anthropic") | Some("responses") => Some(NativeStreamFormat::OpenAiChat),
            _ => None,
        },
    };
    let translator = native.map(NativeStreamTranslator::new);
    let emitter: Option<Box<dyn ChatFormat>> = if translator.is_some() {
        Some(match args.inbound_format.as_deref() {
            Some("anthropic") => Box::new(AnthropicMessagesFormat) as Box<dyn ChatFormat>,
            Some("responses") => Box::new(OpenAiResponsesFormat) as Box<dyn ChatFormat>,
            _ => Box::new(OpenAiChatFormat) as Box<dyn ChatFormat>,
        })
    } else {
        None
    };
    (translator, emitter)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn relay_ai_stream(
    session: &mut Session,
    resp: reqwest::Response,
    pipeline: &CompiledPipeline,
    hostname: &str,
    model_id: Option<String>,
    origin_idx: Option<usize>,
    recorder_args: StreamCacheRecorderArgs,
    budget_recorder: Option<BudgetRecorderArgs<'_>>,
    router_sink: RouterTokenSink<'_>,
    parser_args: StreamUsageParserArgs,
    format_args: StreamFormatArgs,
    ai_span: tracing::Span,
    trace_content: AiTraceContentArgs<'_>,
    // WOR-1044 PR2: request-time reversible PII capture. Empty for
    // requests with no reversible rule matches; in that case the
    // streaming restorer short-circuits per-chunk via
    // `StreamingReversibleRestore::is_noop`.
    reversible_pairs: Vec<(String, String, String)>,
    // WOR-1141: streaming-safe OUTPUT guardrails. `None` when the origin
    // declares no output guardrails. Each outbound chunk is fed through
    // `check_output_chunk` (streaming-safe guardrails only, per the
    // WOR-235 ADR); a match terminates the stream.
    output_guardrails: Option<std::sync::Arc<sbproxy_ai::guardrails::GuardrailPipeline>>,
) -> Result<()> {
    let status = resp.status().as_u16();
    record_ai_provider_response_failure(&ai_span, router_sink.provider_name, status, None);

    // --- Start safety session (fail-closed on None) ---
    //
    // Gating on `hooks.stream_safety.is_some()` ties this feature to
    // enterprise opt-in. When the enterprise classifier is not linked
    // the hook is absent and streaming runs in its original, unchanged
    // path. Per-origin rule subsetting: read the origin's
    // `stream_safety` list and only start a session when the origin
    // declared at least one rule. Empty list = no safety enforcement
    // for this origin even when the hook is wired (operator opt-out).
    let origin_rules: Vec<String> = origin_idx
        .and_then(|idx| pipeline.config.origins.get(idx))
        .map(|o| o.stream_safety.clone())
        .unwrap_or_default();
    let mut safety_channel = if origin_rules.is_empty() {
        None
    } else if let Some(hook) = pipeline.hooks.stream_safety.as_ref().cloned() {
        let ctx = crate::hooks::StreamSafetyCtx {
            origin: hostname.to_string(),
            model_id: model_id.clone(),
            rules: origin_rules.clone(),
        };
        match hook.start_session(ctx).await {
            Some(ch) => Some(ch),
            None => {
                // FAIL-CLOSED: refuse to stream protected content when the
                // classifier session cannot be established.
                warn!(
                    origin = %hostname,
                    "stream_safety session start failed; rejecting SSE per fail-closed policy"
                );
                sbproxy_ai::tracing_spans::record_error(
                    &ai_span,
                    sbproxy_ai::tracing_spans::error_type::GUARDRAIL_BLOCKED,
                    "stream safety session failed closed",
                );
                return Err(Error::new(ErrorType::HTTPStatus(503)));
            }
        }
    } else {
        None
    };

    // --- Start stream-cache recorder session (fail-open on None) ---
    //
    // Gating on `hooks.stream_cache_recorder.is_some()` ties this
    // feature to enterprise opt-in. The recorder decides per session
    // whether it wants to record this stream (it returns `None` to
    // skip, e.g. when the cache key cannot be derived). On accept we
    // wrap the channel in a `StreamCacheGuard` so the terminal `End`
    // event lands exactly once: either via `finish()` on a clean
    // end-of-stream or via the guard's `Drop` impl on any other exit
    // path (client cancel, upstream error, mid-stream abort).
    let recorder_guard: Option<crate::hooks::StreamCacheGuard> =
        if let Some(hook) = pipeline.hooks.stream_cache_recorder.as_ref().cloned() {
            let ctx = crate::hooks::StreamCacheCtx {
                hostname: hostname.to_string(),
                origin_id: recorder_args.origin_id.clone(),
                request_id: recorder_args.request_id.clone(),
                semantic_key: recorder_args.semantic_key.clone(),
                model_id: model_id.clone(),
                policy: recorder_args.policy.clone(),
            };
            hook.start_session(ctx)
                .await
                .map(crate::hooks::StreamCacheGuard::new)
        } else {
            None
        };

    // Write SSE response headers.
    let mut header = pingora_http::ResponseHeader::build(status, Some(3))
        .map_err(|e| Error::because(ErrorType::InternalError, "failed to build SSE header", e))?;
    header
        .insert_header("content-type", "text/event-stream")
        .map_err(|e| Error::because(ErrorType::InternalError, "failed to set content-type", e))?;
    header
        .insert_header("cache-control", "no-cache")
        .map_err(|e| Error::because(ErrorType::InternalError, "failed to set cache-control", e))?;
    header
        .insert_header("connection", "keep-alive")
        .map_err(|e| Error::because(ErrorType::InternalError, "failed to set connection", e))?;
    session
        .write_response_header(Box::new(header), false)
        .await?;

    // Stream chunks from the upstream response to the client.
    //
    // `upstream_complete` tracks whether the upstream stream ran to
    // its natural end without an error. It is only set to `true`
    // when the chunk loop exits via the `None` arm (no `break` from
    // an upstream error). The flag gates whether the recorder
    // guard's terminal event reports `complete: true`.
    //
    // `usage_scanner` is materialised only when a budget recorder
    // is wired so the scan cost stays opt-in. Each chunk is fed to
    // the scanner in addition to being forwarded to the client; the
    // scanner buffers at most one line of pending bytes so the full
    // SSE body never lands in memory.
    let mut stream = resp.bytes_stream();
    let mut upstream_complete = false;
    // WOR-895: track TTFT + output throughput. `stream_started` anchors
    // the generation window; `first_token_at` is set on the first chunk
    // that carries any payload. Both feed `sbproxy_ai_ttft_seconds` +
    // `sbproxy_ai_output_throughput_tokens_per_second` at stream close.
    let stream_started = std::time::Instant::now();
    let mut first_token_at: Option<std::time::Instant> = None;
    // Build the per-stream usage parser when a budget recorder is
    // wired. `select_parser` returns `None` only when the operator
    // sets `usage_parser: none`; every other branch yields a live
    // parser whose snapshot is read at stream close.
    let mut usage_parser: Option<Box<dyn sbproxy_ai::SseUsageParser>> = if budget_recorder.is_some()
    {
        let hints = sbproxy_ai::UsageParserHints {
            upstream_host: parser_args.upstream_host.as_deref(),
            content_type: parser_args.content_type.as_deref(),
            x_provider: parser_args.x_provider.as_deref(),
        };
        sbproxy_ai::select_parser(&parser_args.configured, &hints)
    } else {
        None
    };

    // --- Native-format streaming translator ---
    //
    // When the upstream emits a non-OpenAI native SSE shape we walk
    // every byte through a hub-format translator: native bytes ->
    // `HubChunk`s -> client's inbound wire shape. OpenAI in /
    // OpenAI out stays a zero-cost pass-through.
    let (mut native_translator, inbound_emitter) = build_stream_translator(&format_args);
    let bridge_ctx = sbproxy_ai::format::BridgeContext {
        inbound_format: format_args
            .inbound_format
            .clone()
            .unwrap_or_else(|| "openai".into()),
        stream: true,
        ..Default::default()
    };

    // --- WOR-1044 PR2: streaming reversible PII restorer ---
    //
    // When the request captured reversible PII placeholders we run
    // each outbound chunk through a buffer that holds back any
    // trailing bytes that might be the prefix of a placeholder shape
    // straddling a chunk boundary. The buffer is bounded at 64 bytes
    // so a malformed `<` that never closes flushes verbatim instead
    // of blocking the stream. The common no-reversible-rules path is
    // a per-chunk `is_noop` short-circuit so byte-forward streaming
    // stays zero-overhead.
    let mut reversible_restore = StreamingReversibleRestore::new(reversible_pairs);
    let mut trace_stream_content = trace_content.enabled().then(AiTraceStreamContent::default);
    // WOR-1144: set when the stream-safety classifier rejects a chunk so
    // the relay stops forwarding (fail closed) instead of delivering
    // flagged content. Leaves `upstream_complete` false so the recorder
    // guard emits `End { complete: false }`.
    let mut safety_blocked = false;
    // WOR-1141: set when a streaming-safe output guardrail matches an
    // outbound chunk so the relay stops forwarding (the violating chunk
    // and everything after it). Headers are already sent, so an
    // already-written chunk cannot be recalled, but the rest of the
    // violating output does not reach the client.
    let mut output_guard_blocked = false;
    'relay: loop {
        match stream.next().await {
            Some(Ok(chunk)) => {
                let chunk_bytes = Bytes::copy_from_slice(&chunk);
                // WOR-895: first non-empty chunk marks TTFT.
                if first_token_at.is_none() && !chunk_bytes.is_empty() {
                    first_token_at = Some(std::time::Instant::now());
                }

                // --- Per-chunk safety probe (fail closed) ---
                //
                // We push chunks into the classifier session channel and
                // drain any pending verdicts. Feeding the classifier is
                // non-blocking (if the sidecar is slow we do not stall the
                // relay), but a verdict with `allow=false` terminates the
                // stream: we stop forwarding the current and all
                // subsequent chunks rather than delivering flagged content
                // (WOR-1144). Verdicts lag the chunk that produced them by
                // the classifier's latency, so an already-written chunk
                // cannot be recalled, but the leak does not continue.
                if let Some(ch) = safety_channel.as_mut() {
                    if ch.tx.try_send(chunk_bytes.clone()).is_err() {
                        debug!("stream safety channel full; skipping verdict input");
                    }
                    while let Ok(v) = ch.rx.try_recv() {
                        if !v.allow {
                            warn!(
                                reason = ?v.reason,
                                "stream safety verdict rejected a chunk; terminating stream (fail closed)"
                            );
                            sbproxy_ai::tracing_spans::record_error(
                                &ai_span,
                                sbproxy_ai::tracing_spans::error_type::GUARDRAIL_BLOCKED,
                                v.reason
                                    .as_deref()
                                    .unwrap_or("stream safety rejected response chunk"),
                            );
                            safety_blocked = true;
                            break 'relay;
                        }
                    }
                }

                // --- Per-chunk recorder fan-out (best-effort) ---
                //
                // Forward a copy of every chunk to the cache recorder
                // before writing to the client. `chunk` swallows
                // SendError, so a closed recorder channel (enterprise
                // dropped early) is not fatal.
                if let Some(g) = recorder_guard.as_ref() {
                    g.chunk(chunk_bytes.clone());
                }

                // --- Per-chunk usage capture for budget recording ---
                //
                // Feed the parser before writing to the client so the
                // scan cost is bounded by the chunk we already have in
                // hand. The parser is only built when a budget
                // recorder is wired, so the non-budget path stays the
                // original zero-overhead pass-through.
                if let Some(parser) = usage_parser.as_mut() {
                    parser.feed(&chunk_bytes);
                }

                // If writing to the downstream client fails (client
                // cancel, broken connection, ...), we propagate the
                // error. The recorder guard's `Drop` impl will then
                // emit a terminal `End { complete: false }` on the way
                // out of this function.
                let outbound_bytes = if let (Some(t), Some(emitter)) =
                    (native_translator.as_mut(), inbound_emitter.as_ref())
                {
                    let hub_chunks = t.feed(&chunk_bytes);
                    if hub_chunks.is_empty() {
                        continue;
                    }
                    let mut translated = String::new();
                    for hub in &hub_chunks {
                        match emitter.from_hub_stream(hub, &bridge_ctx) {
                            Ok(frames) => {
                                for f in frames {
                                    translated.push_str(&f);
                                }
                            }
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    "AI proxy: inbound format SSE emitter failed; skipping chunk"
                                );
                            }
                        }
                    }
                    Bytes::from(translated)
                } else {
                    chunk_bytes
                };
                // WOR-1044 PR2: run the outbound bytes through the
                // reversible PII restorer before writing to the
                // client. The restorer is a no-op (clone-only) when
                // the request has no captured placeholders.
                let outbound_bytes = if reversible_restore.is_noop() {
                    outbound_bytes
                } else {
                    reversible_restore.process_chunk(&outbound_bytes)
                };
                if outbound_bytes.is_empty() {
                    // The restorer held the entire chunk back as
                    // potential placeholder prefix. Skip the write
                    // and wait for the next chunk to flush.
                    continue;
                }
                // WOR-1141: run streaming-safe output guardrails against
                // the client-facing chunk before it is written. A match
                // terminates the stream (fail closed) so the violating
                // content and everything after it is withheld.
                if let Some(ref guardrails) = output_guardrails {
                    if let Ok(text) = std::str::from_utf8(&outbound_bytes) {
                        if let Some(block) = guardrails.check_output_chunk(text) {
                            warn!(
                                guardrail = %block.name,
                                reason = %block.reason,
                                "AI proxy: output guardrail blocked streaming chunk; terminating stream"
                            );
                            sbproxy_ai::tracing_spans::record_error(
                                &ai_span,
                                sbproxy_ai::tracing_spans::error_type::GUARDRAIL_BLOCKED,
                                &block.reason,
                            );
                            output_guard_blocked = true;
                            break 'relay;
                        }
                    }
                }
                if let Some(trace) = trace_stream_content.as_mut() {
                    trace.feed(&outbound_bytes);
                }
                session
                    .write_response_body(Some(outbound_bytes), false)
                    .await?;
            }
            Some(Err(e)) => {
                let kind = if e.is_timeout() {
                    sbproxy_ai::tracing_spans::error_type::TIMEOUT
                } else {
                    sbproxy_ai::tracing_spans::error_type::PROVIDER_ERROR
                };
                sbproxy_ai::tracing_spans::record_error(
                    &ai_span,
                    kind,
                    "AI upstream streaming response failed",
                );
                sbproxy_ai::ai_metrics::record_provider_error(
                    router_sink.provider_name,
                    ai_metric_error_kind_for_span_error_type(kind),
                );
                warn!(error = %e, "AI proxy: error reading SSE chunk from upstream");
                break;
            }
            None => {
                upstream_complete = true;
                // Flush any tail bytes from the translator so a frame
                // straddling the last network read still surfaces.
                if let (Some(t), Some(emitter)) =
                    (native_translator.as_mut(), inbound_emitter.as_ref())
                {
                    let tail = t.flush();
                    if !tail.is_empty() {
                        let mut translated = String::new();
                        for hub in &tail {
                            if let Ok(frames) = emitter.from_hub_stream(hub, &bridge_ctx) {
                                for f in frames {
                                    translated.push_str(&f);
                                }
                            }
                        }
                        if !translated.is_empty() {
                            let bytes = Bytes::from(translated);
                            let bytes = if reversible_restore.is_noop() {
                                bytes
                            } else {
                                reversible_restore.process_chunk(&bytes)
                            };
                            if !bytes.is_empty() {
                                if let Some(trace) = trace_stream_content.as_mut() {
                                    trace.feed(&bytes);
                                }
                                let _ = session.write_response_body(Some(bytes), false).await;
                            }
                        }
                    }
                }
                // WOR-1044 PR2: flush any bytes the restorer held back
                // as potential placeholder prefix. Replaces
                // `reversible_restore` with an empty value so the
                // `finish()` move is sound.
                let tail = std::mem::replace(
                    &mut reversible_restore,
                    StreamingReversibleRestore::new(Vec::new()),
                )
                .finish();
                if !tail.is_empty() {
                    if let Some(trace) = trace_stream_content.as_mut() {
                        trace.feed(&tail);
                    }
                    let _ = session.write_response_body(Some(tail), false).await;
                }
                break;
            }
        }
    }

    // Signal end of stream to the client. A failure here is treated
    // as a partial recording: we let the guard drop emit
    // `End { complete: false }`.
    session.write_response_body(None, true).await?;

    if safety_blocked {
        // WOR-1144: the stream was cut short by an output-safety verdict.
        // `upstream_complete` stayed false, so the recorder guard emits
        // `End { complete: false }`. Budget is still recorded best-effort
        // below for whatever the upstream produced before the cut.
        debug!("AI proxy: streaming response terminated early by stream-safety enforcement");
    }
    if output_guard_blocked {
        // WOR-1141: the stream was cut short by an output guardrail.
        // Same partial-recording semantics as the safety-verdict cut.
        debug!("AI proxy: streaming response terminated early by an output guardrail");
    }
    if (200..300).contains(&status) {
        if let Some(trace) = trace_stream_content.take() {
            let completion = trace.finish();
            record_ai_output_trace(&ai_span, trace_content, &completion);
        }
    }

    // --- Streaming budget recording ---
    //
    // When the parser picked up a usage block (OpenAI's terminal
    // chunk, Anthropic's `message_delta`, Vertex's `usageMetadata`,
    // ...) record tokens + cost against every configured scope. A
    // truncated stream (`upstream_complete == false`) is best-effort:
    // if the parser saw a usage block before the truncation we still
    // record so partial billing reflects the work the upstream
    // actually did.
    if let (Some(args), Some(parser)) = (budget_recorder.as_ref(), usage_parser.as_ref()) {
        if (200..300).contains(&status) {
            if let Some(tokens) = parser.snapshot() {
                record_budget_usage(
                    args.config,
                    args.keys,
                    args.model,
                    tokens.prompt_tokens as u64,
                    tokens.completion_tokens as u64,
                );
                // WOR-1722: mirror into the cluster-shared counters.
                super::budget_share::record_shared_budget_usage(
                    args.config,
                    args.keys,
                    args.model,
                    tokens.prompt_tokens as u64,
                    tokens.completion_tokens as u64,
                )
                .await;
                let prompt = tokens.prompt_tokens as u64;
                let completion = tokens.completion_tokens as u64;
                // WOR-798: feed the router's per-provider token
                // counter so streaming responses contribute to the
                // `LeastTokenUsage` / `TokenRate` signal the same as
                // unary responses.
                router_sink.record(prompt + completion);
                let usage = if prompt != 0 || completion != 0 {
                    sbproxy_ai::budget::AiUsage::Tokens {
                        input: prompt,
                        output: completion,
                        // WOR-1708: from the streaming usage parser. These
                        // are 0 until the per-provider SSE parsers populate
                        // cache tokens (follow-up); billing then discounts
                        // them automatically.
                        cached_input: tokens.cache_read_tokens as u64,
                        cache_creation: tokens.cache_write_tokens as u64,
                    }
                } else {
                    sbproxy_ai::budget::AiUsage::PerCall
                };
                let cost = sbproxy_ai::budget::estimate_cost_for_usage(args.model, &usage);
                let scope_keys = args.keys.iter().map(|(_, k)| k.clone()).collect::<Vec<_>>();
                emit_ai_billing_event(
                    args.surface_label,
                    args.provider_name,
                    Some(args.model.to_string()),
                    usage,
                    cost,
                    scope_keys,
                    &args.attribution_tags,
                    args.tenant_id.as_str(),
                    args.api_key_id.as_str(),
                    &ai_span,
                );

                // WOR-1093: a stream that did not run to a clean
                // upstream completion still consumed the prompt (and
                // any reasoning) tokens; flag the spend as wasted so
                // the ledger's waste detectors can see it. The billing
                // event above still records the real spend; this is an
                // additional waste marker, not a double count of cost.
                // A stream cut short by an output guardrail or the
                // stream-safety classifier is `validation_failed`
                // (spend that produced a rejected outcome); any other
                // incomplete close is an `abandoned_stream` (client
                // cancel or upstream truncation).
                let stream_waste_kind = if output_guard_blocked || safety_blocked {
                    Some(sbproxy_ai::ai_metrics::WasteKind::ValidationFailed)
                } else if !upstream_complete {
                    Some(sbproxy_ai::ai_metrics::WasteKind::AbandonedStream)
                } else {
                    None
                };
                if let Some(kind) = stream_waste_kind {
                    sbproxy_ai::ai_metrics::record_waste(
                        kind,
                        args.provider_name,
                        args.model,
                        args.surface_label,
                        &args.attribution_tags,
                        prompt.saturating_add(completion),
                        cost,
                    );
                }

                // WOR-895: TTFT + output throughput. TTFT only when the
                // upstream actually sent at least one chunk; throughput
                // requires both completion tokens and a measurable
                // generation window (first_token -> now). Both are
                // recorded against the same provider/model labels the
                // billing event used.
                let stream_end = std::time::Instant::now();
                if let Some(ft) = first_token_at {
                    let ttft_secs = ft.duration_since(stream_started).as_secs_f64();
                    sbproxy_ai::ai_metrics::record_ttft(args.provider_name, args.model, ttft_secs);
                    let gen_secs = stream_end.duration_since(ft).as_secs_f64();
                    if completion > 0 && gen_secs > 0.0 {
                        let tps = completion as f64 / gen_secs;
                        sbproxy_ai::ai_metrics::record_output_throughput(
                            args.provider_name,
                            args.model,
                            tps,
                        );
                    }
                }
            }
        }
    } else if let Some(parser) = usage_parser.as_ref() {
        // WOR-798: no-budget streaming path. Still feed the router's
        // per-provider token counter so `LeastTokenUsage` /
        // `TokenRate` see streaming load even when the origin opted
        // out of budgets. Mirrors the unary no-budget branch in
        // `relay_ai_response_with_cache`.
        if (200..300).contains(&status) {
            if let Some(tokens) = parser.snapshot() {
                router_sink.record(tokens.prompt_tokens as u64 + tokens.completion_tokens as u64);
            }
        }
    }

    // Clean end-of-stream: emit terminal `End { complete: true }`
    // to the recorder. If the upstream broke mid-stream (`break`
    // above) we deliberately leave the guard untouched so its drop
    // emits `complete: false`.
    if upstream_complete {
        if let Some(g) = recorder_guard {
            g.finish();
        }
    }
    Ok(())
}

/// WOR-798: extract a stable prefix key from an AI chat / completion
/// request body for prefix-affinity routing. Preference order:
///
/// 1. `body["messages"]` - the chat history is the prefix that
///    matters for KV-cache reuse on vLLM / SGLang. Two requests
///    sharing a system + first-user-message hash to the same
///    upstream and reuse its prefill cache.
/// 2. `body["prompt"]` - for legacy completion-shaped surfaces.
/// 3. The whole body, serialized canonically.
///
/// Truncated to `max_bytes` so very long histories still hash off
/// the leading bytes (which is exactly what KV-cache reuse needs;
/// the divergent tail is the new tokens that won't be cached
/// anyway). Returns an empty `Vec<u8>` when no JSON-serialisable
/// prefix exists, in which case `select_with_prefix` falls back to
/// round-robin so body-less requests do not herd onto one upstream.
fn extract_prefix_key(body: &serde_json::Value, max_bytes: usize) -> Vec<u8> {
    let source = body
        .get("messages")
        .or_else(|| body.get("prompt"))
        .unwrap_or(body);
    let serialized = match serde_json::to_vec(source) {
        Ok(bytes) => bytes,
        Err(_) => return Vec::new(),
    };
    if serialized.len() > max_bytes {
        serialized[..max_bytes].to_vec()
    } else {
        serialized
    }
}

/// WOR-800: build the `request.*` context exposed to a prompt template.
/// Carries the request method, path, query, a lowercased header map, and
/// the parsed request body (so a template can reference, e.g.,
/// `request.headers["x-user-id"]` or `request.body.model`).
fn build_prompt_request_ctx(session: &Session, body: &serde_json::Value) -> serde_json::Value {
    let req = session.req_header();
    let headers: serde_json::Map<String, serde_json::Value> = req
        .headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|val| (k.as_str().to_ascii_lowercase(), serde_json::json!(val)))
        })
        .collect();
    serde_json::json!({
        "method": req.method.as_str(),
        "path": req.uri.path(),
        "query": req.uri.query().unwrap_or(""),
        "headers": serde_json::Value::Object(headers),
        "body": body,
    })
}

/// WOR-800: prepend a rendered prompt to the request as a `system`
/// message. Creates the `messages` array when the body lacks one.
fn prepend_system_message(body: &mut serde_json::Value, text: &str) {
    let sys = serde_json::json!({ "role": "system", "content": text });
    if let Some(arr) = body.get_mut("messages").and_then(|m| m.as_array_mut()) {
        arr.insert(0, sys);
    } else if let Some(obj) = body.as_object_mut() {
        obj.insert("messages".to_string(), serde_json::json!([sys]));
    }
}

/// WOR-1534: restrict the routing set to providers that declare the requested
/// model. A provider with an empty `models` list is a wildcard and stays
/// eligible. Returns `None` (leave the order unchanged) when the model is
/// empty, when no provider declares it (so unenumerated models still pass
/// straight through), or when the filter would not exclude any provider.
/// Rewrite the top-level `model` field of an OpenAI-shaped JSON body to
/// `model`. A served (local) engine reports its weights file path there
/// (e.g. `/var/lib/sbproxy/models/.../Qwen3-14B-Q4_K_M.gguf`), which is
/// not the id any plane routed on (WOR-1809); the serve-entry name is.
/// Non-JSON bodies and bodies without a `model` field pass through
/// unchanged, so error envelopes and exotic shapes are never mangled.
fn rewrite_response_model(body: bytes::Bytes, model: &str) -> bytes::Bytes {
    let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return body;
    };
    match v.get("model").and_then(|m| m.as_str()) {
        Some(existing) if existing != model => {
            v["model"] = serde_json::Value::String(model.to_string());
            match serde_json::to_vec(&v) {
                Ok(out) => bytes::Bytes::from(out),
                Err(_) => body,
            }
        }
        _ => body,
    }
}

fn model_eligible_providers(
    order: &[usize],
    providers: &[sbproxy_ai::ProviderConfig],
    model: &str,
) -> Option<Vec<usize>> {
    if model.is_empty() {
        return None;
    }
    let eligible: Vec<usize> = order
        .iter()
        .copied()
        .filter(|&i| {
            let models = &providers[i].models;
            models.is_empty() || models.iter().any(|m| *m == model)
        })
        .collect();
    (!eligible.is_empty() && eligible.len() < order.len()).then_some(eligible)
}

/// LiteLLM-parity read-only management endpoints served from the `ai_proxy`
/// config without any upstream call: `/model/info`, `/model_group/info`, and
/// the `/health[/readiness|/liveliness|/liveness]` aliases. Returns `None` for
/// any other path so the caller falls through to normal handling.
fn ai_management_response(
    path: &str,
    config: &sbproxy_ai::handler::AiHandlerConfig,
) -> Option<serde_json::Value> {
    match path.trim_end_matches('/') {
        "/model/info" => {
            let mut data = Vec::new();
            for p in &config.providers {
                let provider = p
                    .provider_type
                    .clone()
                    .unwrap_or_else(|| p.name.to_string());
                for m in &p.models {
                    data.push(serde_json::json!({
                        "model_name": m.as_str(),
                        "litellm_provider": provider,
                    }));
                }
            }
            Some(serde_json::json!({ "data": data }))
        }
        "/model_group/info" => {
            use std::collections::BTreeMap;
            let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for p in &config.providers {
                for m in &p.models {
                    groups
                        .entry(m.as_str().to_string())
                        .or_default()
                        .push(p.name.to_string());
                }
            }
            let data: Vec<_> = groups
                .into_iter()
                .map(|(model_group, providers)| {
                    serde_json::json!({
                        "model_group": model_group,
                        "num_deployments": providers.len(),
                        "providers": providers,
                    })
                })
                .collect();
            Some(serde_json::json!({ "data": data }))
        }
        // LiteLLM spells one of these "liveliness"; accept both spellings.
        "/health" | "/health/readiness" | "/health/liveliness" | "/health/liveness" => {
            Some(serde_json::json!({ "status": "healthy" }))
        }
        _ => None,
    }
}

#[cfg(test)]
mod model_routing_tests {
    use super::model_eligible_providers;

    fn prov(name: &str, models: &[&str]) -> sbproxy_ai::ProviderConfig {
        serde_json::from_value(serde_json::json!({
            "name": name,
            "api_key": "x",
            "models": models,
        }))
        .expect("ProviderConfig fixture")
    }

    #[test]
    fn requested_model_selects_declaring_provider() {
        let providers = vec![
            prov("openai", &["gpt-4o-mini"]),
            prov("anthropic", &["claude-haiku-4-5"]),
            prov("gemini", &["gemini-3.5-flash"]),
        ];
        let order = vec![0, 1, 2];
        assert_eq!(
            model_eligible_providers(&order, &providers, "gemini-3.5-flash"),
            Some(vec![2])
        );
        assert_eq!(
            model_eligible_providers(&order, &providers, "gpt-4o-mini"),
            Some(vec![0])
        );
    }

    #[test]
    fn unenumerated_model_passes_through() {
        let providers = vec![
            prov("openai", &["gpt-4o-mini"]),
            prov("anthropic", &["claude-haiku-4-5"]),
        ];
        // No provider declares this model: leave the order unchanged.
        assert_eq!(model_eligible_providers(&[0, 1], &providers, "gpt-5"), None);
    }

    #[test]
    fn empty_models_is_wildcard() {
        let providers = vec![
            prov("openai", &["gpt-4o-mini"]),
            prov("anthropic", &["claude-haiku-4-5"]),
            prov("openrouter", &[]),
        ];
        // The enumerated match plus the wildcard are eligible; the provider
        // that enumerates a different model is excluded.
        assert_eq!(
            model_eligible_providers(&[0, 1, 2], &providers, "gpt-4o-mini"),
            Some(vec![0, 2])
        );
        // For an unenumerated model only the wildcard qualifies.
        assert_eq!(
            model_eligible_providers(&[0, 1, 2], &providers, "mystery-model"),
            Some(vec![2])
        );
    }

    #[test]
    fn empty_model_is_noop() {
        let providers = vec![prov("openai", &["gpt-4o-mini"])];
        assert_eq!(model_eligible_providers(&[0], &providers, ""), None);
    }

    fn handler_config_two_deployments() -> sbproxy_ai::handler::AiHandlerConfig {
        serde_json::from_value(serde_json::json!({
            "providers": [
                {"name": "openai-a", "api_key": "k", "provider_type": "openai", "models": ["gpt-4o-mini"]},
                {"name": "openai-b", "api_key": "k", "provider_type": "openai", "models": ["gpt-4o-mini"]},
                {"name": "anthropic", "api_key": "k", "provider_type": "anthropic", "models": ["claude-haiku-4-5"]}
            ]
        }))
        .expect("AiHandlerConfig fixture")
    }

    #[test]
    fn model_group_info_groups_deployments_by_public_name() {
        let cfg = handler_config_two_deployments();
        let resp = super::ai_management_response("/model_group/info", &cfg).unwrap();
        let groups = resp["data"].as_array().unwrap();
        // Two public names: gpt-4o-mini (2 deployments) + claude-haiku-4-5 (1).
        assert_eq!(groups.len(), 2);
        let gpt = groups
            .iter()
            .find(|g| g["model_group"] == "gpt-4o-mini")
            .unwrap();
        assert_eq!(gpt["num_deployments"], 2);
    }

    #[test]
    fn model_info_lists_every_deployment() {
        let cfg = handler_config_two_deployments();
        let resp = super::ai_management_response("/model/info", &cfg).unwrap();
        assert_eq!(resp["data"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn health_aliases_report_healthy_and_unknown_paths_pass_through() {
        let cfg = handler_config_two_deployments();
        for p in [
            "/health",
            "/health/readiness",
            "/health/liveliness",
            "/health/liveness",
        ] {
            assert_eq!(
                super::ai_management_response(p, &cfg).unwrap()["status"],
                "healthy"
            );
        }
        assert!(super::ai_management_response("/v1/models", &cfg).is_none());
        assert!(super::ai_management_response("/v1/chat/completions", &cfg).is_none());
    }
}

#[cfg(test)]
mod ai_error_classification_tests {
    use super::{
        ai_metric_error_kind_for_span_error_type, ai_provider_response_error_type,
        ai_response_body_indicates_content_filter,
    };

    #[test]
    fn provider_429_maps_to_rate_limited() {
        assert_eq!(
            ai_provider_response_error_type(429, None),
            Some(sbproxy_ai::tracing_spans::error_type::RATE_LIMITED)
        );
    }

    #[test]
    fn provider_5xx_maps_to_upstream_5xx() {
        assert_eq!(
            ai_provider_response_error_type(503, None),
            Some(sbproxy_ai::tracing_spans::error_type::UPSTREAM_5XX)
        );
    }

    #[test]
    fn content_filter_finish_reason_marks_success_response_failed() {
        let body = br#"{
            "choices": [
                {"message": {"role": "assistant", "content": ""}, "finish_reason": "content_filter"}
            ]
        }"#;

        assert_eq!(
            ai_provider_response_error_type(200, Some(body)),
            Some(sbproxy_ai::tracing_spans::error_type::CONTENT_FILTER)
        );
    }

    #[test]
    fn content_filter_error_envelope_is_detected() {
        let body = br#"{
            "error": {
                "message": "The response was filtered due to the prompt triggering Azure OpenAI's content policy.",
                "code": "content_filter",
                "innererror": {"code": "ResponsibleAIPolicyViolation"}
            }
        }"#;

        assert!(ai_response_body_indicates_content_filter(body));
        assert_eq!(
            ai_provider_response_error_type(400, Some(body)),
            Some(sbproxy_ai::tracing_spans::error_type::CONTENT_FILTER)
        );
    }

    #[test]
    fn provider_4xx_without_known_filter_uses_generic_provider_error() {
        assert_eq!(
            ai_provider_response_error_type(400, Some(br#"{"error":{"code":"bad_request"}}"#)),
            Some(sbproxy_ai::tracing_spans::error_type::PROVIDER_ERROR)
        );
    }

    #[test]
    fn trace_error_types_map_to_low_cardinality_metric_kinds() {
        assert_eq!(
            ai_metric_error_kind_for_span_error_type(
                sbproxy_ai::tracing_spans::error_type::RATE_LIMITED
            ),
            "rate_limited"
        );
        assert_eq!(
            ai_metric_error_kind_for_span_error_type(
                sbproxy_ai::tracing_spans::error_type::UPSTREAM_5XX
            ),
            "upstream_5xx"
        );
        assert_eq!(
            ai_metric_error_kind_for_span_error_type(
                sbproxy_ai::tracing_spans::error_type::TIMEOUT
            ),
            "timeout"
        );
    }
}

#[cfg(test)]
mod restore_tests {
    use super::restore_reversible_pii;

    /// Empty capture short-circuits: the body comes through unchanged
    /// and the function pays no allocation for the regex scan.
    #[test]
    fn empty_capture_passes_body_through() {
        let body = bytes::Bytes::from(r#"{"reply":"hello"}"#);
        let out = restore_reversible_pii(&body, &[]);
        assert_eq!(out, body);
    }

    /// Single round-trip: a placeholder the request captured gets
    /// restored to the original on the response side.
    #[test]
    fn single_placeholder_restored() {
        let body =
            bytes::Bytes::from(r#"{"reply":"hi <placeholder:email:0>, your order is ready"}"#);
        let pairs = vec![(
            "email".to_string(),
            "<placeholder:email:0>".to_string(),
            "alice@example.com".to_string(),
        )];
        let out = restore_reversible_pii(&body, &pairs);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains("alice@example.com"));
        assert!(!s.contains("<placeholder:email:0>"));
    }

    /// Multiple captures, all present in the response: each
    /// placeholder is restored to its captured original.
    #[test]
    fn multiple_placeholders_all_restored() {
        let body =
            bytes::Bytes::from(r#"{"reply":"cc <placeholder:email:0> bcc <placeholder:email:1>"}"#);
        let pairs = vec![
            (
                "email".to_string(),
                "<placeholder:email:0>".to_string(),
                "alice@example.com".to_string(),
            ),
            (
                "email".to_string(),
                "<placeholder:email:1>".to_string(),
                "bob@example.com".to_string(),
            ),
        ];
        let out = restore_reversible_pii(&body, &pairs);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains("alice@example.com"));
        assert!(s.contains("bob@example.com"));
        assert!(!s.contains("<placeholder:email:"));
    }

    /// Hallucinated placeholder: the LLM emits a `<placeholder:...:N>`
    /// shape the request never captured. The function leaves it in
    /// place (caller sees the synthetic value) and the miss metric
    /// fires. We only assert the body is unchanged for the unknown
    /// placeholder; the metric side-effect is global state and is
    /// covered by the metric helper's own tests.
    #[test]
    fn hallucinated_placeholder_is_left_in_place() {
        let body = bytes::Bytes::from(r#"{"reply":"hi <placeholder:email:99>, see token"}"#);
        // Pairs are non-empty (a different rule fired earlier on the
        // request) so the function does NOT short-circuit.
        let pairs = vec![(
            "phone".to_string(),
            "<placeholder:phone:0>".to_string(),
            "555-1234".to_string(),
        )];
        let out = restore_reversible_pii(&body, &pairs);
        let s = std::str::from_utf8(&out).unwrap();
        // The captured pair was not in the body, so nothing was
        // substituted. The hallucinated placeholder is preserved
        // verbatim so the caller can see the synthetic value.
        assert!(s.contains("<placeholder:email:99>"));
    }

    /// Non-UTF-8 body short-circuits (some upstreams return binary
    /// content the request-side redactor never touched in the first
    /// place). The body is returned unchanged.
    #[test]
    fn non_utf8_body_passes_through() {
        let body = bytes::Bytes::from(vec![0xff, 0xfe, 0x00]);
        let pairs = vec![(
            "email".to_string(),
            "<placeholder:email:0>".to_string(),
            "alice@example.com".to_string(),
        )];
        let out = restore_reversible_pii(&body, &pairs);
        assert_eq!(out, body);
    }
}

/// WOR-1044 PR2: streaming reversible PII restorer tests. The chunk
/// loop in [`relay_ai_stream`] feeds bytes through
/// [`StreamingReversibleRestore`] before writing them to the client;
/// the restorer must surface placeholders that span chunk boundaries,
/// bound its carry buffer, and degrade gracefully on malformed input.
#[cfg(test)]
mod streaming_restore_tests {
    use super::StreamingReversibleRestore;

    fn email_pair() -> Vec<(String, String, String)> {
        vec![(
            "email".to_string(),
            "<placeholder:email:1>".to_string(),
            "alice@example.com".to_string(),
        )]
    }

    /// A placeholder that lands across two chunk boundaries still
    /// surfaces with the captured original. We split between the
    /// rule slug and the counter (`:1`) so the first chunk's
    /// trailing `<placeholder:em` is held back and the second
    /// chunk's `ail:1>` completes the shape.
    #[test]
    fn streaming_restore_handles_placeholder_spanning_two_chunks() {
        let mut restore = StreamingReversibleRestore::new(email_pair());
        let first = restore.process_chunk(b"Hello <placeholder:em");
        let second = restore.process_chunk(b"ail:1>!");
        let combined = format!(
            "{}{}",
            std::str::from_utf8(&first).unwrap(),
            std::str::from_utf8(&second).unwrap(),
        );
        assert!(
            combined.contains("alice@example.com"),
            "restored email missing from combined output: {combined}"
        );
        assert!(
            !combined.contains("<placeholder:email:1>"),
            "placeholder leaked into client stream: {combined}"
        );
    }

    /// The first chunk holds back the open-brace plus partial
    /// placeholder tail (anything from the last `<` onward). When
    /// the second chunk closes the shape the restorer emits the
    /// restored placeholder with the original.
    #[test]
    fn streaming_restore_buffers_tail_until_closer() {
        let mut restore = StreamingReversibleRestore::new(email_pair());
        let first = restore.process_chunk(b"Hello <placehol");
        let first_str = std::str::from_utf8(&first).unwrap();
        assert!(
            !first_str.contains("<placehol"),
            "carry leaked on the first chunk: {first_str}"
        );
        assert_eq!(first_str, "Hello ");
        let second = restore.process_chunk(b"der:email:1>!");
        let second_str = std::str::from_utf8(&second).unwrap();
        assert!(
            second_str.contains("alice@example.com"),
            "second chunk missing restored email: {second_str}"
        );
    }

    /// A `<` that never closes must not stall the stream. After 64
    /// bytes of un-terminated suffix the restorer flushes the buffer
    /// verbatim. We feed a chunk ending in `<` plus 100 bytes of
    /// non-`>` garbage; the next chunk drains everything.
    #[test]
    fn streaming_restore_caps_carry_at_64_bytes() {
        let mut restore = StreamingReversibleRestore::new(email_pair());
        let mut chunk = String::from("payload <");
        // 100 bytes of placeholder-shaped garbage that never closes.
        chunk.push_str(&"x".repeat(100));
        let first = restore.process_chunk(chunk.as_bytes());
        let first_str = std::str::from_utf8(&first).unwrap();
        // The buffer must have flushed at least the `<` plus the
        // bytes past the 64-byte cap; the suffix from the cap onward
        // can stay in carry. Either way the emit must have advanced
        // past the `payload ` prefix.
        assert!(
            first_str.starts_with("payload "),
            "prefix did not flush past the open-brace: {first_str}"
        );
        // Push a closing newline so the buffer (if any) finishes
        // draining; total observed output equals input.
        let second = restore.process_chunk(b"\n");
        let combined = format!("{}{}", first_str, std::str::from_utf8(&second).unwrap());
        let expected = format!("{chunk}\n");
        assert_eq!(combined, expected, "lost bytes around the carry cap");
    }

    /// `finish()` emits any remaining carry on a clean stream end.
    /// An unterminated `<placehol` tail is surfaced verbatim so the
    /// caller still receives every byte the upstream produced.
    #[test]
    fn streaming_restore_finish_emits_remaining_carry() {
        let mut restore = StreamingReversibleRestore::new(email_pair());
        let first = restore.process_chunk(b"Hello <placehol");
        assert_eq!(std::str::from_utf8(&first).unwrap(), "Hello ");
        let tail = restore.finish();
        assert_eq!(std::str::from_utf8(&tail).unwrap(), "<placehol");
    }

    /// A complete placeholder shape that is NOT in the capture pairs
    /// is treated as a miss: the body keeps the placeholder verbatim
    /// and the miss counter increments. We assert the verbatim
    /// behaviour and rely on the metric helper's own tests for the
    /// counter side-effect (global state).
    #[test]
    fn streaming_restore_increments_miss_counter_on_unmatched_placeholder() {
        // Pairs map `email:1` but the LLM emitted `email:99` (a
        // hallucinated counter the request never captured).
        let mut restore = StreamingReversibleRestore::new(email_pair());
        // Send the hallucinated placeholder in two chunks to exercise
        // the boundary path; both halves are surfaced as-is.
        let first = restore.process_chunk(b"prefix <placeholder:email:99");
        let second = restore.process_chunk(b">!");
        let combined = format!(
            "{}{}",
            std::str::from_utf8(&first).unwrap(),
            std::str::from_utf8(&second).unwrap(),
        );
        assert!(
            combined.contains("<placeholder:email:99>"),
            "hallucinated placeholder must surface verbatim: {combined}"
        );
        // finish() also runs the miss scan over any remaining carry.
        let tail = restore.finish();
        assert!(tail.is_empty(), "no carry should remain after a closer");
    }

    /// Empty pairs short-circuit per-chunk: bytes copy through
    /// unchanged and no carry is built up.
    #[test]
    fn streaming_restore_is_noop_when_no_pairs() {
        let mut restore = StreamingReversibleRestore::new(Vec::new());
        assert!(restore.is_noop());
        let out = restore.process_chunk(b"data: {\"x\": 1}\n\n");
        assert_eq!(out.as_ref(), b"data: {\"x\": 1}\n\n");
        let tail = restore.finish();
        assert!(tail.is_empty());
    }
}

#[cfg(test)]
mod dynamic_key_resolution_tests {
    use super::*;
    use sbproxy_keystore::crypto::KeyCrypto;
    use sbproxy_keystore::record::{KeyRecord, RecordStatus};
    use sbproxy_keystore::{KeyStore, MemoryKeyStore, TtlCache, TtlCacheConfig};
    use std::sync::Arc;

    #[test]
    fn key_record_carries_extended_per_key_policy() {
        let mut rec = KeyRecord::new("k1", "h1", chrono::Utc::now());
        rec.require_pii_redaction = vec!["email".into(), "ssn".into()];
        rec.route_to_model = Some("gpt-4o-mini".into());
        rec.inject_tools = vec![serde_json::json!({
            "type": "function",
            "function": { "name": "lookup" }
        })];
        rec.bypass_prompt_injection = true;
        rec.principal_selectors = vec![serde_json::json!({ "team": "payments" })];

        let vk = key_record_to_virtual_key(&rec);

        assert_eq!(vk.require_pii_redaction, vec!["email", "ssn"]);
        assert_eq!(vk.route_to_model.as_deref(), Some("gpt-4o-mini"));
        assert_eq!(vk.inject_tools.len(), 1);
        assert!(vk.bypass_prompt_injection);
        assert_eq!(vk.principal_selectors.len(), 1);
        assert_eq!(vk.principal_selectors[0].team.as_deref(), Some("payments"));
    }

    #[test]
    fn malformed_principal_selector_is_dropped_not_fatal() {
        let mut rec = KeyRecord::new("k2", "h2", chrono::Utc::now());
        rec.principal_selectors = vec![
            serde_json::json!({ "user": "alice" }), // valid
            serde_json::json!(42),                  // not a selector object
        ];
        let vk = key_record_to_virtual_key(&rec);
        assert_eq!(
            vk.principal_selectors.len(),
            1,
            "the malformed entry is dropped, the resolve still succeeds"
        );
        assert_eq!(vk.principal_selectors[0].user.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn dynamic_key_resolution_outcomes() {
        let crypto = KeyCrypto::new(b"pep".to_vec(), b"mas".to_vec());
        let now = chrono::Utc::now();

        let active = crypto.mint_key();
        let active_rec = KeyRecord::new(active.key_id.clone(), active.secret_hash.clone(), now);

        let revoked = crypto.mint_key();
        let mut revoked_rec =
            KeyRecord::new(revoked.key_id.clone(), revoked.secret_hash.clone(), now);
        revoked_rec.status = RecordStatus::Revoked;

        let store = Arc::new(MemoryKeyStore::new());
        store.put_key(active_rec).await.unwrap();
        store.put_key(revoked_rec).await.unwrap();
        let cache = Arc::new(TtlCache::new(
            store as Arc<dyn KeyStore>,
            TtlCacheConfig::default(),
        ));
        let plane = crate::key_plane::KeyPlane::from_parts(crypto, cache, false, false, None);

        // Valid token resolves; the synthesized key carries the public id.
        match resolve_dynamic_virtual_key(&plane, Some(&active.token)).await {
            DynamicKeyOutcome::Resolved(vk) => assert_eq!(vk.key, active.key_id),
            other => panic!("expected resolved, got {:?}", outcome_label(&other)),
        }
        // Wrong secret for a known id is 401 (no existence oracle).
        let wrong = format!("sk-{}-deadbeefdeadbeef", active.key_id);
        assert!(matches!(
            resolve_dynamic_virtual_key(&plane, Some(&wrong)).await,
            DynamicKeyOutcome::Deny(401, _)
        ));
        // Unknown id is also 401.
        assert!(matches!(
            resolve_dynamic_virtual_key(&plane, Some("sk-nope-secretsecret")).await,
            DynamicKeyOutcome::Deny(401, _)
        ));
        // Revoked key with the correct secret is 403 (known but not active).
        assert!(matches!(
            resolve_dynamic_virtual_key(&plane, Some(&revoked.token)).await,
            DynamicKeyOutcome::Deny(403, _)
        ));
        // A non-virtual-key-shaped token defers to other auth providers.
        assert!(matches!(
            resolve_dynamic_virtual_key(&plane, Some("opaque-jwt")).await,
            DynamicKeyOutcome::NotApplicable
        ));
        // No token at all is also not applicable.
        assert!(matches!(
            resolve_dynamic_virtual_key(&plane, None).await,
            DynamicKeyOutcome::NotApplicable
        ));
    }

    fn outcome_label(o: &DynamicKeyOutcome) -> &'static str {
        match o {
            DynamicKeyOutcome::Resolved(_) => "resolved",
            DynamicKeyOutcome::NotApplicable => "not-applicable",
            DynamicKeyOutcome::Deny(_, _) => "deny",
        }
    }

    fn principal_with_claim(field: &str, value: &str) -> sbproxy_plugin::Principal {
        sbproxy_plugin::Principal {
            attrs: sbproxy_plugin::PrincipalAttrs {
                claims: Some(
                    [(
                        field.to_string(),
                        serde_json::Value::String(value.to_string()),
                    )]
                    .into_iter()
                    .collect(),
                ),
                ..Default::default()
            },
            ..sbproxy_plugin::Principal::anonymous()
        }
    }

    #[tokio::test]
    async fn oidc_claim_maps_to_virtual_key() {
        let crypto = KeyCrypto::new(b"pep".to_vec(), b"mas".to_vec());
        let now = chrono::Utc::now();
        let store = Arc::new(MemoryKeyStore::new());
        let mut active = KeyRecord::new("team-acme", "unused-hash", now);
        active.name = Some("acme".into());
        store.put_key(active).await.unwrap();
        let mut revoked = KeyRecord::new("team-old", "unused-hash", now);
        revoked.status = RecordStatus::Revoked;
        store.put_key(revoked).await.unwrap();
        let cache = Arc::new(TtlCache::new(
            store as Arc<dyn KeyStore>,
            TtlCacheConfig::default(),
        ));

        // Mapping configured on the claim `virtual_key`.
        let plane = crate::key_plane::KeyPlane::from_parts(
            crypto,
            cache,
            false,
            false,
            Some("virtual_key".to_string()),
        );

        // A verified identity whose claim names a usable record resolves it
        // (no secret required, identity already proven by the JWT provider).
        let p = principal_with_claim("virtual_key", "team-acme");
        match resolve_oidc_mapped_key(&plane, &p).await {
            DynamicKeyOutcome::Resolved(vk) => assert_eq!(vk.key, "team-acme"),
            other => panic!("expected resolved, got {}", outcome_label(&other)),
        }

        // A claim that names a revoked record DENIES (403): revoking the
        // record blocks the JWT instead of degrading it to ungoverned access.
        let p = principal_with_claim("virtual_key", "team-old");
        assert!(matches!(
            resolve_oidc_mapped_key(&plane, &p).await,
            DynamicKeyOutcome::Deny(403, _)
        ));

        // A claim that names no record denies with the bearer path's 401.
        let p = principal_with_claim("virtual_key", "team-missing");
        assert!(matches!(
            resolve_oidc_mapped_key(&plane, &p).await,
            DynamicKeyOutcome::Deny(401, _)
        ));

        // A principal without the mapped claim is simply unmapped: the JWT
        // stays valid, no per-key policy applies.
        let p = principal_with_claim("other", "team-acme");
        assert!(matches!(
            resolve_oidc_mapped_key(&plane, &p).await,
            DynamicKeyOutcome::NotApplicable
        ));
    }

    #[test]
    fn per_key_rate_limiter_reads_live_rpm_from_record() {
        // A record's max_requests_per_minute is carried onto the synthesized
        // VirtualKeyConfig, so the same limiter the dispatch uses enforces the
        // live value. A PATCH to the record changes this without a reload.
        let mut rec = KeyRecord::new("rl-key", "h", chrono::Utc::now());
        rec.max_requests_per_minute = Some(2);
        let vk = key_record_to_virtual_key(&rec);
        assert_eq!(vk.max_requests_per_minute, Some(2));

        let limiter = sbproxy_ai::identity::KeyRateLimiter::new();
        assert!(limiter.check_rate(&vk.key, &vk));
        assert!(limiter.check_rate(&vk.key, &vk));
        assert!(
            !limiter.check_rate(&vk.key, &vk),
            "the third request in the window exceeds the 2 rpm limit"
        );
    }
}

#[cfg(test)]
mod served_model_rewrite_tests {
    use super::rewrite_response_model;

    #[test]
    fn rewrites_weights_path_to_serve_name() {
        let body = bytes::Bytes::from(
            r#"{"model":"/var/lib/sbproxy/models/Qwen/Qwen3-14B-GGUF/main/Qwen3-14B-Q4_K_M.gguf","choices":[]}"#,
        );
        let out = rewrite_response_model(body, "qwen3-14b");
        let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
        assert_eq!(v["model"], "qwen3-14b");
        assert!(v.get("choices").is_some());
    }

    #[test]
    fn leaves_matching_model_untouched() {
        let body = bytes::Bytes::from(r#"{"model":"qwen3-14b"}"#);
        let out = rewrite_response_model(body.clone(), "qwen3-14b");
        assert_eq!(out, body);
    }

    #[test]
    fn passes_through_non_json_and_missing_field() {
        let sse = bytes::Bytes::from("data: {\"chunk\":1}\n\n");
        assert_eq!(rewrite_response_model(sse.clone(), "m"), sse);
        let err = bytes::Bytes::from(r#"{"error":{"message":"boom"}}"#);
        assert_eq!(rewrite_response_model(err.clone(), "m"), err);
    }
}
