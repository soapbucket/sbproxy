//! Non-proxy action dispatch: `handle_action` (the request_filter
//! short-circuit for non-Proxy actions) and the MCP action path.
//!
//! Extracted from `server.rs`. Behavior-preserving move:
//! `use super::*` re-imports the parent module's private items and
//! `use` aliases, so the moved code needs no rewiring.

use super::*;

/// Handle non-proxy actions directly in request_filter.
/// Returns Ok(true) if the action was handled (short-circuit), Ok(false) for Proxy.
pub(super) async fn handle_action(
    action: &Action,
    session: &mut Session,
    pipeline: &CompiledPipeline,
    origin_idx: Option<usize>,
    ctx: &mut RequestContext,
) -> Result<bool> {
    match action {
        Action::Proxy(_)
        | Action::LoadBalancer(_)
        | Action::WebSocket(_)
        | Action::Grpc(_)
        | Action::GraphQL(_)
        | Action::A2a(_) => Ok(false),

        Action::AiProxy(ai) => {
            // Pull hostname from the resolved origin (if any) so the AI
            // handler can use it for classifier lookups and other
            // per-origin features.
            let hostname = origin_idx
                .and_then(|idx| pipeline.config.origins.get(idx))
                .map(|o| o.hostname.to_string())
                .unwrap_or_default();

            // Phase 7: realtime WebSocket dispatch. When the request
            // is a GET upgrade for `/v1/realtime`, run the standard
            // AI gateway gating (surface classify, 501 capability
            // check, per-surface rate limit, metrics) and stash the
            // selected provider's connection target on the request
            // context so `upstream_peer` can build the dynamic peer.
            // Returns `Ok(false)` so Pingora proceeds to its normal
            // transparent forwarding flow.
            let method = session.req_header().method.clone();
            let path = session.req_header().uri.path().to_string();
            let is_websocket_upgrade = session
                .req_header()
                .headers
                .get("upgrade")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_ascii_lowercase().contains("websocket"))
                .unwrap_or(false);
            let surface_for_check = sbproxy_ai::handler::classify_surface(method.as_str(), &path);
            if method == http::Method::GET
                && is_websocket_upgrade
                && matches!(surface_for_check, sbproxy_ai::handler::AiSurface::Realtime)
            {
                let surface_label = surface_for_check.label();
                ctx.ai_surface = Some(surface_label.to_string());
                sbproxy_ai::ai_metrics::record_surface_request(surface_label, method.as_str());

                // Per-surface rate limit gate.
                if let Some(rate_cfg) = ai.config.per_surface_rate_limits.get(surface_label) {
                    if !AI_SURFACE_RATE_LIMITER.check_rate(surface_label, rate_cfg) {
                        warn!(
                            ai.surface = surface_label,
                            "AI realtime: per-surface rate limit hit; returning 429"
                        );
                        send_error(session, 429, "per-surface rate limit exceeded").await?;
                        return Ok(true);
                    }
                }

                // 501 gate: pick the first provider that supports realtime.
                let provider = ai
                    .config
                    .providers
                    .iter()
                    .find(|p| sbproxy_ai::api_routes::provider_supports_realtime(&p.name));
                let provider = match provider {
                    Some(p) => p,
                    None => {
                        warn!(
                            ai.surface = surface_label,
                            "AI realtime: no configured provider supports realtime; returning 501"
                        );
                        send_error(session, 501, "no configured AI provider supports realtime")
                            .await?;
                        return Ok(true);
                    }
                };

                // Parse the provider's base URL into (host, port, tls).
                // Realtime uses wss:// to api.openai.com; provider base_url
                // is typically https://api.openai.com/v1, which gives us
                // the same host/port pair (TLS on 443).
                let base_url_owned = provider.effective_base_url();
                let parsed_url = match url::Url::parse(&base_url_owned) {
                    Ok(u) => u,
                    Err(e) => {
                        warn!(error = %e, "AI realtime: invalid provider base_url");
                        send_error(session, 502, "invalid provider base_url").await?;
                        return Ok(true);
                    }
                };
                let host = match parsed_url.host_str() {
                    Some(h) => h.to_string(),
                    None => {
                        warn!("AI realtime: provider base_url has no host");
                        send_error(session, 502, "provider base_url missing host").await?;
                        return Ok(true);
                    }
                };
                let tls = matches!(parsed_url.scheme(), "https" | "wss");
                let port = parsed_url
                    .port_or_known_default()
                    .unwrap_or(if tls { 443 } else { 80 });

                ctx.ai_realtime_dispatch = Some(crate::context::RealtimeDispatchCtx {
                    provider_name: provider.name.to_string(),
                    upstream_host: host.clone(),
                    upstream_port: port,
                    upstream_tls: tls,
                    started_at: std::time::Instant::now(),
                    surface_label: "realtime",
                });
                ctx.ai_provider = Some(provider.name.to_string());
                sbproxy_ai::ai_metrics::inc_realtime_sessions_active();
                info!(
                    ai.surface = surface_label,
                    provider = %provider.name,
                    upstream_host = %host,
                    upstream_port = port,
                    upstream_tls = tls,
                    "AI realtime: session opening, handing off to Pingora for transparent forwarding"
                );

                // Let Pingora's normal flow continue: `upstream_peer`
                // will read `ctx.ai_realtime_dispatch` and build the
                // peer; Pingora forwards bytes after the upgrade.
                return Ok(false);
            }

            handle_ai_proxy(session, &ai.config, pipeline, &hostname, ctx, origin_idx).await?;
            Ok(true)
        }

        Action::Storage(storage) => {
            let req = session.req_header();
            let method = req.method.as_str().to_string();
            let path = req.uri.path().to_string();
            let range = req
                .headers
                .get("range")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let resp = storage.serve(&method, &path, range.as_deref()).await;
            let mut header =
                pingora_http::ResponseHeader::build(resp.status, Some(resp.headers.len()))
                    .map_err(|e| {
                        Error::because(
                            ErrorType::InternalError,
                            "failed to build storage response header",
                            e,
                        )
                    })?;
            for (name, value) in &resp.headers {
                header.insert_header(name.clone(), value).map_err(|e| {
                    Error::because(
                        ErrorType::InternalError,
                        "failed to set storage response header",
                        e,
                    )
                })?;
            }
            // For HEAD or empty bodies the response is header-only.
            let has_body = resp.body.is_some();
            session
                .write_response_header(Box::new(header), !has_body)
                .await?;
            if let Some(body) = resp.body {
                session.write_response_body(Some(body), true).await?;
            }
            Ok(true)
        }

        Action::Redirect(r) => {
            // Per-origin bulk-redirect table takes precedence: an exact
            // match on the request path overrides the action's url.
            let request_path = session.req_header().uri.path();
            let (target_url, target_status, preserve_query) =
                match r.table.as_ref().and_then(|t| t.lookup(request_path)) {
                    Some(row) => (row.to.clone(), row.status, row.preserve_query),
                    None => (r.url.clone(), r.status, r.preserve_query),
                };

            if target_url.is_empty() {
                // No bulk match and no fallback url: surface a 404 so
                // the caller sees an unconfigured route instead of an
                // empty redirect.
                let header = pingora_http::ResponseHeader::build(404, Some(0)).map_err(|e| {
                    Error::because(
                        ErrorType::InternalError,
                        "failed to build redirect 404 header",
                        e,
                    )
                })?;
                session
                    .write_response_header(Box::new(header), true)
                    .await?;
                return Ok(true);
            }

            let mut header =
                pingora_http::ResponseHeader::build(target_status, Some(1)).map_err(|e| {
                    Error::because(
                        ErrorType::InternalError,
                        "failed to build redirect header",
                        e,
                    )
                })?;
            let location = if preserve_query {
                match session.req_header().uri.query() {
                    Some(qs) if !qs.is_empty() => {
                        if target_url.contains('?') {
                            format!("{}&{}", target_url, qs)
                        } else {
                            format!("{}?{}", target_url, qs)
                        }
                    }
                    _ => target_url,
                }
            } else {
                target_url
            };
            header.insert_header("location", &location).map_err(|e| {
                Error::because(ErrorType::InternalError, "failed to set location", e)
            })?;
            session
                .write_response_header(Box::new(header), true)
                .await?;
            Ok(true)
        }

        Action::Static(s) => {
            // `ct` is owned (instead of an `&str` slice off `s`) so
            // day-5 Items 3 and 4 can rebind it to the JSON-envelope
            // or Markdown Content-Type after the typed transforms
            // run.
            let mut ct = s
                .content_type
                .as_deref()
                .unwrap_or("text/plain")
                .to_string();

            // Why: stamp the static action's status onto ctx before
            // transforms run so the day-6 Item 1 CEL header transform
            // can read `response.status` from the static response.
            // The upstream-body path gets it from `response_filter`
            // earlier in the chain; the static action never goes
            // through Pingora's response_filter so we set it here.
            ctx.response_status = Some(s.status);

            // Apply transforms to the static body if any are configured.
            // Wave 4 day-5: walks the pipeline through `apply_transform_with_ctx`
            // so the gated `html_to_markdown`, typed `citation_block`, and
            // typed `json_envelope` all run with the per-request ctx fields
            // (`content_shape_transform`, `markdown_projection`,
            // `canonical_url`, `rsl_urn`, `citation_required`).
            let mut body_bytes = if let Some(idx) = origin_idx {
                if idx < pipeline.transforms.len() && !pipeline.transforms[idx].is_empty() {
                    let mut buf = bytes::BytesMut::from(s.body.as_bytes());
                    let content_type = Some(ct.as_str());
                    let ratio = resolved_token_bytes_ratio(Some(&pipeline.config.origins[idx]));
                    for compiled_transform in &pipeline.transforms[idx] {
                        let needs_synth_projection = matches!(
                            compiled_transform.transform,
                            sbproxy_modules::Transform::CitationBlock(_)
                                | sbproxy_modules::Transform::JsonEnvelope(_)
                        );
                        if needs_synth_projection {
                            synthesise_markdown_projection_if_missing(ctx, &buf, ratio);
                        }
                        if let Err(e) = apply_transform_with_ctx(
                            compiled_transform,
                            &mut buf,
                            content_type,
                            ctx,
                        ) {
                            warn!(
                                transform = compiled_transform.transform.transform_type(),
                                error = %e,
                                "static action transform failed, continuing"
                            );
                        }
                    }
                    buf.freeze()
                } else {
                    Bytes::copy_from_slice(s.body.as_bytes())
                }
            } else {
                Bytes::copy_from_slice(s.body.as_bytes())
            };

            // Wave 4 day-5 Items 3 + 4: shape-driven body rewrite +
            // Content-Type override.
            //
            // - When the negotiated shape is Json AND no
            //   `json_envelope` transform has already produced the
            //   envelope, synthesise a Markdown projection from the
            //   body and build a fresh envelope here.
            // - When the negotiated shape is Markdown, run the
            //   citation_block transform inline if `citation_required`
            //   is set and no `citation_block` transform was wired
            //   into the chain. Detected by checking whether the body
            //   already starts with the citation prefix.
            // - In both cases override `ct` so the response
            //   Content-Type lines up with the body.
            if matches!(
                ctx.content_shape_transform,
                Some(sbproxy_modules::ContentShape::Json)
            ) {
                let already_envelope = serde_json::from_slice::<serde_json::Value>(&body_bytes)
                    .ok()
                    .and_then(|v| {
                        v.get("schema_version")
                            .and_then(|s| s.as_str())
                            .map(|s| s == sbproxy_modules::JSON_ENVELOPE_SCHEMA_VERSION)
                    })
                    .unwrap_or(false);
                if !already_envelope {
                    let ratio = resolved_token_bytes_ratio(
                        origin_idx.map(|idx| &pipeline.config.origins[idx]),
                    );
                    synthesise_markdown_projection_if_missing(ctx, &body_bytes, ratio);
                    if let Some(projection) = ctx.markdown_projection.as_ref() {
                        let envelope = sbproxy_modules::JsonEnvelope::from_projection(
                            projection,
                            ctx.canonical_url.as_deref(),
                            ctx.rsl_urn.as_deref(),
                            ctx.citation_required.unwrap_or(false),
                            None,
                            chrono::Utc::now(),
                        );
                        if let Ok(env_bytes) = envelope.to_vec() {
                            body_bytes = Bytes::from(env_bytes);
                        }
                    }
                }
                ct = sbproxy_modules::JSON_ENVELOPE_CONTENT_TYPE.to_string();
            } else if matches!(
                ctx.content_shape_transform,
                Some(sbproxy_modules::ContentShape::Markdown)
            ) {
                let cite_required = ctx.citation_required.unwrap_or(false);
                let needs_citation_prefix = cite_required
                    && !std::str::from_utf8(&body_bytes)
                        .map(|s| s.starts_with("> Citation required"))
                        .unwrap_or(true);
                if needs_citation_prefix {
                    let mut buf = bytes::BytesMut::from(&body_bytes[..]);
                    let cb = sbproxy_modules::CitationBlockTransform::default();
                    if let Err(e) = cb.apply(
                        &mut buf,
                        ctx.canonical_url.as_deref(),
                        ctx.rsl_urn.as_deref(),
                        ctx.citation_required,
                    ) {
                        warn!(error = %e, "citation_block fall-through failed");
                    } else {
                        body_bytes = buf.freeze();
                    }
                }
                ct = "text/markdown; charset=utf-8".to_string();
            }

            // Apply response modifiers to static actions (body replacement, headers, Lua, status).
            let mut status_override: Option<u16> = None;
            let mut extra_headers: Vec<(String, String)> = Vec::new();
            // Wave 5 day-6 Item 1: drain CEL header mutations the
            // transform pipeline accumulated while walking the body.
            // Set / Append both surface as `extra_headers` entries;
            // Remove is folded in below by deleting the matching
            // entries before the response builder runs.
            let mut cel_header_removals: Vec<String> = Vec::new();
            for m in std::mem::take(&mut ctx.cel_response_header_mutations) {
                match m {
                    sbproxy_modules::transform::CelHeaderMutation::Set(k, v)
                    | sbproxy_modules::transform::CelHeaderMutation::Append(k, v) => {
                        extra_headers.push((k, v));
                    }
                    sbproxy_modules::transform::CelHeaderMutation::Remove(k) => {
                        cel_header_removals.push(k);
                    }
                }
            }
            if let Some(idx) = origin_idx {
                let origin = &pipeline.config.origins[idx];
                for modifier in &origin.response_modifiers {
                    // Body replacement
                    if let Some(body_mod) = &modifier.body {
                        if let Some(json_val) = &body_mod.replace_json {
                            body_bytes = Bytes::from(json_val.to_string());
                        } else if let Some(text) = &body_mod.replace {
                            body_bytes = Bytes::from(text.clone());
                        }
                    }
                    // Status override
                    if let Some(status_mod) = &modifier.status {
                        status_override = Some(status_mod.code);
                    }
                    // Header modifiers
                    if let Some(hm) = &modifier.headers {
                        for (key, value) in &hm.set {
                            extra_headers.push((key.clone(), value.clone()));
                        }
                        for (key, value) in &hm.add {
                            extra_headers.push((key.clone(), value.clone()));
                        }
                    }
                    // Lua response modifier
                    if let Some(script) = &modifier.lua_script {
                        let lua_status = status_override.unwrap_or(s.status);
                        match lua_response_modifier(script, lua_status) {
                            Ok(headers) => {
                                for (key, value) in headers {
                                    extra_headers.push((key, value));
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "Lua response modifier on static action failed");
                            }
                        }
                    }
                }
            }

            let effective_status = status_override.unwrap_or(s.status);
            let num_headers = 2 + s.headers.len() + extra_headers.len();
            let mut header =
                pingora_http::ResponseHeader::build(effective_status, Some(num_headers)).map_err(
                    |e| {
                        Error::because(ErrorType::InternalError, "failed to build static header", e)
                    },
                )?;
            header
                .insert_header("content-type", ct.as_str())
                .map_err(|e| {
                    Error::because(ErrorType::InternalError, "failed to set content-type", e)
                })?;
            header
                .insert_header("content-length", body_bytes.len().to_string())
                .map_err(|e| {
                    Error::because(ErrorType::InternalError, "failed to set content-length", e)
                })?;
            for (k, v) in &s.headers {
                if cel_header_removals
                    .iter()
                    .any(|r| r.eq_ignore_ascii_case(k))
                {
                    continue;
                }
                header.insert_header(k.clone(), v.clone()).map_err(|e| {
                    Error::because(ErrorType::InternalError, "failed to set header", e)
                })?;
            }
            for (k, v) in &extra_headers {
                if cel_header_removals
                    .iter()
                    .any(|r| r.eq_ignore_ascii_case(k))
                {
                    continue;
                }
                let _ = header.insert_header(k.clone(), v.clone());
            }
            // Final pass: stamp explicit removals so any header set
            // by an earlier middleware (cors, hsts, content-signal)
            // is also stripped when the operator asked for it.
            for k in &cel_header_removals {
                let _ = header.remove_header(k);
            }
            // Wave 4 day-5 Item 5: stamp `x-markdown-tokens` when the
            // negotiated transform shape is Markdown or Json. Skipped
            // for Html / Pdf / Other shapes and for legacy origins
            // (shape == None) so non-AI responses are unaffected. The
            // per-origin `token_bytes_ratio:` override (A4.2 follow-up)
            // threads through the fallback path so the header still
            // honours the operator's calibration when the synthesise
            // step never ran (e.g. legacy origin with no transforms).
            let ratio_override =
                origin_idx.and_then(|idx| pipeline.config.origins[idx].token_bytes_ratio);
            if let Some(n) = x_markdown_tokens_header_value_with_ratio(
                ctx.content_shape_transform,
                ctx.markdown_token_estimate,
                Some(body_bytes.len() as u64),
                ratio_override,
            ) {
                let _ = header.insert_header("x-markdown-tokens", n.to_string());
            }
            // Wave 4 / G4.5: stamp Content-Signal on 2xx static
            // responses when the origin set the closed-enum value.
            // The check shares `resolve_content_signal_decision` with
            // the response_filter path so static and upstream-proxied
            // responses produce the same wire shape.
            if let Some(idx) = origin_idx {
                let origin = &pipeline.config.origins[idx];
                let is_2xx = (200..300).contains(&effective_status);
                let projections = sbproxy_modules::projections::current_projections();
                let host_key = origin.hostname.as_str();
                let projection_signal = projections
                    .content_signals
                    .get(host_key)
                    .map(|maybe| maybe.as_ref().map(|cs| cs.as_str()));
                match resolve_content_signal_decision(
                    is_2xx,
                    origin.content_signal,
                    projection_signal,
                ) {
                    ContentSignalDecision::Stamp(value) => {
                        let _ = header.insert_header("content-signal", value);
                    }
                    ContentSignalDecision::TdmReservationFallback => {
                        let _ = header.insert_header("tdm-reservation", "1");
                    }
                    ContentSignalDecision::Skip => {}
                }
            }
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session.write_response_body(Some(body_bytes), true).await?;
            Ok(true)
        }

        Action::Echo(_) => {
            let method = session.req_header().method.as_str().to_string();
            let path = session.req_header().uri.path().to_string();
            let headers: serde_json::Map<String, serde_json::Value> = session
                .req_header()
                .headers
                .iter()
                .map(|(k, v)| {
                    (
                        k.to_string(),
                        serde_json::Value::String(v.to_str().unwrap_or("").to_string()),
                    )
                })
                .collect();
            let echo = serde_json::json!({
                "method": method,
                "path": path,
                "headers": headers,
            });
            let body = serde_json::to_vec(&echo).unwrap_or_default();
            send_response(session, 200, "application/json", &body).await?;
            Ok(true)
        }

        Action::Mock(m) => {
            let num_headers = 1 + m.headers.len();
            let mut header = pingora_http::ResponseHeader::build(m.status, Some(num_headers))
                .map_err(|e| {
                    Error::because(ErrorType::InternalError, "failed to build mock header", e)
                })?;
            header
                .insert_header("content-type", "application/json")
                .map_err(|e| {
                    Error::because(ErrorType::InternalError, "failed to set content-type", e)
                })?;
            for (k, v) in &m.headers {
                header.insert_header(k.clone(), v.clone()).map_err(|e| {
                    Error::because(ErrorType::InternalError, "failed to set header", e)
                })?;
            }
            let body = serde_json::to_vec(&m.body).unwrap_or_default();
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session
                .write_response_body(Some(bytes::Bytes::from(body)), true)
                .await?;
            Ok(true)
        }

        Action::Beacon(_) => {
            let mut header = pingora_http::ResponseHeader::build(200, Some(2)).map_err(|e| {
                Error::because(ErrorType::InternalError, "failed to build beacon header", e)
            })?;
            header
                .insert_header("content-type", "image/gif")
                .map_err(|e| {
                    Error::because(ErrorType::InternalError, "failed to set content-type", e)
                })?;
            header
                .insert_header("cache-control", "no-cache, no-store")
                .map_err(|e| {
                    Error::because(ErrorType::InternalError, "failed to set cache-control", e)
                })?;
            session
                .write_response_header(Box::new(header), false)
                .await?;
            // 1x1 transparent GIF
            static GIF_1X1: &[u8] = &[
                0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0xff,
                0xff, 0xff, 0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c,
                0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00,
                0x3b,
            ];
            session
                .write_response_body(Some(bytes::Bytes::from_static(GIF_1X1)), true)
                .await?;
            Ok(true)
        }

        Action::Noop => {
            let header = pingora_http::ResponseHeader::build(200, None).map_err(|e| {
                Error::because(ErrorType::InternalError, "failed to build noop header", e)
            })?;
            session
                .write_response_header(Box::new(header), true)
                .await?;
            Ok(true)
        }

        Action::Mcp(mcp) => {
            // WOR-195: thread the origin's `agent_skills:` posture into
            // the MCP handler so `initialize` can advertise the
            // discovery URL via `experimental.agentSkillsUrl`.
            let has_skills = origin_idx
                .and_then(|idx| pipeline.config.origins.get(idx))
                .map(|o| !o.agent_skills.is_empty())
                .unwrap_or(false);
            handle_mcp_action(session, mcp, ctx, has_skills).await?;
            Ok(true)
        }

        Action::Plugin(_) => {
            send_error(session, 501, "plugin actions not yet supported").await?;
            Ok(true)
        }
    }
}

// --- MCP gateway action handler ---

/// Handle an MCP `Action::Mcp` request.
///
/// Speaks the MCP wire protocol over HTTP POST + JSON-RPC 2.0:
///
/// * `initialize` returns the configured `server_info` plus `tools` capability.
/// * `tools/list` aggregates the federated upstream tool catalogue.
/// * `tools/call` enforces the inline `tool_allowlist` guardrail and
///   forwards to the owning upstream via `McpFederation::call_tool`.
/// * `ping` returns `"pong"`.
///
/// Methods other than `POST` produce a 405. Malformed JSON-RPC bodies
/// surface as a proper JSON-RPC error envelope so MCP clients can
/// surface the failure to their LLM.
pub(super) async fn handle_mcp_action(
    session: &mut Session,
    mcp: &sbproxy_modules::action::McpAction,
    ctx: &RequestContext,
    has_agent_skills: bool,
) -> Result<()> {
    use sbproxy_extension::mcp::types::{
        InitializeResult, JsonRpcRequest, JsonRpcResponse, ServerCapabilities, ServerInfo,
        INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST, METHOD_NOT_FOUND, PARSE_ERROR,
    };

    let method = session.req_header().method.clone();
    let req_path = session.req_header().uri.path();

    // WOR-483: serve the federated tool catalogue as a typed
    // Cloudflare-Code-Mode TypeScript module at
    // `/.well-known/mcp/codemode.ts`. WOR-410 added the
    // `McpFederation::codemode_ts(callback_base_url)` library
    // function; this branch wraps it in a one-URL HTTP surface so
    // any TypeScript agent or sandbox can `import` the module
    // directly without a separate codegen step.
    if method == http::Method::GET && req_path == "/.well-known/mcp/codemode.ts" {
        use sha2::{Digest, Sha256};

        let listener_is_tls = session
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .is_some();
        let scheme = if listener_is_tls { "https" } else { "http" };
        let callback_base = match session
            .req_header()
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
        {
            // The runtime stub posts each tool call to
            // `{callback}/call/{tool_name}`, so the callback root is
            // the MCP gateway path itself (the request path stripped
            // of the well-known suffix). For the typical mount where
            // the MCP origin owns the whole hostname, the gateway
            // accepts the JSON-RPC POSTs at `/`; passing the bare
            // origin URL is the safest default.
            Some(authority) => format!("{scheme}://{authority}"),
            None => String::new(),
        };
        let module = mcp.federation.codemode_ts(&callback_base);

        // Strong ETag is the lowercase hex SHA-256 of the emitted
        // bytes wrapped in double quotes per RFC 9110 §8.8.3. The
        // federation sorts tools lexicographically before emission,
        // so the digest is stable across calls as long as the tool
        // registry does not change; a CDN or browser can pin against
        // it with `If-None-Match` and skip the body on the next pull.
        let digest = Sha256::digest(module.as_bytes());
        let mut etag_value = String::with_capacity(2 + digest.len() * 2);
        etag_value.push('"');
        for byte in digest.iter() {
            etag_value.push_str(&format!("{:02x}", byte));
        }
        etag_value.push('"');

        let if_none_match = session
            .req_header()
            .headers
            .get("if-none-match")
            .and_then(|v| v.to_str().ok());

        // 60 seconds keeps the catalogue fresh enough that a
        // federation refresh propagates quickly, while
        // `must-revalidate` forces shared caches to re-check via
        // the Etag once the TTL expires.
        const CACHE_CONTROL: &str = "max-age=60, must-revalidate";

        // RFC 9110 §13.1.2 If-None-Match matching is a list of
        // entity tags or `*`; accept any whitespace-separated entry
        // that matches the digest. We avoid weak tags entirely
        // because the body is byte-stable on every emission.
        let etag_match = if_none_match
            .map(|h| {
                h.split(',')
                    .any(|tok| tok.trim() == etag_value || tok.trim() == "*")
            })
            .unwrap_or(false);

        if etag_match {
            let mut header = pingora_http::ResponseHeader::build(304, Some(2)).map_err(|e| {
                Error::because(ErrorType::InternalError, "failed to build 304 header", e)
            })?;
            let _ = header.insert_header("etag", &etag_value);
            let _ = header.insert_header("cache-control", CACHE_CONTROL);
            session
                .write_response_header(Box::new(header), true)
                .await?;
            tracing::info!(
                target: "sbproxy::audit",
                event = "mcp.codemode_ts.not_modified",
                mcp_server = %mcp.server_name,
                request_id = %ctx.request_id,
                "codemode.ts module unchanged; returned 304"
            );
            return Ok(());
        }

        // 200 path: write content-type + content-length + etag +
        // cache-control inline so we can carry both custom headers.
        let body = module.into_bytes();
        let mut header = pingora_http::ResponseHeader::build(200, Some(4)).map_err(|e| {
            Error::because(
                ErrorType::InternalError,
                "failed to build codemode.ts header",
                e,
            )
        })?;
        let _ = header.insert_header("content-type", "text/typescript; charset=utf-8");
        let _ = header.insert_header("content-length", body.len().to_string());
        let _ = header.insert_header("etag", &etag_value);
        let _ = header.insert_header("cache-control", CACHE_CONTROL);
        session
            .write_response_header(Box::new(header), false)
            .await?;
        let body_len = body.len();
        session
            .write_response_body(Some(bytes::Bytes::from(body)), true)
            .await?;
        tracing::info!(
            target: "sbproxy::audit",
            event = "mcp.codemode_ts.served",
            mcp_server = %mcp.server_name,
            request_id = %ctx.request_id,
            byte_count = body_len,
            etag = %etag_value,
            "served codemode.ts module"
        );
        return Ok(());
    }

    // WOR-806: serve the MCP discovery manifest at
    // `/.well-known/mcp-server` and the Cloudflare Agent-Readiness
    // variant `/.well-known/mcp/server-card.json`. An autonomous agent
    // fetches this to learn the gateway's endpoint, protocol version,
    // transport, and tool catalogue without first opening a JSON-RPC
    // session. Served for any origin whose action is the MCP gateway.
    if method == http::Method::GET
        && sbproxy_extension::mcp::discovery::SERVER_MANIFEST_PATHS.contains(&req_path)
    {
        // Own the path now so its borrow of `session` ends before the
        // mutable `write_response_*` calls below (used only for audit).
        let path_for_log = req_path.to_string();
        let listener_is_tls = session
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .is_some();
        let scheme = if listener_is_tls { "https" } else { "http" };
        let endpoint = match session
            .req_header()
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
        {
            Some(authority) => format!("{scheme}://{authority}/"),
            None => "/".to_string(),
        };
        // Advertise the gateway's tool catalogue, honouring any
        // collapsed `tool_allowlist` guardrail so the manifest never
        // lists a tool the gateway would refuse to call.
        let tools: Vec<sbproxy_extension::mcp::discovery::DiscoveryTool> = mcp
            .federation
            .list_tools()
            .into_iter()
            .filter(|t| {
                mcp.tool_allowlist
                    .as_ref()
                    .map(|allow| allow.iter().any(|a| a == &t.name))
                    .unwrap_or(true)
            })
            .map(|t| sbproxy_extension::mcp::discovery::DiscoveryTool {
                name: t.name,
                description: t.description,
            })
            .collect();
        let manifest = sbproxy_extension::mcp::discovery::build_server_manifest(
            &mcp.server_name,
            &mcp.server_version,
            "2025-06-18",
            &endpoint,
            &tools,
        );
        let body = serde_json::to_vec(&manifest).unwrap_or_default();
        let mut header = pingora_http::ResponseHeader::build(200, Some(2)).map_err(|e| {
            Error::because(
                ErrorType::InternalError,
                "failed to build mcp discovery header",
                e,
            )
        })?;
        let _ = header.insert_header(
            "content-type",
            sbproxy_extension::mcp::discovery::SERVER_MANIFEST_CONTENT_TYPE,
        );
        let _ = header.insert_header("content-length", body.len().to_string());
        let tool_count = tools.len();
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(bytes::Bytes::from(body)), true)
            .await?;
        tracing::info!(
            target: "sbproxy::audit",
            event = "mcp.discovery.served",
            mcp_server = %mcp.server_name,
            request_id = %ctx.request_id,
            path = %path_for_log,
            tool_count,
            "served MCP discovery manifest"
        );
        return Ok(());
    }

    if method != http::Method::POST {
        send_error(session, 405, "MCP gateway accepts POST only").await?;
        return Ok(());
    }

    // Cap the inbound JSON-RPC body before reading it into memory.
    // MCP requests are a few KiB at most; an unbounded
    // `read_request_body()` would let a misconfigured (or hostile)
    // client exhaust per-worker memory and stall the handler. We
    // also reject early if `Content-Length` already exceeds the cap.
    const MAX_MCP_BODY_BYTES: usize = 1024 * 1024;
    if let Some(declared) = session
        .req_header()
        .headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
    {
        if declared > MAX_MCP_BODY_BYTES {
            send_error(session, 413, "MCP request body too large").await?;
            return Ok(());
        }
    }
    let mut body_bytes = bytes::BytesMut::new();
    while let Some(chunk) = session.read_request_body().await? {
        if body_bytes.len().saturating_add(chunk.len()) > MAX_MCP_BODY_BYTES {
            send_error(session, 413, "MCP request body too large").await?;
            return Ok(());
        }
        body_bytes.extend_from_slice(&chunk);
    }
    let body_bytes = body_bytes.freeze();
    let request: JsonRpcRequest = match serde_json::from_slice(&body_bytes) {
        Ok(r) => r,
        Err(_) => {
            let err = JsonRpcResponse::error(None, PARSE_ERROR, "invalid JSON-RPC body");
            return write_jsonrpc(session, &err).await;
        }
    };

    if request.jsonrpc != "2.0" {
        let err = JsonRpcResponse::error(
            request.id.clone(),
            INVALID_REQUEST,
            "jsonrpc field must be \"2.0\"",
        );
        return write_jsonrpc(session, &err).await;
    }

    // Notifications (id absent) get an empty 204 per JSON-RPC 2.0.
    if request.id.is_none() {
        let header = pingora_http::ResponseHeader::build(204, Some(0))
            .map_err(|e| Error::because(ErrorType::InternalError, "failed to build mcp 204", e))?;
        session
            .write_response_header(Box::new(header), true)
            .await?;
        return Ok(());
    }

    let response = match request.method.as_str() {
        "initialize" => {
            // WOR-195: when the origin opts into Agent Skills, surface
            // `experimental.agentSkillsUrl` so MCP clients that have
            // learned to fetch the manifest can discover skills
            // without out-of-band configuration. Anonymous callers
            // and authenticated callers see the same path; the
            // manifest itself filters by visibility at serve time.
            let experimental = if has_agent_skills {
                let listener_is_tls = session
                    .digest()
                    .and_then(|d| d.ssl_digest.as_ref())
                    .is_some();
                let scheme = if listener_is_tls { "https" } else { "http" };
                let url = match session
                    .req_header()
                    .headers
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                {
                    Some(authority) => {
                        format!("{scheme}://{authority}/.well-known/agent-skills/index.json")
                    }
                    None => "/.well-known/agent-skills/index.json".to_string(),
                };
                Some(serde_json::json!({ "agentSkillsUrl": url }))
            } else {
                None
            };
            let result = InitializeResult {
                protocol_version: "2025-06-18".to_string(),
                capabilities: ServerCapabilities {
                    tools: Some(serde_json::json!({})),
                    resources: None,
                    prompts: None,
                    experimental,
                },
                server_info: ServerInfo {
                    name: mcp.server_name.clone(),
                    version: mcp.server_version.clone(),
                },
            };
            JsonRpcResponse::success(
                request.id.clone(),
                serde_json::to_value(result).unwrap_or(serde_json::Value::Null),
            )
        }
        "ping" => JsonRpcResponse::success(request.id.clone(), serde_json::json!("pong")),
        "tools/list" => {
            // Lazy refresh: kick off a tools fetch on the first call so
            // the registry is populated. Subsequent calls reuse the
            // cached snapshot until the operator wires up a periodic
            // refresh task. Failures fall through to an empty list.
            if let Err(e) = mcp.federation.refresh_tools().await {
                warn!(error = %e, "MCP federation tool refresh failed");
            }
            let tools = mcp.federation.list_tools();
            let tool_defs: Vec<serde_json::Value> = tools
                .into_iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "inputSchema": t.input_schema,
                    })
                })
                .collect();
            JsonRpcResponse::success(
                request.id.clone(),
                serde_json::json!({ "tools": tool_defs }),
            )
        }
        "tools/call" => {
            let params = request.params.clone().unwrap_or(serde_json::Value::Null);
            let tool_name = params
                .get("name")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            match tool_name {
                None => JsonRpcResponse::error(
                    request.id.clone(),
                    INVALID_PARAMS,
                    "tools/call requires a 'name' parameter",
                ),
                Some(name) => {
                    if !mcp.is_tool_allowed(&name) {
                        JsonRpcResponse::error(
                            request.id.clone(),
                            INVALID_PARAMS,
                            &format!("tool '{}' is blocked by tool_allowlist guardrail", name),
                        )
                    } else {
                        // WOR-186: per-server RBAC + timeout enforcement.
                        //
                        // 1. Resolve the caller's virtual key from the
                        //    auth context (`Allow.sub`); fall back to
                        //    "" (anonymous) when no subject is set so
                        //    the policy lookup still has a stable key.
                        // 2. Resolve the tool's owning upstream and
                        //    check the per-server `ToolAccessPolicy`
                        //    (when one is wired). A denied tool returns
                        //    a JSON-RPC error and bumps an audit
                        //    counter; the upstream is never contacted.
                        // 3. Wrap `federation.call_tool` in
                        //    `tokio::time::timeout(server.timeout, ...)`
                        //    when a per-server timeout is configured.
                        let virtual_key = mcp_virtual_key(ctx);
                        let federated = mcp.federation.resolve_tool(&name);
                        let denied_by_rbac = match &federated {
                            Some(t) => {
                                if let Some(policy) = mcp.policy_for_server(&t.server_name) {
                                    !policy.is_tool_allowed(&virtual_key, &name)
                                } else {
                                    false
                                }
                            }
                            None => false,
                        };
                        if denied_by_rbac {
                            tracing::warn!(
                                target: "sbproxy::mcp::rbac",
                                tool = %name,
                                virtual_key = %virtual_key,
                                "MCP tools/call denied by RBAC policy",
                            );
                            sbproxy_observe::metrics::record_policy(
                                ctx.hostname.as_str(),
                                "mcp_rbac",
                                "deny",
                            );
                            JsonRpcResponse::error(
                                request.id.clone(),
                                INVALID_PARAMS,
                                &format!("tool '{}' is denied by RBAC policy for caller", name,),
                            )
                        } else {
                            // Per-server timeout. The
                            // dispatcher inside `call_tool` shares one
                            // reqwest::Client across upstreams; the
                            // request-level cap is what makes the field
                            // observable.
                            let timeout = federated
                                .as_ref()
                                .and_then(|t| mcp.timeout_for_server(&t.server_name));
                            let call = mcp.federation.call_tool(&name, arguments);
                            let outcome = match timeout {
                                Some(d) => match tokio::time::timeout(d, call).await {
                                    Ok(r) => r,
                                    Err(_elapsed) => {
                                        tracing::warn!(
                                            target: "sbproxy::mcp::timeout",
                                            tool = %name,
                                            timeout_ms = d.as_millis() as u64,
                                            "MCP tools/call exceeded per-server timeout",
                                        );
                                        sbproxy_observe::metrics::record_policy(
                                            ctx.hostname.as_str(),
                                            "mcp_timeout",
                                            "deny",
                                        );
                                        Err(anyhow::anyhow!(
                                            "tool call exceeded per-server timeout of {}ms",
                                            d.as_millis(),
                                        ))
                                    }
                                },
                                None => call.await,
                            };
                            match outcome {
                                Ok(value) => {
                                    sbproxy_observe::metrics::record_policy(
                                        ctx.hostname.as_str(),
                                        "mcp_rbac",
                                        "allow",
                                    );
                                    JsonRpcResponse::success(request.id.clone(), value)
                                }
                                Err(e) => JsonRpcResponse::error(
                                    request.id.clone(),
                                    INTERNAL_ERROR,
                                    &format!("tool call failed: {}", e),
                                ),
                            }
                        }
                    }
                }
            }
        }
        other => JsonRpcResponse::error(
            request.id.clone(),
            METHOD_NOT_FOUND,
            &format!("unknown method: {}", other),
        ),
    };

    write_jsonrpc(session, &response).await
}

/// Resolve the caller's virtual key for MCP RBAC lookups.
///
/// Pulls the resolved subject from the auth decision when the request
/// authenticated; returns the empty string for anonymous traffic so a
/// `ToolAccessPolicy` keyed on `""` can still encode an explicit
/// "anonymous" lane.
pub(super) fn mcp_virtual_key(ctx: &RequestContext) -> String {
    match ctx.auth_result.as_ref() {
        Some(sbproxy_plugin::AuthDecision::Allow { sub: Some(s), .. }) => s.clone(),
        _ => String::new(),
    }
}

/// Serialise a JSON-RPC response and write it to the session.
pub(super) async fn write_jsonrpc(
    session: &mut Session,
    response: &sbproxy_extension::mcp::types::JsonRpcResponse,
) -> Result<()> {
    let body = serde_json::to_vec(response).map_err(|e| {
        Error::because(
            ErrorType::InternalError,
            "failed to serialise JSON-RPC response",
            e,
        )
    })?;
    send_response(session, 200, "application/json", &body).await
}
