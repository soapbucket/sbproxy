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
        | Action::GraphQL(_)
        | Action::A2a(_) => Ok(false),

        Action::Grpc(g) => {
            // WOR-819: a REST request (not native `application/grpc`) sent
            // to a transcode-configured grpc action that matches no route
            // is a 404. We reject here, in request_filter, rather than
            // letting it proxy as a native gRPC call. Native gRPC requests
            // and matched transcode routes proxy normally (`Ok(false)`);
            // the route is matched again in `upstream_request_filter` to
            // drive the request/response body rewrite.
            if let Some(transcoder) = g.transcoder.as_ref() {
                let is_native_grpc = session
                    .req_header()
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|ct| ct.starts_with("application/grpc"))
                    .unwrap_or(false);
                if !is_native_grpc {
                    let method = session.req_header().method.as_str().to_string();
                    let path = session.req_header().uri.path().to_string();
                    if transcoder.match_route(&method, &path).is_none() {
                        let body = bytes::Bytes::from_static(
                            b"{\"error\":\"no transcode route for this path\"}",
                        );
                        let mut header = pingora_http::ResponseHeader::build(404, Some(1))
                            .map_err(|e| {
                                Error::because(
                                    ErrorType::InternalError,
                                    "failed to build transcode 404 header",
                                    e,
                                )
                            })?;
                        header
                            .insert_header("content-type", "application/json")
                            .map_err(|e| {
                                Error::because(
                                    ErrorType::InternalError,
                                    "failed to set transcode 404 content-type",
                                    e,
                                )
                            })?;
                        session
                            .write_response_header(Box::new(header), false)
                            .await?;
                        session.write_response_body(Some(body), true).await?;
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }

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
            let mut response_headers = response_headers_for_static_action(&ct, &s.headers);
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
                            insert_json_header(&mut response_headers, key, value);
                        }
                        for (key, value) in &hm.add {
                            extra_headers.push((key.clone(), value.clone()));
                            insert_json_header(&mut response_headers, key, value);
                        }
                    }
                    // Lua response modifier
                    if let Some(script) = &modifier.lua_script {
                        let lua_status = status_override.unwrap_or(s.status);
                        match lua_response_modifier(script, lua_status, &response_headers, ctx) {
                            Ok(headers) => {
                                for (key, value) in headers {
                                    insert_json_header(&mut response_headers, &key, &value);
                                    extra_headers.push((key, value));
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "Lua response modifier on static action failed");
                            }
                        }
                    }
                    // JavaScript response modifier
                    if let Some(script) = &modifier.js_script {
                        let js_status = status_override.unwrap_or(s.status);
                        match js_response_modifier(script, js_status, &response_headers, ctx) {
                            Ok(headers) => {
                                for (key, value) in headers {
                                    insert_json_header(&mut response_headers, &key, &value);
                                    extra_headers.push((key, value));
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "JavaScript response modifier on static action failed");
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
            // WOR-803: Cloudflare Pay Per Crawl. Stamp `crawler-charged`
            // on the 2xx static response when the request settled
            // through the ledger in Cloudflare-compat mode, mirroring
            // the upstream-proxied path in `proxy_http::response_filter`.
            if (200..300).contains(&effective_status) {
                if let Some(charged) = ctx.crawl_charged.as_deref() {
                    let _ = header.insert_header("crawler-charged", charged);
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
/// * `tools/list` aggregates the federated upstream tool catalogue,
///   filtered by the per-server RBAC policy against the inbound
///   principal (WOR-1065).
/// * `tools/call` enforces the inline `tool_allowlist` guardrail, the
///   per-server `ToolAccessPolicy` (default-deny per WOR-1066), and
///   per-tool sliding-window quotas, then forwards to the owning
///   upstream via `McpFederation::call_tool`.
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
        is_supported_protocol_version, negotiate_protocol_version, InitializeResult,
        JsonRpcRequest, JsonRpcResponse, ServerCapabilities, ServerInfo, INTERNAL_ERROR,
        INVALID_PARAMS, INVALID_REQUEST, LATEST_PROTOCOL_VERSION, METHOD_NOT_FOUND, PARSE_ERROR,
        SUPPORTED_PROTOCOL_VERSIONS,
    };

    let method = session.req_header().method.clone();
    let req_path = session.req_header().uri.path();

    // WOR-1638: make the federation servable before any branch reads
    // the registry. First request spawns the periodic refresh task
    // and runs the cold-start prime (single-flight); every request
    // after that is a no-op fast path serving the cached snapshot.
    // Inbound traffic never fans out to upstream catalogues inline.
    mcp.federation.ensure_ready(mcp.refresh_interval).await;

    // WOR-483: serve the federated tool catalogue as a typed
    // Cloudflare-Code-Mode TypeScript module at
    // `/.well-known/mcp/codemode.ts`. WOR-410 added the
    // `McpFederation::codemode_ts(callback_base_url)` library
    // function; this branch wraps it in a one-URL HTTP surface so
    // any TypeScript agent or sandbox can `import` the module
    // directly without a separate codegen step.
    if method == http::Method::GET && req_path == "/.well-known/mcp/codemode.ts" {
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
        // Strong ETag is the lowercase hex SHA-256 of the emitted
        // bytes wrapped in double quotes per RFC 9110 §8.8.3.
        // WOR-1640: module emission and hashing are cached by
        // (registry generation, callback base), so a warm hit does
        // neither; the ETag stays stable until the catalogue moves.
        let (module, etag_value) = mcp.federation.codemode_ts_cached(&callback_base);

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
        let body = module.as_bytes().to_vec();
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

    // WOR-806: RFC 9728 OAuth Protected Resource Metadata. Served only
    // when the gateway declares `oauth:`, so an agent can discover the
    // authorization server. Not configured -> not intercepted.
    if method == http::Method::GET
        && req_path == sbproxy_extension::mcp::discovery::OAUTH_PROTECTED_RESOURCE_PATH
    {
        if let Some(oauth) = mcp.oauth.as_ref() {
            let listener_is_tls = session
                .digest()
                .and_then(|d| d.ssl_digest.as_ref())
                .is_some();
            let scheme = if listener_is_tls { "https" } else { "http" };
            let resource = match session
                .req_header()
                .headers
                .get("host")
                .and_then(|v| v.to_str().ok())
            {
                Some(authority) => format!("{scheme}://{authority}/"),
                None => "/".to_string(),
            };
            let doc = sbproxy_extension::mcp::discovery::build_oauth_protected_resource(
                &resource,
                &oauth.authorization_servers,
                &oauth.scopes_supported,
            );
            let body = serde_json::to_vec(&doc).unwrap_or_default();
            let mut header = pingora_http::ResponseHeader::build(200, Some(2)).map_err(|e| {
                Error::because(
                    ErrorType::InternalError,
                    "failed to build oauth metadata header",
                    e,
                )
            })?;
            let _ = header.insert_header("content-type", "application/json; charset=utf-8");
            let _ = header.insert_header("content-length", body.len().to_string());
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session
                .write_response_body(Some(bytes::Bytes::from(body)), true)
                .await?;
            return Ok(());
        }
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
        // Advertise the gateway's tool catalogue, honouring the
        // collapsed `tool_allowlist` guardrail and the per-server
        // RBAC policy against the inbound principal (WOR-1065) so
        // the manifest never lists a tool the gateway would refuse
        // to call for this caller.
        let tools: Vec<sbproxy_extension::mcp::discovery::DiscoveryTool> = mcp
            .federation
            .list_tools()
            .into_iter()
            .filter(|t| mcp.is_tool_allowed(&t.name))
            .filter(|t| match mcp.policy_for_server(&t.server_name) {
                Some(policy) => matches!(
                    policy.check(&ctx.principal, &t.name),
                    sbproxy_extension::mcp::ToolAccessDecision::Allow,
                ),
                None => true,
            })
            .map(|t| sbproxy_extension::mcp::discovery::DiscoveryTool {
                name: t.name,
                description: t.description,
            })
            .collect();
        // RFC 9728 auth-discovery pointer when the gateway is
        // OAuth-protected (WOR-806).
        let authorization = mcp.oauth.as_ref().map(|_| {
            let resource_meta = format!(
                "{}/.well-known/oauth-protected-resource",
                endpoint.trim_end_matches('/')
            );
            serde_json::json!({ "type": "oauth2", "resourceMetadata": resource_meta })
        });
        let manifest = sbproxy_extension::mcp::discovery::build_server_manifest(
            &mcp.server_name,
            &mcp.server_version,
            LATEST_PROTOCOL_VERSION,
            &endpoint,
            &tools,
            authorization,
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

    // WOR-1642: a GET with `Accept: text/event-stream` opens the
    // streamable HTTP server-to-client channel. The gateway pushes
    // `notifications/tools/list_changed` and
    // `notifications/resources/list_changed` when the corresponding
    // registry generation moves, which is what the `listChanged`
    // capabilities advertised in `initialize` promise.
    if method == http::Method::GET {
        let accepts_sse = session
            .req_header()
            .headers
            .get("accept")
            .and_then(|v| v.to_str().ok())
            .map(|a| a.contains("text/event-stream"))
            .unwrap_or(false);
        if accepts_sse {
            return handle_mcp_server_stream(session, mcp, ctx).await;
        }
    }

    // WOR-1642: DELETE ends a session when session management is on.
    if method == http::Method::DELETE {
        return handle_mcp_session_delete(session, mcp, ctx).await;
    }

    if method != http::Method::POST {
        send_error(session, 405, "MCP gateway accepts POST only").await?;
        return Ok(());
    }

    // WOR-1643: an OAuth-protected gateway must point credential-less
    // callers at its protected-resource metadata; the MCP auth
    // discovery flow starts from exactly this challenge (RFC 9728).
    // Token validation stays in the generic auth layer; this covers
    // only the no-Authorization-header case, so a request that passed
    // header-based auth is never re-challenged. The well-known
    // discovery routes above stay unauthenticated.
    if mcp.oauth.is_some()
        && session
            .req_header()
            .headers
            .get("authorization")
            .is_none()
    {
        let listener_is_tls = session
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .is_some();
        let scheme = if listener_is_tls { "https" } else { "http" };
        let metadata_url = match session
            .req_header()
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
        {
            Some(authority) => format!(
                "{scheme}://{authority}{}",
                sbproxy_extension::mcp::discovery::OAUTH_PROTECTED_RESOURCE_PATH
            ),
            None => sbproxy_extension::mcp::discovery::OAUTH_PROTECTED_RESOURCE_PATH.to_string(),
        };
        let mut header = pingora_http::ResponseHeader::build(401, Some(2)).map_err(|e| {
            Error::because(ErrorType::InternalError, "failed to build 401 header", e)
        })?;
        let _ = header.insert_header(
            "www-authenticate",
            format!("Bearer resource_metadata=\"{metadata_url}\""),
        );
        let _ = header.insert_header("content-length", "0");
        session
            .write_response_header(Box::new(header), true)
            .await?;
        tracing::info!(
            target: "sbproxy::audit",
            event = "mcp.oauth.challenge",
            mcp_server = %mcp.server_name,
            request_id = %ctx.request_id,
            resource_metadata = %metadata_url,
            "challenged credential-less MCP request with RFC 9728 pointer"
        );
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
            // WOR-1641: a JSON-RPC batch (top-level array) is valid
            // JSON, so answer it with a specific message instead of
            // a bare parse error. The 2025-06-18 revision removed
            // batching and this gateway does not accept it.
            let first_byte = body_bytes.iter().find(|b| !b.is_ascii_whitespace());
            let (code, message) = if first_byte == Some(&b'[') {
                (
                    INVALID_REQUEST,
                    "JSON-RPC batching is not supported (removed in MCP 2025-06-18); send one request per POST",
                )
            } else {
                (PARSE_ERROR, "invalid JSON-RPC body")
            };
            let err = JsonRpcResponse::error(None, code, message);
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

    // WOR-1641: post-initialize requests SHOULD carry
    // `MCP-Protocol-Version`; when present it must name a revision
    // the gateway serves, else 400 per the spec's version-validation
    // rule. A missing header is accepted (the request is served at
    // the gateway's newest revision). `initialize` is exempt: that
    // is where negotiation happens.
    if request.method != "initialize" {
        if let Some(header_version) = session
            .req_header()
            .headers
            .get("mcp-protocol-version")
            .and_then(|v| v.to_str().ok())
        {
            if !is_supported_protocol_version(header_version) {
                send_error(
                    session,
                    400,
                    &format!(
                        "unsupported MCP-Protocol-Version '{header_version}' (supported: {})",
                        SUPPORTED_PROTOCOL_VERSIONS.join(", ")
                    ),
                )
                .await?;
                return Ok(());
            }
        }
    }

    // WOR-1642: with session management enabled, every
    // post-initialize request (notifications included) must carry
    // the Mcp-Session-Id the gateway issued. Missing means 400;
    // unknown or expired means 404, the client's cue to
    // re-initialize.
    let mut mcp_session_id: Option<String> = None;
    if let Some(store) = mcp.sessions.as_deref() {
        if request.method != "initialize" {
            match session
                .req_header()
                .headers
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
            {
                None => {
                    send_error(
                        session,
                        400,
                        "missing Mcp-Session-Id header (session management is enabled)",
                    )
                    .await?;
                    return Ok(());
                }
                Some(id) if !store.validate(id) => {
                    send_error(session, 404, "unknown or expired MCP session; re-initialize")
                        .await?;
                    return Ok(());
                }
                Some(id) => mcp_session_id = Some(id.to_string()),
            }
        }
    }

    // Notifications (id absent) get an empty 202 Accepted per the
    // streamable HTTP transport (WOR-1642; previously 204).
    if request.id.is_none() {
        let header = pingora_http::ResponseHeader::build(202, Some(0))
            .map_err(|e| Error::because(ErrorType::InternalError, "failed to build mcp 202", e))?;
        session
            .write_response_header(Box::new(header), true)
            .await?;
        return Ok(());
    }

    // WOR-1640: take the method out so match arms can move
    // `request.params` instead of cloning the full inbound JSON.
    let mut request = request;
    let rpc_method = std::mem::take(&mut request.method);
    // WOR-1642: set when this request is an `initialize` on a
    // session-managed gateway; the response then carries the issued
    // `Mcp-Session-Id` header.
    let mut issued_session: Option<String> = None;
    let response = match rpc_method.as_str() {
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
            // WOR-818/WOR-1638: the resource registry (and the
            // mirrored mcpApps capability) is primed by ensure_ready
            // above and kept fresh by the background task; initialize
            // reads the snapshot.
            let mcp_apps = mcp.federation.mcp_apps_capability();
            // Resources capability: present whenever this origin
            // surfaces resources to MCP clients, either via the
            // agent-skills well-known projection or via a federated
            // upstream that advertised resources. `listChanged: true`
            // tells clients with a persistent server-push transport
            // (the streamable HTTP transport's GET-SSE channel) to
            // subscribe and refresh when the resource set changes.
            // Clients without a persistent channel fall back to
            // polling the manifest URL with `If-Modified-Since` (the
            // spec's documented fallback). The server-side push
            // channel itself is not yet implemented; advertising the
            // capability lets clients on a future-shipping transport
            // subscribe without re-handshaking.
            let surfaces_resources =
                has_agent_skills || !mcp.federation.list_resources().is_empty();
            let resources = surfaces_resources.then(|| serde_json::json!({ "listChanged": true }));
            // WOR-1642: issue a session when session management is
            // enabled. The id rides back on the Mcp-Session-Id
            // response header, per the streamable HTTP transport.
            if let Some(store) = mcp.sessions.as_deref() {
                issued_session = Some(store.create());
            }
            // WOR-1641: spec-correct negotiation. Echo the client's
            // requested revision when supported; otherwise answer
            // with the newest revision the gateway serves and let
            // the client decide.
            let requested_version = request
                .params
                .as_ref()
                .and_then(|p| p.get("protocolVersion"))
                .and_then(|v| v.as_str());
            let result = InitializeResult {
                protocol_version: negotiate_protocol_version(requested_version).to_string(),
                capabilities: ServerCapabilities {
                    // WOR-1642: `listChanged: true` is truthful now
                    // that the GET server-to-client stream delivers
                    // the notifications.
                    tools: Some(serde_json::json!({ "listChanged": true })),
                    resources,
                    prompts: None,
                    experimental,
                    // WOR-818: mirror SEP-1865 capability from
                    // upstreams. Apps-SDK clients use this to know
                    // they should look for UI templates on tools and
                    // fetch them via resources/read.
                    mcp_apps,
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
            // WOR-1638: serves the ArcSwap snapshot primed by
            // ensure_ready and refreshed by the background task.
            // Upstream fan-outs are bounded by the refresh interval,
            // not by inbound request volume.
            // WOR-806: progressive discovery advertises two meta-tools
            // (`search` / `execute`) instead of the full catalogue, so
            // a large federated tool set stays out of the model's
            // context window.
            if mcp.progressive_discovery {
                JsonRpcResponse::success(
                    request.id.clone(),
                    serde_json::json!({ "tools": mcp_progressive_meta_tools() }),
                )
            } else {
                // WOR-1640: the catalogue is pre-serialized once per
                // registry generation. With no allowlist and no
                // principal-scoped RBAC the cached array is spliced
                // into the envelope untouched (zero clones, zero
                // re-serialization); otherwise the response is a
                // string concat of the pre-serialized entries that
                // pass the filters.
                // WOR-1065: the RBAC filter still runs per principal
                // so the catalogue never lists a tool the gate would
                // refuse to call for this caller.
                let snapshot = mcp.federation.serialized_tools();
                // WOR-1635: tools blocked by the version gate are
                // filtered out of the catalogue entirely.
                let version_blocked = mcp.federation.version_blocked();
                let needs_filter = mcp.tool_allowlist.is_some()
                    || mcp.has_principal_scoped_tools
                    || !version_blocked.is_empty();
                let tools_json: std::borrow::Cow<'_, str> = if !needs_filter {
                    std::borrow::Cow::Borrowed(snapshot.full_array.as_str())
                } else {
                    let mut out = String::with_capacity(snapshot.full_array.len());
                    out.push('[');
                    let mut first = true;
                    for entry in &snapshot.entries {
                        if version_blocked.contains_key(&entry.name) {
                            continue;
                        }
                        if !mcp.is_tool_allowed(&entry.name) {
                            continue;
                        }
                        if let Some(policy) = mcp.policy_for_server(&entry.server_name) {
                            if !matches!(
                                policy.check(&ctx.principal, &entry.name),
                                sbproxy_extension::mcp::ToolAccessDecision::Allow,
                            ) {
                                continue;
                            }
                        }
                        if !first {
                            out.push(',');
                        }
                        first = false;
                        out.push_str(&entry.json);
                    }
                    out.push(']');
                    std::borrow::Cow::Owned(out)
                };
                let id_json = serde_json::to_string(&request.id)
                    .unwrap_or_else(|_| "null".to_string());
                let body = format!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":{id_json},\"result\":{{\"tools\":{tools_json}}}}}"
                );
                return send_response(session, 200, "application/json", body.as_bytes()).await;
            }
        }
        "resources/list" => {
            // WOR-818/WOR-1638: pass-through the federated resource
            // list from the primed snapshot (same pattern as
            // `tools/list`).
            let resources: Vec<serde_json::Value> = mcp
                .federation
                .list_resources()
                .into_iter()
                .map(|r| {
                    let mut entry = serde_json::json!({
                        "uri": r.uri,
                        "name": r.name,
                    });
                    if let Some(d) = r.description {
                        entry["description"] = serde_json::Value::String(d);
                    }
                    if let Some(m) = r.mime_type {
                        entry["mimeType"] = serde_json::Value::String(m);
                    }
                    entry
                })
                .collect();
            JsonRpcResponse::success(
                request.id.clone(),
                serde_json::json!({ "resources": resources }),
            )
        }
        "resources/read" => {
            // WOR-818: forward to the upstream that owns the URI.
            // Pass-through only -- the gateway does not enforce
            // CSP / iframe-sandbox / cache-metadata at this layer;
            // those validators ship in the enterprise tier.
            let params = request.params.take().unwrap_or(serde_json::Value::Null);
            let uri = params.get("uri").and_then(|v| v.as_str()).unwrap_or("");
            if uri.is_empty() {
                JsonRpcResponse::error(
                    request.id.clone(),
                    INVALID_PARAMS,
                    "resources/read requires `uri` param",
                )
            } else {
                match mcp.federation.read_resource(uri).await {
                    Ok(value) => JsonRpcResponse::success(request.id.clone(), value),
                    Err(e) => {
                        warn!(error = %e, uri = %uri, "resources/read failed");
                        JsonRpcResponse::error(
                            request.id.clone(),
                            INTERNAL_ERROR,
                            &format!("resources/read failed: {e}"),
                        )
                    }
                }
            }
        }
        "tools/call" => {
            let params = request.params.take().unwrap_or(serde_json::Value::Null);
            // WOR-818 PR2: extract the OpenAI Apps SDK
            // `params.audit.cause` so it reaches the policy hook
            // and the audit chain. Absent on base-MCP calls.
            let audit_cause = params
                .get("audit")
                .and_then(|a| a.get("cause"))
                .and_then(|c| c.as_str())
                .map(str::to_string);
            if let Some(cause) = audit_cause.as_deref() {
                tracing::debug!(
                    target: "sbproxy::mcp::audit_cause",
                    cause = %cause,
                    "mcp tools/call carries audit.cause (SEP-1865)"
                );
            }
            let mut tool_name = params
                .get("name")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let mut arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            // WOR-806: progressive discovery meta-tools. `search`
            // returns matching catalogue entries (yielding this arm's
            // value directly); `execute` unwraps to the real tool name +
            // arguments and then runs the normal allowlist / RBAC /
            // timeout / dispatch path below.
            if mcp.progressive_discovery && tool_name.as_deref() == Some("search") {
                let query = arguments
                    .get("query")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let limit = arguments
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(10) as usize;
                let matches = mcp_progressive_search(mcp, ctx, query, limit);
                let text = serde_json::to_string(&matches).unwrap_or_else(|_| "[]".into());
                JsonRpcResponse::success(
                    request.id.clone(),
                    serde_json::json!({
                        "content": [{"type": "text", "text": text}],
                        "isError": false,
                    }),
                )
            } else {
                if mcp.progressive_discovery && tool_name.as_deref() == Some("execute") {
                    let inner_name = arguments
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                    let inner_args = arguments
                        .get("arguments")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);
                    tool_name = inner_name;
                    arguments = inner_args;
                }

                match tool_name {
                    None => JsonRpcResponse::error(
                        request.id.clone(),
                        INVALID_PARAMS,
                        "tools/call requires a 'name' parameter",
                    ),
                    Some(name) => {
                        // WOR-1635: version-gate check first; a
                        // blocked tool is invisible in tools/list and
                        // must fail calls with the violation detail.
                        if let Some(detail) = mcp.federation.version_blocked().get(&name) {
                            JsonRpcResponse::error(
                                request.id.clone(),
                                INVALID_PARAMS,
                                &format!("tool '{}' is blocked by the version gate: {}", name, detail),
                            )
                        } else if !mcp.is_tool_allowed(&name) {
                            JsonRpcResponse::error(
                                request.id.clone(),
                                INVALID_PARAMS,
                                &format!("tool '{}' is blocked by tool_allowlist guardrail", name),
                            )
                        } else {
                            // WOR-186 + WOR-1065 + WOR-1066: per-server
                            // RBAC + per-tool quota + timeout enforcement.
                            //
                            // 1. Resolve the tool's owning upstream and
                            //    check the per-server `ToolAccessPolicy`
                            //    against `ctx.principal`. The policy is
                            //    default-deny per WOR-1066; a request
                            //    that matches no rule is rejected. A
                            //    denied tool returns a JSON-RPC error
                            //    and bumps an audit counter; the
                            //    upstream is never contacted.
                            // 2. Check the per-tool sliding-window
                            //    quota on the same policy. Quotas are
                            //    keyed on
                            //    `(tenant_id, principal_id, tool_name)`,
                            //    so tenant A's traffic cannot starve
                            //    tenant B's of the same tool. On
                            //    exceed, return JSON-RPC error code
                            //    `-32099` with a human-readable
                            //    message.
                            // 3. Wrap `federation.call_tool` in
                            //    `tokio::time::timeout(server.timeout, ...)`
                            //    when a per-server timeout is configured.
                            let federated = mcp.federation.resolve_tool(&name);
                            let server_policy = federated
                                .as_ref()
                                .and_then(|t| mcp.policy_for_server(&t.server_name));
                            let denied_by_rbac = match server_policy {
                                Some(policy) => matches!(
                                    policy.check(&ctx.principal, &name),
                                    sbproxy_extension::mcp::ToolAccessDecision::Deny,
                                ),
                                None => false,
                            };
                            let quota_error = if denied_by_rbac {
                                None
                            } else if let Some(policy) = server_policy {
                                mcp.quota_store
                                    .check_quota(policy, &ctx.principal, &name)
                                    .err()
                            } else {
                                None
                            };
                            if denied_by_rbac {
                                tracing::warn!(
                                    target: "sbproxy::mcp::rbac",
                                    tool = %name,
                                    tenant = %ctx.principal.tenant_id,
                                    principal = %ctx.principal.sub,
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
                            } else if let Some(err) = quota_error {
                                tracing::warn!(
                                    target: "sbproxy::mcp::quota",
                                    tool = %name,
                                    tenant = %ctx.principal.tenant_id,
                                    principal = %ctx.principal.sub,
                                    "MCP tools/call denied by per-tool quota",
                                );
                                sbproxy_observe::metrics::record_policy(
                                    ctx.hostname.as_str(),
                                    "mcp_quota",
                                    "deny",
                                );
                                // JSON-RPC application-defined error code
                                // `-32099`: per the JSON-RPC 2.0 spec, the
                                // range `-32000..=-32099` is reserved for
                                // implementation-defined server errors.
                                // We pick the top of the range for the
                                // quota lane so future per-tool gates
                                // (cost, concurrency) can sit beside it.
                                JsonRpcResponse::error(
                                    request.id.clone(),
                                    -32099,
                                    &format!("tool quota exceeded for {}", err.tool_name),
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

                                // WOR-1186: capture the ledger inputs
                                // before `arguments` is moved into the
                                // call. Gated on `is_enabled()` so a
                                // deployment without the ledger pays no
                                // clone and no timestamp.
                                let ledger_capture =
                                    if sbproxy_observe::session_ledger::is_enabled() {
                                        Some(LedgerCapture {
                                            params: arguments.clone(),
                                            server: federated
                                                .as_ref()
                                                .map(|t| t.server_name.clone())
                                                .unwrap_or_else(|| "unknown".to_string()),
                                            started_at: chrono::Utc::now().to_rfc3339(),
                                            started: std::time::Instant::now(),
                                        })
                                    } else {
                                        None
                                    };

                                // WOR-508: capture the inputs for the
                                // prompt-linked audit envelope before
                                // `arguments` is moved into the call. Gated
                                // on a subscriber being interested in the
                                // `mcp_audit` target (the enterprise audit
                                // layer), so an OSS-only deployment pays no
                                // clone.
                                let mcp_audit_capture = if tracing::enabled!(
                                    target: "mcp_audit",
                                    tracing::Level::INFO
                                ) {
                                    Some(McpAuditCapture {
                                        args_json: serde_json::to_string(&arguments)
                                            .unwrap_or_default(),
                                        prompt: audit_cause.clone().unwrap_or_default(),
                                        server: federated
                                            .as_ref()
                                            .map(|t| t.server_name.clone())
                                            .unwrap_or_else(|| "unknown".to_string()),
                                        started: std::time::Instant::now(),
                                    })
                                } else {
                                    None
                                };

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

                                // WOR-1186: emit the per-call ledger
                                // record (success or failure) before the
                                // outcome is consumed by the response.
                                if let Some(cap) = ledger_capture {
                                    emit_tool_call_ledger(
                                        ctx,
                                        &name,
                                        cap,
                                        &outcome,
                                        mcp_session_id.as_deref(),
                                    );
                                }

                                // WOR-508: bridge the prompt-linked audit
                                // inputs to the enterprise audit layer over
                                // the `mcp_audit` tracing target.
                                if let Some(cap) = mcp_audit_capture {
                                    emit_mcp_prompt_audit(ctx, &name, cap, &outcome);
                                }

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
        }
        other => JsonRpcResponse::error(
            request.id.clone(),
            METHOD_NOT_FOUND,
            &format!("unknown method: {}", other),
        ),
    };

    match issued_session.as_deref() {
        Some(session_id) => write_jsonrpc_with_session(session, &response, session_id).await,
        None => write_jsonrpc(session, &response).await,
    }
}

/// WOR-1186: ledger inputs captured before the federated call consumes
/// `arguments`, so the per-call record can be assembled after the await.
struct LedgerCapture {
    params: serde_json::Value,
    server: String,
    started_at: String,
    started: std::time::Instant,
}

/// WOR-1186: assemble and emit one session-ledger tool-call record from
/// the captured inputs and the call outcome. Identity (session, agent)
/// comes off `ctx`; payload redaction happens inside `emit_tool_call`.
/// WOR-508: inputs captured before `arguments` is moved into the tool
/// call, used by the enterprise audit layer to build the prompt-linked
/// audit envelope. Only populated when a subscriber is listening on
/// the `mcp_audit` tracing target, so an OSS-only deployment pays no
/// clone.
struct McpAuditCapture {
    /// Canonical JSON of the tool arguments (the enterprise side
    /// digests this; the raw value never leaves the process).
    args_json: String,
    /// The originating prompt / reason for the call, from the SEP-1865
    /// `params.audit.cause` field. Empty on base-MCP calls.
    prompt: String,
    /// Upstream MCP server name.
    server: String,
    /// Call start, for the end-to-end duration.
    started: std::time::Instant,
}

/// WOR-508: emit a structured event on the `mcp_audit` tracing target
/// carrying the inputs the enterprise audit layer needs to build an
/// `McpPromptLinkedAudit` envelope (the prompt that caused the call,
/// linked to the call). The OSS proxy cannot depend on the enterprise
/// audit crate, so the bridge is a tracing event; with no subscriber
/// the event is dropped at near-zero cost. The enterprise layer
/// digests the arguments and PII-redacts the prompt excerpt before it
/// reaches the hash-chained audit log.
fn emit_mcp_prompt_audit(
    ctx: &RequestContext,
    tool_name: &str,
    cap: McpAuditCapture,
    outcome: &anyhow::Result<serde_json::Value>,
) {
    // No clean upstream response on an error / timeout; report 0 per
    // the envelope's `upstream_status` contract, 200 on a served call.
    let upstream_status: u16 = if outcome.is_ok() { 200 } else { 0 };
    // The detected agent id is only present when the agent-class
    // feature is compiled in; fall back to an empty string otherwise.
    #[cfg(feature = "agent-class")]
    let agent_id = ctx
        .agent_id
        .as_ref()
        .map(|a| a.to_string())
        .unwrap_or_default();
    #[cfg(not(feature = "agent-class"))]
    let agent_id = String::new();
    tracing::info!(
        target: "mcp_audit",
        workspace_id = %ctx.tenant_id,
        request_id = %ctx.request_id,
        agent_id = %agent_id,
        human_sponsor = %ctx.principal.sub,
        mcp_server = %cap.server,
        tool_name = %tool_name,
        tool_arguments = %cap.args_json,
        prompt = %cap.prompt,
        upstream_status = upstream_status,
        duration_ms = cap.started.elapsed().as_millis() as u64,
        "mcp prompt-linked tool-call audit",
    );
}

fn emit_tool_call_ledger(
    ctx: &RequestContext,
    tool_name: &str,
    cap: LedgerCapture,
    outcome: &anyhow::Result<serde_json::Value>,
    mcp_session_id: Option<&str>,
) {
    use sbproxy_observe::session_ledger::{emit_tool_call, Caller, ToolCallObservation};

    // Session id preference (WOR-1642): the protocol-level MCP
    // session when the gateway issued one, else the generic
    // header-sourced session, else the request id so a sessionless
    // call still forms a coherent one-call session.
    let session_id = mcp_session_id
        .map(str::to_string)
        .or_else(|| ctx.session_id.map(|s| s.to_string()))
        .unwrap_or_else(|| ctx.request_id.to_string());

    // Agent id from the resolved principal; an empty subject is `None`.
    let agent_id = {
        let sub = ctx.principal.sub.clone();
        (!sub.is_empty()).then_some(sub)
    };

    // Bare tool name: strip the `<server>__` federation prefix if present.
    let bare = tool_name
        .strip_prefix(&format!("{}__", cap.server))
        .unwrap_or(tool_name)
        .to_string();

    let (result, is_error) = match outcome {
        Ok(value) => {
            let is_error = value
                .get("isError")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            (Some(value.clone()), is_error)
        }
        Err(_) => (None, true),
    };

    emit_tool_call(ToolCallObservation {
        session_id,
        agent_id,
        tool_name: bare,
        server: cap.server,
        params: cap.params,
        result,
        is_error,
        started_at: cap.started_at,
        duration_ms: cap.started.elapsed().as_millis() as u64,
        caller: Caller::Direct,
    });
}

/// The two meta-tool definitions advertised by `tools/list` when
/// progressive discovery is on (WOR-806).
fn mcp_progressive_meta_tools() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "name": "search",
            "description": "Search the gateway's tool catalogue by keyword. Returns matching tool names and descriptions. Call this first to find the tool you need, then call `execute`.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Keywords to match against tool names and descriptions."},
                    "limit": {"type": "integer", "description": "Maximum results to return (default 10)."}
                },
                "required": ["query"]
            }
        }),
        serde_json::json!({
            "name": "execute",
            "description": "Invoke a catalogue tool by name. Use `search` first to discover the tool name and its arguments.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "The tool name to invoke."},
                    "arguments": {"type": "object", "description": "Arguments to pass to the tool."}
                },
                "required": ["name"]
            }
        }),
    ]
}

/// Search the federated tool catalogue for entries whose name or
/// description matches `query` (case-insensitive substring), honouring
/// the `tool_allowlist` guardrail, the per-server RBAC policy
/// (WOR-1065), and capping at `limit`. An empty query returns the
/// first `limit` allowed tools. WOR-806.
fn mcp_progressive_search(
    mcp: &sbproxy_modules::action::McpAction,
    ctx: &RequestContext,
    query: &str,
    limit: usize,
) -> Vec<serde_json::Value> {
    let q = query.to_ascii_lowercase();
    mcp.federation
        .list_tools()
        .into_iter()
        .filter(|t| mcp.is_tool_allowed(&t.name))
        .filter(|t| match mcp.policy_for_server(&t.server_name) {
            Some(policy) => matches!(
                policy.check(&ctx.principal, &t.name),
                sbproxy_extension::mcp::ToolAccessDecision::Allow,
            ),
            None => true,
        })
        .filter(|t| {
            q.is_empty()
                || t.name.to_ascii_lowercase().contains(&q)
                || t.description.to_ascii_lowercase().contains(&q)
        })
        .take(limit.max(1))
        .map(|t| {
            serde_json::json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
            })
        })
        .collect()
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

/// Serialise a JSON-RPC response and write it with the issued
/// `Mcp-Session-Id` header (WOR-1642; used by `initialize` on a
/// session-managed gateway).
async fn write_jsonrpc_with_session(
    session: &mut Session,
    response: &sbproxy_extension::mcp::types::JsonRpcResponse,
    session_id: &str,
) -> Result<()> {
    let body = serde_json::to_vec(response).map_err(|e| {
        Error::because(
            ErrorType::InternalError,
            "failed to serialise JSON-RPC response",
            e,
        )
    })?;
    let mut header = pingora_http::ResponseHeader::build(200, Some(3)).map_err(|e| {
        Error::because(ErrorType::InternalError, "failed to build mcp header", e)
    })?;
    let _ = header.insert_header("content-type", "application/json");
    let _ = header.insert_header("content-length", body.len().to_string());
    let _ = header.insert_header("mcp-session-id", session_id);
    session
        .write_response_header(Box::new(header), false)
        .await?;
    session
        .write_response_body(Some(bytes::Bytes::from(body)), true)
        .await?;
    Ok(())
}

/// WOR-1642: the streamable HTTP server-to-client channel. Opened by
/// a GET with `Accept: text/event-stream`; pushes
/// `notifications/tools/list_changed` and
/// `notifications/resources/list_changed` when the corresponding
/// federation registry generation moves, with periodic keep-alive
/// comments in between. Runs until the client disconnects.
async fn handle_mcp_server_stream(
    session: &mut Session,
    mcp: &sbproxy_modules::action::McpAction,
    ctx: &RequestContext,
) -> Result<()> {
    // Session gating mirrors the POST path.
    if let Some(store) = mcp.sessions.as_deref() {
        match session
            .req_header()
            .headers
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
        {
            None => {
                send_error(
                    session,
                    400,
                    "missing Mcp-Session-Id header (session management is enabled)",
                )
                .await?;
                return Ok(());
            }
            Some(id) if !store.validate(id) => {
                send_error(session, 404, "unknown or expired MCP session; re-initialize").await?;
                return Ok(());
            }
            Some(_) => {}
        }
    }

    let mut header = pingora_http::ResponseHeader::build(200, Some(3)).map_err(|e| {
        Error::because(ErrorType::InternalError, "failed to build sse header", e)
    })?;
    let _ = header.insert_header("content-type", "text/event-stream");
    let _ = header.insert_header("cache-control", "no-cache");
    session
        .write_response_header(Box::new(header), false)
        .await?;
    tracing::info!(
        target: "sbproxy::audit",
        event = "mcp.stream.opened",
        mcp_server = %mcp.server_name,
        request_id = %ctx.request_id,
        "opened MCP server-to-client stream"
    );

    let mut last_tools = mcp.federation.tools_generation();
    let mut last_resources = mcp.federation.resources_generation();
    let poll = std::time::Duration::from_millis(1000);
    // Keep-alive cadence: one comment frame per 15 idle polls, so
    // intermediaries do not reap the connection.
    let mut idle_polls: u32 = 0;
    loop {
        tokio::time::sleep(poll).await;
        let mut frames = String::new();
        let tools_now = mcp.federation.tools_generation();
        if tools_now != last_tools {
            last_tools = tools_now;
            frames.push_str(
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n",
            );
        }
        let resources_now = mcp.federation.resources_generation();
        if resources_now != last_resources {
            last_resources = resources_now;
            frames.push_str(
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/resources/list_changed\"}\n\n",
            );
        }
        if frames.is_empty() {
            idle_polls += 1;
            if idle_polls < 15 {
                continue;
            }
            frames.push_str(": keep-alive\n\n");
        }
        idle_polls = 0;
        if session
            .write_response_body(Some(bytes::Bytes::from(frames)), false)
            .await
            .is_err()
        {
            // Client went away; the stream is done.
            break;
        }
    }
    Ok(())
}

/// WOR-1642: DELETE ends an MCP session on a session-managed
/// gateway (405 otherwise, matching the POST-only contract).
async fn handle_mcp_session_delete(
    session: &mut Session,
    mcp: &sbproxy_modules::action::McpAction,
    ctx: &RequestContext,
) -> Result<()> {
    let Some(store) = mcp.sessions.as_deref() else {
        send_error(session, 405, "MCP session management is not enabled").await?;
        return Ok(());
    };
    match session
        .req_header()
        .headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
    {
        None => {
            send_error(session, 400, "missing Mcp-Session-Id header").await?;
            Ok(())
        }
        Some(id) if store.end(id) => {
            tracing::info!(
                target: "sbproxy::audit",
                event = "mcp.session.ended",
                mcp_server = %mcp.server_name,
                request_id = %ctx.request_id,
                "ended MCP session on client DELETE"
            );
            let header = pingora_http::ResponseHeader::build(204, Some(0)).map_err(|e| {
                Error::because(ErrorType::InternalError, "failed to build 204 header", e)
            })?;
            session
                .write_response_header(Box::new(header), true)
                .await?;
            Ok(())
        }
        Some(_) => {
            send_error(session, 404, "unknown or expired MCP session").await?;
            Ok(())
        }
    }
}
