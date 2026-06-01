//! The Pingora `ProxyHttp` trait implementation for `SbProxy`:
//! per-request context construction and the request/upstream/response/
//! body phase handlers.
//!
//! Extracted from `server.rs`. A trait impl may live in any
//! module of the crate; `use super::*` brings `SbProxy`, the trait, and
//! every helper into scope. Behavior-preserving move, no logic changes.

use super::*;

#[async_trait]
impl ProxyHttp for SbProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext::new()
    }

    /// Handle incoming request before proxying.
    ///
    /// This phase:
    /// 1. Handles the /health endpoint
    /// 2. Extracts hostname and resolves the origin
    /// 3. Handles CORS preflight requests (short-circuits before auth)
    /// 4. Runs auth checks
    /// 5. Runs policy enforcement
    /// 6. Handles non-proxy actions (redirect, static, echo, mock, beacon, noop)
    ///
    /// Returns `Ok(true)` if a response was already sent (short-circuit),
    /// `Ok(false)` to continue to upstream_peer (proxy action).
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        request_phase::request_filter(session, ctx).await
    }

    /// Resolve the upstream peer for proxy actions.
    ///
    /// Only called when request_filter returns Ok(false), which means the
    /// action is Proxy. All other action types are handled in request_filter.
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // tune_peer applies matched upstream transport settings to every peer
        // we return. Pingora 0.8 ships with very conservative defaults
        // (HTTP/1.1 only, max_h2_streams=1, no idle_timeout, no tcp_keepalive,
        // no connect/read/write deadlines). See sbproxy-bench/docs/TUNING.md
        // for the rationale. Numbers here are chosen to match the Go engine's
        // http.Transport settings so benchmark comparisons measure the engine,
        // not the defaults.
        fn tune_peer(mut peer: HttpPeer) -> HttpPeer {
            use std::time::Duration;
            peer.options.connection_timeout = Some(Duration::from_secs(5));
            peer.options.total_connection_timeout = Some(Duration::from_secs(10));
            peer.options.read_timeout = Some(Duration::from_secs(30));
            peer.options.write_timeout = Some(Duration::from_secs(30));
            peer.options.idle_timeout = Some(Duration::from_secs(90));
            peer.options.alpn = ALPN::H2H1;
            peer.options.max_h2_streams = 256;
            peer.options.tcp_keepalive = Some(TcpKeepalive {
                idle: Duration::from_secs(60),
                interval: Duration::from_secs(10),
                count: 3,
                #[cfg(target_os = "linux")]
                user_timeout: Duration::from_secs(0),
            });
            // Larger TCP recv buffer helps large-body upstream responses
            // (streaming AI, file proxies) avoid receive-window stalls.
            // 1 MB matches what Go's net.Dialer advertises with the bumped
            // tcp_rmem sysctl we set on the VMs.
            peer.options.tcp_recv_buf = Some(1024 * 1024);
            peer
        }

        let pipeline = reload::current_pipeline();
        let origin_idx = ctx.origin_idx.ok_or_else(|| {
            warn!("upstream_peer called without origin_idx");
            Error::new(ErrorType::HTTPStatus(500))
        })?;

        // If a forward rule matched, use its action instead of the origin's.
        let effective_action: &Action = if let Some(fwd_idx) = ctx.forward_rule_idx {
            &pipeline.forward_rules[origin_idx][fwd_idx].action
        } else {
            &pipeline.actions[origin_idx]
        };

        let allow_private = pipeline.upstream_allow_private_cidrs.as_slice();

        match effective_action {
            Action::Proxy(proxy) => {
                let (host, port, tls) = proxy.parse_upstream().map_err(|e| {
                    warn!(error = %e, "failed to parse upstream URL");
                    Error::because(ErrorType::ConnectError, "bad upstream URL", e)
                })?;

                // SSRF guard: reject upstreams that resolve to private,
                // loopback, link-local, or metadata addresses unless the
                // operator opted in via `upstream.allow_private_cidrs`.
                // Skipped when `resolve_override` is set: the operator
                // has explicitly pinned the connect address, so DNS
                // rebinding is not a factor; the override path is
                // checked against `allow_private_cidrs` separately.
                if proxy.resolve_override.is_none() {
                    guard_upstream(&host, port, tls, allow_private)?;
                }

                // Service discovery: resolve to a fresh IP per
                // refresh_secs, fall through to letting Pingora's
                // resolver handle it when SD is unconfigured or has
                // never produced an IP for this hostname.
                let sd_idle_timeout =
                    proxy
                        .service_discovery
                        .as_ref()
                        .filter(|s| s.enabled)
                        .map(|s| {
                            // Cap idle connections at half the refresh
                            // window (or 10s, whichever is smaller). When
                            // DNS rotates an IP, the connection pool
                            // entries pinned to the stale IP age out
                            // quickly instead of lingering for 90s. This
                            // is a workaround for the missing pool-eviction
                            // primitive in Pingora 0.8; it trades a small
                            // amount of pool churn for much fresher routing.
                            let half_refresh = std::cmp::max(s.refresh_secs / 2, 1);
                            std::time::Duration::from_secs(std::cmp::min(half_refresh, 10))
                        });
                // resolve_override pins the connect address, bypassing
                // DNS for the URL host. Equivalent to `curl --connect-to`.
                let addr = if let Some(over) = proxy.resolve_override.as_deref() {
                    resolve_addr_override(over, port)
                } else if let Some(sd) = proxy.service_discovery.as_ref().filter(|s| s.enabled) {
                    match pipeline
                        .dns_resolver
                        .pick_ip(&host, port, sd.refresh_secs, sd.ipv6)
                        .await
                    {
                        Some(ip) => match ip {
                            std::net::IpAddr::V4(v4) => format!("{v4}:{port}"),
                            std::net::IpAddr::V6(v6) => format!("[{v6}]:{port}"),
                        },
                        None => format!("{host}:{port}"),
                    }
                } else {
                    format!("{host}:{port}")
                };

                // sni_override changes the SNI server name (and the
                // cert verification target) without changing the URL
                // host or the rewritten Host header. Use this when
                // the upstream presents a cert for a different hostname
                // than the URL - the SaaS-fronting pattern.
                let sni = proxy
                    .sni_override
                    .as_deref()
                    .unwrap_or(host.as_str())
                    .to_string();

                debug!(
                    hostname = %ctx.hostname,
                    upstream_host = %host,
                    upstream_port = %port,
                    upstream_addr = %addr,
                    upstream_sni = %sni,
                    tls = %tls,
                    "routing request to upstream"
                );

                let mut peer = tune_peer(HttpPeer::new(&*addr, tls, sni));
                if let Some(t) = sd_idle_timeout {
                    peer.options.idle_timeout = Some(t);
                }
                Ok(Box::new(peer))
            }
            Action::LoadBalancer(lb) => {
                let client_ip_str = ctx.client_ip.map(|ip| ip.to_string());
                let uri = _session.req_header().uri.path();
                let headers = &_session.req_header().headers;

                let (host, port, tls, target_idx) = lb
                    .select_target(client_ip_str.as_deref(), uri, headers)
                    .map_err(|e| {
                        warn!(error = %e, "load balancer target selection failed");
                        Error::because(ErrorType::ConnectError, "lb target selection failed", e)
                    })?;

                guard_upstream(&host, port, tls, allow_private)?;

                lb.record_connect(target_idx);
                ctx.lb_target_idx = Some(target_idx);

                debug!(
                    hostname = %ctx.hostname,
                    upstream_host = %host,
                    upstream_port = %port,
                    tls = %tls,
                    target_idx = %target_idx,
                    "load balancer routing request to upstream"
                );

                let addr = format!("{host}:{port}");
                let peer = tune_peer(HttpPeer::new(&*addr, tls, host));
                Ok(Box::new(peer))
            }
            Action::A2a(a2a) => {
                let (host, port, tls) = a2a.parse_upstream().map_err(|e| {
                    warn!(error = %e, "failed to parse A2A upstream URL");
                    Error::because(ErrorType::ConnectError, "bad A2A upstream URL", e)
                })?;

                guard_upstream(&host, port, tls, allow_private)?;

                debug!(
                    hostname = %ctx.hostname,
                    upstream_host = %host,
                    upstream_port = %port,
                    tls = %tls,
                    "routing A2A request to upstream"
                );

                let addr = format!("{host}:{port}");
                let peer = tune_peer(HttpPeer::new(&*addr, tls, host));
                Ok(Box::new(peer))
            }
            Action::WebSocket(ws) => {
                let (host, port, tls) = ws.parse_upstream().map_err(|e| {
                    warn!(error = %e, "failed to parse websocket upstream URL");
                    Error::because(ErrorType::ConnectError, "bad websocket upstream URL", e)
                })?;

                guard_upstream(&host, port, tls, allow_private)?;

                debug!(
                    hostname = %ctx.hostname,
                    upstream_host = %host,
                    upstream_port = %port,
                    tls = %tls,
                    "routing websocket request to upstream"
                );

                let addr = format!("{host}:{port}");
                let peer = tune_peer(HttpPeer::new(&*addr, tls, host));
                Ok(Box::new(peer))
            }
            Action::AiProxy(_) => {
                // Phase 7: realtime WebSocket dispatch. `handle_action`
                // populated `ctx.ai_realtime_dispatch` for this path
                // after running the AI gateway gating; build the peer
                // from there and let Pingora forward bytes transparently
                // through the upgraded connection.
                let rd = ctx.ai_realtime_dispatch.as_ref().ok_or_else(|| {
                    warn!("AI proxy reached upstream_peer without a realtime dispatch context");
                    Error::new(ErrorType::InternalError)
                })?;
                guard_upstream(
                    &rd.upstream_host,
                    rd.upstream_port,
                    rd.upstream_tls,
                    allow_private,
                )?;
                debug!(
                    hostname = %ctx.hostname,
                    upstream_host = %rd.upstream_host,
                    upstream_port = %rd.upstream_port,
                    tls = %rd.upstream_tls,
                    provider = %rd.provider_name,
                    "routing AI realtime WebSocket upgrade to provider"
                );
                let addr = format!("{}:{}", rd.upstream_host, rd.upstream_port);
                let peer = tune_peer(HttpPeer::new(
                    &*addr,
                    rd.upstream_tls,
                    rd.upstream_host.clone(),
                ));
                Ok(Box::new(peer))
            }
            Action::Grpc(grpc) => {
                let (host, port, tls) = grpc.parse_upstream().map_err(|e| {
                    warn!(error = %e, "failed to parse gRPC upstream URL");
                    Error::because(ErrorType::ConnectError, "bad gRPC upstream URL", e)
                })?;

                guard_upstream(&host, port, tls, allow_private)?;

                debug!(
                    hostname = %ctx.hostname,
                    upstream_host = %host,
                    upstream_port = %port,
                    tls = %tls,
                    "routing gRPC request to upstream"
                );

                let addr = format!("{host}:{port}");
                let mut peer = tune_peer(HttpPeer::new(&*addr, tls, host));
                // gRPC mandates HTTP/2 end-to-end. Force ALPN::H2 so
                // Pingora negotiates h2 over TLS and, on plaintext
                // hops, opens an h2c connection by prior knowledge
                // (min HTTP version = 2). Without this the upstream
                // connector falls back to HTTP/1.1 and the gRPC
                // length-prefixed framing fails.
                peer.options.alpn = ALPN::H2;
                Ok(Box::new(peer))
            }
            Action::GraphQL(gql) => {
                let (host, port, tls) = gql.parse_upstream().map_err(|e| {
                    warn!(error = %e, "failed to parse GraphQL upstream URL");
                    Error::because(ErrorType::ConnectError, "bad GraphQL upstream URL", e)
                })?;

                guard_upstream(&host, port, tls, allow_private)?;

                debug!(
                    hostname = %ctx.hostname,
                    upstream_host = %host,
                    upstream_port = %port,
                    tls = %tls,
                    "routing GraphQL request to upstream"
                );

                let addr = format!("{host}:{port}");
                let peer = tune_peer(HttpPeer::new(&*addr, tls, host));
                Ok(Box::new(peer))
            }
            _ => {
                // Should never reach here - non-proxy actions are handled in request_filter.
                warn!(
                    hostname = %ctx.hostname,
                    "upstream_peer called for non-proxy action"
                );
                Err(Error::new(ErrorType::HTTPStatus(500)))
            }
        }
    }

    /// Modify the request before it is sent to the upstream.
    ///
    /// This phase applies request modifiers (header set/add/remove and Lua
    /// scripts) that were configured on the origin. It runs after auth and
    /// policies but before the request leaves the proxy.
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Collect header modifications into owned Vecs, then drop the pipeline
        // guard before calling Pingora's insert_header (requires 'static borrows).
        let mut req_to_set: Vec<(String, String)> = Vec::new();
        let mut req_to_remove: Vec<String> = Vec::new();
        let mut req_to_append: Vec<(String, String)> = Vec::new();
        let mut lua_scripts: Vec<String> = Vec::new();
        let mut advanced_modifiers: Vec<sbproxy_config::RequestModifierConfig> = Vec::new();
        let mut upstream_url_path: Option<String> = None;
        let mut upstream_host_header: Option<String> = None;
        let mut disable_forwarded_host: bool = false;
        let mut forwarding = ForwardingHeaderControls::default();
        // WOR-802: outbound credential resolver config for this origin,
        // cloned out of the pipeline so it can be used (and awaited on)
        // after the pipeline guard is dropped below.
        let mut outbound_cred: Option<
            sbproxy_modules::auth::outbound_credential::OutboundCredentialConfig,
        > = None;
        // WOR-805: outbound Web Bot Auth signer + Signature-Agent for
        // this origin, cloned (Arc) out of the pipeline so they outlive
        // the pipeline guard dropped below.
        let mut wba_signer: Option<
            std::sync::Arc<sbproxy_middleware::signatures_egress::MessageSigner>,
        > = None;
        let mut wba_signature_agent: Option<String> = None;
        // WOR-819: gRPC `:path` to rewrite the upstream request into when
        // the request matched a `transcode` route on a `grpc` action.
        // Applied after the pipeline guard drops, alongside the other
        // header rewrites.
        let mut transcode_grpc_path: Option<String> = None;
        // WOR-819: true when this is a gRPC-Web request on a `grpc_web`-
        // enabled action, so the upstream content-type is rewritten to
        // native gRPC after the guard drops (the `:path` is unchanged -
        // gRPC-Web already uses the native gRPC method path).
        let mut grpc_web_request = false;

        {
            let pipeline = reload::current_pipeline();
            if let Some(idx) = ctx.origin_idx {
                let origin = &pipeline.config.origins[idx];
                outbound_cred = pipeline.outbound_creds.get(idx).and_then(|o| o.clone());
                // WOR-805: capture the shared outbound signer when this
                // origin opts into Web Bot Auth signing.
                if pipeline.outbound_wba.get(idx).copied().unwrap_or(false) {
                    wba_signer = pipeline.web_bot_auth_signer.clone();
                    wba_signature_agent = pipeline.web_bot_auth_signature_agent.clone();
                }

                // Extract the URL path from the proxy action so we can prepend it
                // to the upstream request path. This ensures that configs like
                // `url: http://backend:8080/api` proxy to /api/... not just /...
                let effective_action: &Action = if let Some(fwd_idx) = ctx.forward_rule_idx {
                    &pipeline.forward_rules[idx][fwd_idx].action
                } else {
                    &pipeline.actions[idx]
                };

                // WOR-819: REST -> gRPC transcoding. When the resolved
                // grpc action carries a compiled transcoder and the
                // request matches a transcode route, capture the gRPC
                // `:path` + method now so the upstream header is rewritten
                // after the guard drops, and flag the body filters to
                // rewrite the request and response bodies. The request
                // body itself is read in `request_body_filter`, so only a
                // signal + the resolved gRPC method are carried on ctx.
                if let Action::Grpc(g) = effective_action {
                    let req_ct = upstream_request
                        .headers
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    // gRPC-Web takes precedence: a browser gRPC-Web request
                    // carries `application/grpc-web*` and uses the native
                    // gRPC method path, so it is bridged (not transcoded).
                    if g.grpc_web && sbproxy_transport::grpc::is_grpc_web(req_ct) {
                        ctx.grpc_web_active = true;
                        ctx.grpc_web_text = sbproxy_transport::grpc::is_text_encoded(req_ct);
                        grpc_web_request = true;
                    } else if let Some(transcoder) = g.transcoder.as_ref() {
                        if let Some(rm) = transcoder.match_route(
                            upstream_request.method.as_str(),
                            upstream_request.uri.path(),
                        ) {
                            transcode_grpc_path = Some(rm.grpc_path);
                            ctx.transcode_active = true;
                            ctx.transcode_grpc_method = Some(rm.grpc_method);
                        }
                    }
                }

                // Compute the upstream Host header. Default: hostname from the
                // upstream URL (proxy / lb target / websocket / grpc / a2a /
                // graphql). Override: explicit host_override field on the action
                // or target. This avoids the failure mode where vhost-based
                // upstreams (Vercel, Cloudflare, AWS ALB, K8s ingresses) reject
                // the request because the client's Host header was forwarded
                // verbatim.
                let mut fc = ForwardingHeaderControls::default();
                upstream_host_header = match effective_action {
                    Action::Proxy(p) => {
                        fc = p.forwarding.clone();
                        p.host_override.clone().or_else(|| {
                            url::Url::parse(&p.url)
                                .ok()
                                .and_then(|u| u.host_str().map(String::from))
                        })
                    }
                    Action::LoadBalancer(lb) => ctx
                        .lb_target_idx
                        .and_then(|i| lb.targets.get(i))
                        .and_then(|t| {
                            fc = t.forwarding.clone();
                            t.host_override.clone().or_else(|| {
                                url::Url::parse(&t.url)
                                    .ok()
                                    .and_then(|u| u.host_str().map(String::from))
                            })
                        }),
                    Action::WebSocket(ws) => {
                        fc = ws.forwarding.clone();
                        ws.host_override.clone().or_else(|| {
                            url::Url::parse(&ws.url)
                                .ok()
                                .and_then(|u| u.host_str().map(String::from))
                        })
                    }
                    Action::Grpc(g) => {
                        fc = g.forwarding.clone();
                        g.authority.clone().or_else(|| {
                            url::Url::parse(&g.url)
                                .ok()
                                .and_then(|u| u.host_str().map(String::from))
                        })
                    }
                    Action::A2a(a) => {
                        fc = a.forwarding.clone();
                        a.host_override.clone().or_else(|| {
                            url::Url::parse(&a.url)
                                .ok()
                                .and_then(|u| u.host_str().map(String::from))
                        })
                    }
                    Action::GraphQL(gq) => {
                        fc = gq.forwarding.clone();
                        gq.host_override.clone().or_else(|| {
                            url::Url::parse(&gq.url)
                                .ok()
                                .and_then(|u| u.host_str().map(String::from))
                        })
                    }
                    _ => None,
                };
                forwarding = fc;
                disable_forwarded_host = forwarding.disable_forwarded_host_header;

                if let Action::Proxy(proxy) = effective_action {
                    if let Ok(parsed) = url::Url::parse(&proxy.url) {
                        let p = parsed.path();
                        if p != "/" && !p.is_empty() {
                            upstream_url_path = Some(p.to_string());
                        }
                    }
                }

                if !origin.request_modifiers.is_empty() {
                    let tmpl = build_request_template_context(session, ctx, origin);
                    for modifier in &origin.request_modifiers {
                        if let Some(hm) = &modifier.headers {
                            for key in &hm.remove {
                                req_to_remove.push(key.clone());
                            }
                            for (key, value) in &hm.set {
                                req_to_set.push((key.clone(), tmpl.resolve(value)));
                            }
                            for (key, value) in &hm.add {
                                req_to_append.push((key.clone(), tmpl.resolve(value)));
                            }
                        }
                        if let Some(script) = &modifier.lua_script {
                            lua_scripts.push(script.clone());
                        }
                    }
                    // Clone modifiers for advanced processing (URL rewrite, query, method, body).
                    advanced_modifiers = origin.request_modifiers.to_vec();
                }

                // Collect forward-rule request modifiers (OUTSIDE the origin modifier block
                // because forward rules have their own modifiers even if the origin has none)
                if let Some(fwd_idx) = ctx.forward_rule_idx {
                    if let Some(fwd_rules) = pipeline.forward_rules.get(idx) {
                        if let Some(fwd_rule) = fwd_rules.get(fwd_idx) {
                            for modifier in &fwd_rule.request_modifiers {
                                if let Some(hm) = &modifier.headers {
                                    for key in &hm.remove {
                                        req_to_remove.push(key.clone());
                                    }
                                    for (key, value) in &hm.set {
                                        req_to_set.push((key.clone(), value.clone()));
                                    }
                                    for (key, value) in &hm.add {
                                        req_to_append.push((key.clone(), value.clone()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } // pipeline guard dropped here

        // WOR-819: rewrite the upstream request into a unary gRPC call.
        // gRPC mandates POST; the `:path` is the resolved gRPC method
        // path; the body becomes a length-prefixed gRPC frame in
        // `request_body_filter`, so we drop the inbound content-length
        // (the framed length differs and h2 delimits via END_STREAM) and
        // ask the upstream for trailers so `grpc-status` comes back.
        if let Some(grpc_path) = &transcode_grpc_path {
            upstream_request.set_method(http::Method::POST);
            if let Ok(uri) = grpc_path.parse::<http::Uri>() {
                upstream_request.set_uri(uri);
            }
            let _ = upstream_request.insert_header("content-type".to_string(), "application/grpc");
            let _ = upstream_request.insert_header("te".to_string(), "trailers");
            upstream_request.remove_header("content-length");
        }

        // WOR-819: gRPC-Web request -> native gRPC. The path and method
        // are already the native gRPC shape (POST /pkg.Service/Method);
        // only the content-type changes (and the body is de-framed in
        // request_body_filter). Drop content-length: the `-text` variant
        // base64-decodes to a different length, and h2 delimits via
        // END_STREAM anyway.
        if grpc_web_request {
            let _ = upstream_request.insert_header("content-type".to_string(), "application/grpc");
            let _ = upstream_request.insert_header("te".to_string(), "trailers");
            upstream_request.remove_header("content-length");
            // X-Grpc-Web is a CORS preflight marker the upstream gRPC
            // server does not expect.
            upstream_request.remove_header("x-grpc-web");
        }

        // Prepend the proxy action's URL path to the upstream request path.
        // E.g., if action url is http://backend:8080/fail and client sends /,
        // the upstream request should go to /fail (not /).
        if let Some(base_path) = &upstream_url_path {
            let client_path = upstream_request.uri.path().to_string();
            let new_path = if client_path == "/" {
                base_path.clone()
            } else {
                let trimmed = base_path.trim_end_matches('/');
                format!("{}{}", trimmed, client_path)
            };
            let new_uri = if let Some(query) = upstream_request.uri.query() {
                format!("{}?{}", new_path, query)
            } else {
                new_path
            };
            if let Ok(uri) = new_uri.parse::<http::Uri>() {
                upstream_request.set_uri(uri);
            }
        }

        // Apply advanced request modifiers (URL rewrite, query injection, method
        // override, body replacement).
        if !advanced_modifiers.is_empty() {
            apply_advanced_request_modifiers(&advanced_modifiers, upstream_request, ctx);
            // Update Content-Length if body was replaced
            if let Some(ref body) = ctx.replacement_request_body {
                let _ = upstream_request
                    .insert_header("content-length".to_string(), body.len().to_string());
            }
        }

        // Set the upstream Host header. Default: hostname from the upstream
        // URL (so vhost-based upstreams resolve correctly). The action's
        // host_override field (or per-target host_override on a load balancer)
        // overrides this. Applied before request_modifier headers so a user
        // can still set Host explicitly through a modifier if they need to.
        //
        // Whenever we rewrite the upstream Host, preserve the client's
        // original Host as `X-Forwarded-Host` so the upstream can still
        // observe the public name. Skip if the action sets
        // `disable_forwarded_host_header: true`, or if the upstream Host we
        // are about to set is identical to what the client sent (no rewrite
        // happening, no need for the breadcrumb).
        let client_host: Option<String> = upstream_request
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .map(String::from);
        if let Some(host) = &upstream_host_header {
            let _ = upstream_request.insert_header("host".to_string(), host);
            if !disable_forwarded_host {
                if let Some(orig) = &client_host {
                    if orig.as_str() != host.as_str() {
                        let _ = upstream_request
                            .insert_header("x-forwarded-host".to_string(), orig.as_str());
                    }
                }
            }
        }

        // Propagate the standard forwarding headers so the upstream knows
        // the real client + the public-facing scheme/port. Each header is
        // governed by an opt-out flag on the action so callers can suppress
        // any of them per route.
        let client_ip_str = ctx.client_ip.map(|ip| ip.to_string());
        let is_tls = session
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .is_some();
        let proto = if is_tls { "https" } else { "http" };
        let listener_port: Option<u16> = session
            .server_addr()
            .and_then(|a| a.as_inet())
            .map(|a| a.port());

        if !forwarding.disable_forwarded_for_header {
            if let Some(ip) = &client_ip_str {
                // RFC: append to existing X-Forwarded-For so chained
                // proxies preserve the full client trail.
                let new_xff = match upstream_request
                    .headers
                    .get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                {
                    Some(existing) if !existing.is_empty() => format!("{existing}, {ip}"),
                    _ => ip.clone(),
                };
                let _ = upstream_request.insert_header("x-forwarded-for".to_string(), &new_xff);
            }
        }

        if !forwarding.disable_real_ip_header {
            if let Some(ip) = &client_ip_str {
                let _ = upstream_request.insert_header("x-real-ip".to_string(), ip.as_str());
            }
        }

        if !forwarding.disable_forwarded_proto_header {
            let _ = upstream_request.insert_header("x-forwarded-proto".to_string(), proto);
        }

        if !forwarding.disable_forwarded_port_header {
            if let Some(port) = listener_port {
                let _ = upstream_request
                    .insert_header("x-forwarded-port".to_string(), port.to_string().as_str());
            }
        }

        if !forwarding.disable_forwarded_header {
            // RFC 7239 Forwarded: for=<client>; proto=<scheme>; host=<orig>; by=<proxy>
            // Append to existing Forwarded so chained proxies preserve the trail.
            let mut parts: Vec<String> = Vec::with_capacity(4);
            if let Some(ip) = &client_ip_str {
                parts.push(format!("for={}", forwarded_node(ip)));
            }
            parts.push(format!("proto={proto}"));
            if let Some(orig) = &client_host {
                parts.push(format!("host=\"{orig}\""));
            }
            if let Some(addr) = session.server_addr().and_then(|a| a.as_inet()) {
                parts.push(format!("by={}", forwarded_node(&addr.ip().to_string())));
            }
            let new_value = parts.join("; ");
            let merged = match upstream_request
                .headers
                .get("forwarded")
                .and_then(|v| v.to_str().ok())
            {
                Some(existing) if !existing.is_empty() => format!("{existing}, {new_value}"),
                _ => new_value,
            };
            let _ = upstream_request.insert_header("forwarded".to_string(), &merged);
        }

        if !forwarding.disable_via_header {
            let token = "1.1 sbproxy";
            let merged = match upstream_request
                .headers
                .get("via")
                .and_then(|v| v.to_str().ok())
            {
                Some(existing) if !existing.is_empty() => format!("{existing}, {token}"),
                _ => token.to_string(),
            };
            let _ = upstream_request.insert_header("via".to_string(), &merged);
        }

        // Propagate the correlation ID to the upstream under the
        // configured header name. The same value is echoed on the
        // downstream response in `response_filter`.
        {
            let pipeline = reload::current_pipeline();
            let cfg = &pipeline.config.server.correlation_id;
            if cfg.enabled && !ctx.request_id.is_empty() {
                let _ = upstream_request.insert_header(cfg.header.clone(), ctx.request_id.as_str());
            }
        }

        // mTLS: when the listener verified a client cert, expose
        // what we know to the upstream so it can authorize the
        // request. Always strip any inbound X-Client-Cert-* headers
        // from the client first so a non-TLS client cannot forge
        // them.
        upstream_request.remove_header("x-client-cert-verified");
        upstream_request.remove_header("x-client-cert-cn");
        upstream_request.remove_header("x-client-cert-san");
        upstream_request.remove_header("x-client-cert-organization");
        upstream_request.remove_header("x-client-cert-serial");
        upstream_request.remove_header("x-client-cert-fingerprint");
        if let Some(digest) = session.digest().and_then(|d| d.ssl_digest.as_ref()) {
            // SslDigest exists; this is a TLS connection. cert_digest
            // is empty when the peer presented no cert.
            if !digest.cert_digest.is_empty() {
                let _ = upstream_request.insert_header("x-client-cert-verified".to_string(), "1");

                // CN and SANs are captured by our wrapping
                // ClientCertVerifier at handshake time and indexed by
                // SHA-256 of the cert DER (which matches Pingora's
                // cert_digest).
                if let Some(info) = crate::identity::mtls_cert_cache().get(&digest.cert_digest) {
                    if !info.common_name.is_empty() {
                        let _ = upstream_request.insert_header(
                            "x-client-cert-cn".to_string(),
                            info.common_name.as_str(),
                        );
                    }
                    if !info.subject_alt_names.is_empty() {
                        let joined = info.subject_alt_names.join(", ");
                        let _ = upstream_request
                            .insert_header("x-client-cert-san".to_string(), joined.as_str());
                    }
                }

                if let Some(org) = digest.organization.as_ref() {
                    let _ = upstream_request
                        .insert_header("x-client-cert-organization".to_string(), org.as_str());
                }
                if let Some(sn) = digest.serial_number.as_ref() {
                    let _ = upstream_request
                        .insert_header("x-client-cert-serial".to_string(), sn.as_str());
                }
                let fp = hex::encode(&digest.cert_digest);
                let _ = upstream_request
                    .insert_header("x-client-cert-fingerprint".to_string(), fp.as_str());
            }
        }

        // Apply collected headers via Pingora's methods.
        // Use owned Strings (Pingora's IntoCaseHeaderName is impl'd for String).
        for key in req_to_remove {
            upstream_request.remove_header(&key);
        }
        for (key, value) in req_to_set {
            let _ = upstream_request.insert_header(key, &value);
        }
        for (key, value) in req_to_append {
            let _ = upstream_request.append_header(key, &value);
        }

        // Apply forward auth trust headers (e.g., X-User-ID from auth service)
        if let Some(trust_hdrs) = ctx.trust_headers.take() {
            for (key, value) in trust_hdrs {
                let _ = upstream_request.insert_header(key, &value);
            }
        }

        // Apply on_request callback enrichment headers. Drain the
        // accumulator so retries do not re-inject the same values.
        if let Some(inject) = ctx.callback_inject_headers.take() {
            for (key, value) in inject {
                let _ = upstream_request.insert_header(key, &value);
            }
        }

        // WOR-802: outbound credential resolver. When the origin
        // configures `outbound_credential`, mint/resolve the credential
        // and stamp it on the upstream request, with the inbound
        // caller's bearer token as the RFC 8693 subject token. Config
        // secrets are already `${ENV}`-interpolated at load, so the
        // request-path secret lookup is identity. Minted tokens are
        // cached (by origin + subject) until they near expiry. On
        // failure we fail open: the request goes upstream without the
        // minted credential (the upstream rejects it) rather than the
        // proxy 500ing; a fail-closed flag can follow.
        if let Some(cred_cfg) = outbound_cred.as_ref() {
            let inbound_bearer: Option<String> = session
                .req_header()
                .headers
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| {
                    s.strip_prefix("Bearer ")
                        .or_else(|| s.strip_prefix("bearer "))
                })
                .map(|s| s.to_string());
            let lookup = |r: &str| Ok::<String, anyhow::Error>(r.to_string());
            match sbproxy_modules::auth::outbound_credential::resolve_cached(
                &ctx.hostname,
                cred_cfg,
                forward_auth_client(),
                inbound_bearer.as_deref(),
                &lookup,
            )
            .await
            {
                Ok(minted) => {
                    let _ =
                        upstream_request.insert_header(minted.header_name, &minted.header_value);
                }
                Err(e) => {
                    warn!(
                        origin = %ctx.hostname,
                        error = %e,
                        "outbound credential resolution failed; sending upstream request without it (fail-open)"
                    );
                }
            }
        }

        // Apply Lua script request modifiers
        for script in &lua_scripts {
            match lua_request_modifier(script, session.req_header(), &ctx.hostname) {
                Ok(headers_to_set) => {
                    for (key, value) in headers_to_set {
                        let _ = upstream_request.insert_header(key, &value);
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Lua request modifier script error");
                }
            }
        }

        // --- Distributed tracing: inject child traceparent into upstream request ---
        if let Some(parent_ctx) = &ctx.trace_ctx {
            let child = parent_ctx.child();
            let traceparent = child.to_traceparent();
            let _ = upstream_request.insert_header("traceparent".to_string(), &traceparent);
            if let Some(ref ts) = child.tracestate {
                let _ = upstream_request.insert_header("tracestate".to_string(), ts.as_str());
            }
            // Advance ctx to the child so the response phase can echo the same context.
            ctx.trace_ctx = Some(child);
        }

        // WOR-805: outbound Web Bot Auth signing. When the origin opted
        // in and the proxy has a web_bot_auth key, sign the final
        // outbound request (RFC 9421, tag=web-bot-auth) over
        // @authority/@method/@path so an upstream demanding Web Bot Auth
        // accepts SBproxy as a verified agent. No body is covered (the
        // auth phase does not buffer it). Signing happens last so the
        // covered components match the request the upstream receives.
        // Failures fail open: the request goes upstream unsigned.
        if let Some(signer) = wba_signer.as_ref() {
            if let Some(authority) = upstream_request
                .headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
            {
                let signed = http::Request::builder()
                    .method(upstream_request.method.clone())
                    .uri(format!(
                        "https://{}{}",
                        authority,
                        upstream_request.uri.path()
                    ))
                    .header("host", authority.as_str())
                    .body(bytes::Bytes::new())
                    .map_err(|e| anyhow::anyhow!("build sign request: {e}"))
                    .and_then(|req| {
                        signer
                            .sign_request(req)
                            .map_err(|e| anyhow::anyhow!("sign: {e}"))
                    });
                match signed {
                    Ok(signed) => {
                        for name in ["signature-input", "signature"] {
                            if let Some(v) =
                                signed.headers().get(name).and_then(|v| v.to_str().ok())
                            {
                                let _ = upstream_request.insert_header(name.to_string(), v);
                            }
                        }
                        if let Some(agent) = wba_signature_agent.as_ref() {
                            let _ = upstream_request
                                .insert_header("signature-agent".to_string(), agent);
                        }
                    }
                    Err(e) => warn!(
                        error = %e,
                        "outbound web bot auth signing failed; sending upstream without a signature (fail-open)"
                    ),
                }
            }
        }

        Ok(())
    }

    /// Modify the response header before it is sent to the downstream client.
    ///
    /// This phase applies, in order:
    /// 1. CORS response headers (Access-Control-Allow-Origin, etc.)
    /// 2. HSTS (Strict-Transport-Security)
    /// 3. Security headers from SecHeaders policies (X-Frame-Options, CSP, etc.)
    /// 4. Response modifiers (header set/add/remove)
    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Phase-timing capture: snapshot the moment the upstream's
        // response header arrived. `request_start -> here` is TTFB;
        // `here -> end of this fn` is response_filter latency. Both
        // feed `sbproxy_phase_duration_seconds` and the access log.
        // Set unconditionally because a single request only enters
        // this hook once per upstream response.
        ctx.upstream_first_byte_at = Some(std::time::Instant::now());

        // --- WOR-808: RSL `Link: rel="license"` discovery header ---
        //
        // When the origin publishes an RSL document (it has an
        // `ai_crawl_control` policy, so the projection builder emitted a
        // `/licenses.xml` + URN for it), advertise that document on every
        // response via an RFC 8288 `Link` header so a crawler discovers
        // the license without already knowing the well-known path.
        // Appended (not inserted) so an upstream's own `Link` headers
        // survive.
        //
        // WOR-808 PR5: when the response is HTML, arm the body filter
        // to inject `<link rel="license" ...>` into `<head>`.
        // Header-only discovery misses consumers that read the
        // rendered document (some browsers' "view source" tooling,
        // HTML-parsing scrapers that ignore headers); the inline tag
        // closes that gap without changing the header behaviour.
        //
        // WOR-808 PR6: same treatment for RSS / Atom feeds. The link
        // slots into `<channel>` (RSS) or `<feed>` (Atom) with the
        // self-closing XML form so a feed-reading consumer discovers
        // the license document the same way an HTML reader does.
        if !ctx.hostname.is_empty() {
            let projections = sbproxy_modules::projections::current_projections();
            if projections.rsl_urns.contains_key(ctx.hostname.as_str()) {
                let _ = upstream_response
                    .append_header("link".to_string(), "</licenses.xml>; rel=\"license\"");
                let raw_ct = upstream_response
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let is_html = raw_ct
                    .split(';')
                    .next()
                    .map(|t| t.trim().eq_ignore_ascii_case("text/html"))
                    .unwrap_or(false);
                let feed_format = sbproxy_modules::projections::classify_feed_content_type(raw_ct);
                if is_html || feed_format.is_some() {
                    ctx.rsl_inject_link_pending = true;
                    ctx.rsl_inject_link_feed = feed_format;
                    // Body length is about to change; drop
                    // Content-Length and switch to chunked so the body
                    // filter can rewrite without producing a
                    // length-mismatch error downstream.
                    upstream_response.remove_header("content-length");
                    let _ = upstream_response.insert_header("transfer-encoding", "chunked");
                }
            }
        }

        // --- WOR-819: gRPC -> REST/JSON response header rewrite ---
        //
        // A transcoded request gets a gRPC response: `content-type:
        // application/grpc`, the body a length-prefixed frame, and the
        // gRPC status in trailers (or, for an immediate error, a
        // trailers-only response carrying `grpc-status` in the headers).
        // Rewrite the content-type to JSON and drop the now-wrong
        // content-length (the body is rewritten in response_body_filter).
        // Capture a header-borne `grpc-status` so a trailers-only error
        // maps to the JSON error envelope.
        if ctx.transcode_active {
            let _ = upstream_response.insert_header("content-type".to_string(), "application/json");
            upstream_response.remove_header("content-length");
            upstream_response.remove_header("grpc-encoding");
            if let Some(status) = upstream_response
                .headers
                .get("grpc-status")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<i32>().ok())
            {
                ctx.transcode_grpc_status = Some(status);
                if let Some(msg) = upstream_response
                    .headers
                    .get("grpc-message")
                    .and_then(|v| v.to_str().ok())
                {
                    ctx.transcode_grpc_message = Some(msg.to_string());
                }
            }
        }

        // --- WOR-819: gRPC -> gRPC-Web response header rewrite ---
        //
        // Set the gRPC-Web response content-type (tracking the request's
        // text/binary variant), drop content-length (the body gains a
        // trailer frame), and capture a header-borne `grpc-status` for a
        // trailers-only error so the trailer frame reports it.
        if ctx.grpc_web_active {
            let req_ct = session
                .req_header()
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/grpc-web+proto")
                .to_string();
            let resp_ct = sbproxy_transport::grpc::GrpcWebBridge::response_content_type(&req_ct);
            let _ = upstream_response.insert_header("content-type".to_string(), resp_ct);
            upstream_response.remove_header("content-length");
            upstream_response.remove_header("grpc-encoding");
            if let Some(status) = upstream_response
                .headers
                .get("grpc-status")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<i32>().ok())
            {
                ctx.transcode_grpc_status = Some(status);
                if let Some(msg) = upstream_response
                    .headers
                    .get("grpc-message")
                    .and_then(|v| v.to_str().ok())
                {
                    ctx.transcode_grpc_message = Some(msg.to_string());
                }
            }
        }

        // --- WOR-114: x-sb-flags debug response markers ---
        //
        // When the client opted in via `x-sb-flags: debug` (or
        // `?_sb.debug`), stamp the request id and the active config
        // revision onto the response so an operator can correlate
        // a single request with the proxy logs and the running
        // pipeline. The headers are intentionally short to keep the
        // header block under typical 8KB limits.
        if ctx.flags.debug {
            let _ = upstream_response
                .insert_header("x-sbproxy-debug-request-id", ctx.request_id.as_str());
            let pipeline = reload::current_pipeline();
            let _ = upstream_response.insert_header(
                "x-sbproxy-debug-config-rev",
                pipeline.config_revision.as_str(),
            );
        }

        // --- RFC 9209 Proxy-Status header (per-origin opt-in) ---
        //
        // When the resolved origin has `proxy_status.enabled: true`,
        // stamp a structured Proxy-Status header on every non-2xx
        // response. The header carries the configured proxy identity
        // (`sbproxy` by default), the received upstream status, and
        // an `error` parameter when the status maps to a known
        // failure mode. Downstream clients can diagnose forwarding
        // errors without scraping the body.
        {
            let status_code = upstream_response.status.as_u16();
            if !(200..300).contains(&status_code) {
                let pipeline = reload::current_pipeline();
                if let Some(idx) = ctx.origin_idx {
                    if let Some(origin) = pipeline.config.origins.get(idx) {
                        if let Some(cfg) = origin.proxy_status.as_ref() {
                            if cfg.enabled {
                                let identity = cfg.identity.as_deref().unwrap_or("sbproxy");
                                let error_token = proxy_status_error_token(status_code);
                                let value =
                                    sbproxy_middleware::proxy_status::build_proxy_status_with_identity(
                                        identity,
                                        status_code,
                                        error_token,
                                    );
                                let _ = upstream_response.insert_header("proxy-status", value);
                            }
                        }
                    }
                }
            }
        }

        // --- Idempotency cache-miss response capture ---
        //
        // When `request_body_filter` recorded a cache miss on this
        // request, `ctx.idempotency_miss` carries the key + body hash.
        // Snapshot the upstream status and headers here so
        // `response_body_filter` can pair them with the accumulated
        // body and call `record_response` once the stream ends.
        if ctx.idempotency_miss.is_some() {
            ctx.idempotency_response_status = Some(upstream_response.status.as_u16());
            let headers: Vec<(String, String)> = upstream_response
                .headers
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|v| (name.as_str().to_string(), v.to_string()))
                })
                .collect();
            ctx.idempotency_response_headers = Some(headers);
        }

        // --- Idempotency skip-reason marker ---
        //
        // When `request_filter` or `request_body_filter` disengaged
        // the middleware (oversize body, pool exhausted), stamp the
        // reason on the response so operators can see the skip in
        // dashboards. The header is informational; the response
        // body and status come from the upstream untouched.
        if let Some(reason) = ctx.idempotency_skip_reason {
            let _ = upstream_response.insert_header("x-sbproxy-idempotency", reason);
        }

        // --- Wave 5 / G5.6 wire: AnomalyDetectorHook dispatch ---
        //
        // Run every registered anomaly detector hook against the
        // per-request context now that all signals have been populated
        // (TLS fingerprint, ML classification, headless detection,
        // request rate). Verdicts are forwarded to whichever sink the
        // hook impl wires (audit log, tracing, reputation updater).
        // The OSS pipeline does not act on the verdicts directly; a
        // plugin is responsible for routing them through whatever
        // alert sink and reputation tally it wants.
        //
        // OSS-only builds register no anomaly hooks; the iteration is
        // a no-op. A plugin can install detectors at startup via the
        // `sbproxy-plugin` registry.
        {
            let hooks = sbproxy_plugin::anomaly_hooks();
            if !hooks.is_empty() {
                let req_header = session.req_header();
                let method_str = req_header.method.as_str();
                let path_str = req_header.uri.path();
                let query_str = req_header.uri.query().unwrap_or("");
                #[cfg(feature = "agent-class")]
                let agent_id_str = ctx.agent_id.as_ref().map(|a| a.as_str().to_string());
                #[cfg(not(feature = "agent-class"))]
                let agent_id_str: Option<String> = None;
                #[cfg(feature = "agent-class")]
                let agent_id_source_label = ctx.agent_id_source.map(|s| s.as_str());
                #[cfg(not(feature = "agent-class"))]
                let agent_id_source_label: Option<&str> = None;
                #[cfg(feature = "tls-fingerprint")]
                let (ja4_fp, ja4_trust, headless_lib) = {
                    let ja4 = ctx
                        .tls_fingerprint
                        .as_ref()
                        .and_then(|fp| fp.ja4.as_deref());
                    let trust = ctx
                        .tls_fingerprint
                        .as_ref()
                        .is_some_and(|fp| fp.trustworthy);
                    let lib = match ctx.headless_signal.as_ref() {
                        Some(crate::context::HeadlessSignal::Detected { library, .. }) => {
                            Some(library.as_str())
                        }
                        _ => None,
                    };
                    (ja4, trust, lib)
                };
                #[cfg(not(feature = "tls-fingerprint"))]
                let (ja4_fp, ja4_trust, headless_lib): (
                    Option<&str>,
                    bool,
                    Option<&str>,
                ) = (None, false, None);
                let view = sbproxy_plugin::RequestContextView {
                    hostname: ctx.hostname.as_str(),
                    method: method_str,
                    path: path_str,
                    query: query_str,
                    agent_id: agent_id_str.as_deref(),
                    agent_id_source: agent_id_source_label,
                    ja4_fingerprint: ja4_fp,
                    ja4_trustworthy: ja4_trust,
                    headless_library: headless_lib,
                    client_ip: ctx.client_ip,
                };
                for hook in hooks.iter() {
                    let verdicts = hook.analyze(&view).await;
                    if !verdicts.is_empty() {
                        debug!(
                            hostname = %ctx.hostname,
                            verdict_count = verdicts.len(),
                            "anomaly detector hook returned {} verdicts",
                            verdicts.len()
                        );
                    }
                }
            }
        }

        // --- On-status fallback: rewrite response if upstream status matches ---
        {
            let upstream_status = upstream_response.status.as_u16();
            if let Some(origin_idx) = ctx.origin_idx {
                let pipeline = reload::current_pipeline();
                if let Some(fallback) = &pipeline.fallbacks[origin_idx] {
                    if !fallback.on_status.is_empty()
                        && fallback.on_status.contains(&upstream_status)
                    {
                        debug!(
                            hostname = %ctx.hostname,
                            upstream_status = %upstream_status,
                            "upstream status matched on_status fallback, rewriting response"
                        );
                        ctx.fallback_triggered = true;

                        // Rewrite response headers with the fallback action's response.
                        if let Action::Static(s) = &fallback.action {
                            let ct = s.content_type.as_deref().unwrap_or("text/plain");
                            upstream_response.set_status(s.status).map_err(|e| {
                                Error::because(
                                    ErrorType::InternalError,
                                    "failed to set fallback status",
                                    e,
                                )
                            })?;
                            let _ = upstream_response.insert_header("content-type", ct);
                            let _ = upstream_response
                                .insert_header("content-length", s.body.len().to_string());
                            upstream_response.remove_header("transfer-encoding");
                            for (k, v) in &s.headers {
                                let _ = upstream_response.insert_header(k.clone(), v.clone());
                            }
                            if fallback.add_debug_header {
                                let _ =
                                    upstream_response.insert_header("X-Fallback-Trigger", "status");
                            }
                            // Store the fallback body for response_body_filter to swap in.
                            ctx.fallback_body =
                                Some(bytes::Bytes::copy_from_slice(s.body.as_bytes()));
                            ctx.response_status = Some(s.status);
                            return Ok(());
                        }
                    }
                }
            }
        }

        // Collect all header modifications into owned Vecs, then drop the pipeline
        // guard before calling Pingora's insert_header (which requires 'static names).
        let mut to_set: Vec<(String, String)> = Vec::new();
        let mut to_remove: Vec<String> = Vec::new();
        let mut to_append: Vec<(String, String)> = Vec::new();

        {
            let pipeline = reload::current_pipeline();
            let origin_idx = match ctx.origin_idx {
                Some(idx) => idx,
                None => return Ok(()),
            };
            let origin = &pipeline.config.origins[origin_idx];

            // 1. CORS headers
            if let Some(cors_config) = &origin.cors {
                let request_origin = session
                    .req_header()
                    .headers
                    .get("origin")
                    .and_then(|v| v.to_str().ok());
                let mut temp = http::HeaderMap::new();
                sbproxy_middleware::cors::apply_cors_headers(
                    cors_config,
                    request_origin,
                    &mut temp,
                );
                for (name, value) in &temp {
                    to_set.push((name.to_string(), value.to_str().unwrap_or("").to_string()));
                }
            }

            // 2. HSTS
            if let Some(hsts_config) = &origin.hsts {
                let mut temp = http::HeaderMap::new();
                sbproxy_middleware::hsts::apply_hsts(hsts_config, &mut temp);
                for (name, value) in &temp {
                    to_set.push((name.to_string(), value.to_str().unwrap_or("").to_string()));
                }
            }

            // 2b. Wave 4 / G4.5 + G4.8 wire: Content-Signal +
            // TDM-Reservation headers.
            //
            // Per G4.1: when the origin sets a closed-enum
            // `content_signal` value the proxy
            // stamps `Content-Signal: <value>` on 200 responses. Only
            // 2xx responses carry the header; 402/403/406/etc.
            // negotiation failures intentionally suppress it.
            //
            // Per A4.1 § "tdmrep.json": when an origin asserts no
            // `Content-Signal` value the proxy stamps the optional
            // `TDM-Reservation: 1` response header so non-cooperative
            // crawlers see the reservation even without parsing the
            // JSON document at `/.well-known/tdmrep.json`. The two
            // headers are mutually exclusive: a signalled origin
            // surfaces its position through `Content-Signal`; an
            // unsignalled origin falls back to `TDM-Reservation`.
            {
                let upstream_status = upstream_response.status.as_u16();
                let is_2xx = (200..300).contains(&upstream_status);
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
                        to_set.push(("content-signal".to_string(), value));
                    }
                    ContentSignalDecision::TdmReservationFallback => {
                        to_set.push(("tdm-reservation".to_string(), "1".to_string()));
                    }
                    ContentSignalDecision::Skip => {}
                }
            }

            // WOR-803: Cloudflare Pay Per Crawl. When the request
            // settled through the ledger in Cloudflare-compat mode, the
            // policy stashed the charged amount on the context. Stamp
            // `crawler-charged: <currency> <amount>` on the 2xx so the
            // crawler learns exactly what it paid, matching Cloudflare's
            // wire contract. Only 2xx responses carry it.
            if (200..300).contains(&upstream_response.status.as_u16()) {
                if let Some(charged) = ctx.crawl_charged.clone() {
                    to_set.push(("crawler-charged".to_string(), charged));
                }
            }

            // 3. Security headers
            //
            // When the CSP configuration is the detailed variant with
            // enable_nonce or dynamic_routes, we use the per-request builder
            // which picks the policy for the current path and generates a
            // nonce. The generated nonce (if any) is exposed as X-CSP-Nonce
            // so templated responses can read it.
            for policy in &pipeline.policies[origin_idx] {
                if let Policy::SecHeaders(sec) = policy {
                    let path = session.req_header().uri.path();
                    let (headers, nonce) = sec.resolved_headers_for_request(path);
                    for (name, value) in headers {
                        to_set.push((name, value));
                    }
                    if let Some(n) = nonce {
                        to_set.push(("x-csp-nonce".to_string(), n));
                    }
                }
                if let Policy::PageShield(shield) = policy {
                    // Skip when the upstream emits its own CSP and the
                    // policy is configured to defer.
                    let upstream_has_csp = upstream_response
                        .headers
                        .contains_key(http::header::CONTENT_SECURITY_POLICY)
                        || upstream_response
                            .headers
                            .contains_key("content-security-policy-report-only");
                    if !shield.yields_to_upstream(upstream_has_csp) {
                        let host = session
                            .req_header()
                            .headers
                            .get("host")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        let (name, value) = shield.header(host);
                        to_set.push((name.to_string(), value));
                    }
                }
            }

            // 4. Response modifiers (static headers, status override, body replacement, Lua scripts)
            // Build template context for response modifier interpolation.
            let tmpl = build_request_template_context(session, ctx, origin);
            for modifier in &origin.response_modifiers {
                if let Some(hm) = &modifier.headers {
                    for key in &hm.remove {
                        to_remove.push(key.clone());
                    }
                    for (key, value) in &hm.set {
                        to_set.push((key.clone(), tmpl.resolve(value)));
                    }
                    for (key, value) in &hm.add {
                        to_append.push((key.clone(), tmpl.resolve(value)));
                    }
                }
                // Status code override.
                if let Some(status_override) = &modifier.status {
                    ctx.response_status_override = Some(status_override.code);
                }
                // Body replacement (stored for response_body_filter).
                if let Some(body_mod) = &modifier.body {
                    if let Some(json_val) = &body_mod.replace_json {
                        ctx.response_body_replacement = Some(Bytes::from(json_val.to_string()));
                    } else if let Some(text) = &body_mod.replace {
                        ctx.response_body_replacement = Some(Bytes::from(text.clone()));
                    }
                }
                if let Some(script) = &modifier.lua_script {
                    let status = upstream_response.status.as_u16();
                    match lua_response_modifier(script, status) {
                        Ok(headers) => {
                            for (key, value) in headers {
                                to_set.push((key, value));
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "Lua response modifier script error");
                        }
                    }
                }
            }
        } // pipeline guard dropped here

        // 5. Forward rule request modifier headers echoed on response
        // (Go proxy includes forward rule set headers in the response too)
        {
            let pipeline = reload::current_pipeline();
            if let (Some(idx), Some(fwd_idx)) = (ctx.origin_idx, ctx.forward_rule_idx) {
                if let Some(fwd_rules) = pipeline.forward_rules.get(idx) {
                    if let Some(fwd_rule) = fwd_rules.get(fwd_idx) {
                        for modifier in &fwd_rule.request_modifiers {
                            if let Some(hm) = &modifier.headers {
                                for (key, value) in &hm.set {
                                    to_set.push((key.clone(), value.clone()));
                                }
                            }
                        }
                    }
                }
            }
        }

        // 6. Rate limit headers on proxied responses.
        if let Some(ref info) = ctx.rate_limit_info {
            if info.headers_enabled {
                to_set.push(("X-RateLimit-Limit".into(), info.limit.to_string()));
                to_set.push(("X-RateLimit-Remaining".into(), info.remaining.to_string()));
                to_set.push(("X-RateLimit-Reset".into(), info.reset_secs.to_string()));
            }
        }

        // 7. Alt-Svc header for HTTP/3 advertisement.
        {
            let alt_svc = reload::alt_svc_value();
            if !alt_svc.is_empty() {
                to_set.push(("Alt-Svc".into(), alt_svc.to_string()));
            }
        }

        // 8. Wave 8 P0 session ID echo.
        //    When a session was captured (caller-supplied valid ULID or
        //    auto-generated for anonymous traffic), echo it on the
        //    response so stateless SDK callers can learn their
        //    freshly-minted session ID.
        if let Some(sid) = ctx.session_id {
            to_set.push(("X-Sb-Session-Id".into(), sid.to_string()));
        }

        // T1.3 properties echo. When the per-origin
        // PropertiesConfig.echo flag is on, every captured property
        // flows back as `X-Sb-Property-<key>: <value>`. Properties
        // are already cardinality-capped, allowlist-checked, and
        // redacted by capture_properties so the echo cannot leak
        // unbounded or unsafe data.
        if ctx.properties_echo {
            for (key, value) in &ctx.properties {
                to_set.push((format!("X-Sb-Property-{key}"), value.clone()));
            }
        }

        // WOR-201 PR 1b: drain plugin-policy response headers.
        //
        // Every `Policy::Plugin` enforcer that returned
        // `PolicyDecision::AllowWithHeaders` (or whose `Confirm`
        // verdict the OSS bridge translated to AllowWithHeaders
        // with `X-Policy-Confirm` stamped) pushed onto
        // `ctx.policy_response_headers`. Drain the slot here so
        // the headers land on the outgoing response in chain
        // order. Append rather than set so multi-value contracts
        // (e.g. WWW-Authenticate chains) survive.
        for entry in std::mem::take(&mut ctx.policy_response_headers) {
            to_append.push(entry);
        }

        // Wave 5 day-6 Item 1: drain CEL header transform mutations.
        //
        // Each `type: cel` transform with a non-empty `headers:` array
        // gets its rules evaluated against the response headers we have
        // in hand. Body content is not yet available at this phase
        // (the transforms only see request.* and response.status /
        // response.headers), but that is the documented surface for
        // the day-6 header-mutating variant. Evaluations that reach
        // for `response.body` resolve to "" - the body-rewriting
        // expression continues to run at body-buffer time as before.
        {
            let pipeline = reload::current_pipeline();
            if let Some(idx) = ctx.origin_idx {
                if idx < pipeline.transforms.len() {
                    for compiled in &pipeline.transforms[idx] {
                        if let sbproxy_modules::Transform::CelScript(t) = &compiled.transform {
                            if t.headers.is_empty() {
                                continue;
                            }
                            // WOR-168: use the lossy shim here so the
                            // upstream-response header-wiring path stays
                            // resilient. A drifted CEL invariant is
                            // logged and the response continues with
                            // an empty mutation set; the body-buffer
                            // path above promotes the same drift to a
                            // 500 with attribution because that is
                            // where the failure must be visible to the
                            // client.
                            let mutations = t.evaluate_headers_lossy(
                                b"",
                                upstream_response.status.as_u16(),
                                &upstream_response.headers,
                            );
                            for m in mutations {
                                match m {
                                    sbproxy_modules::transform::CelHeaderMutation::Set(k, v) => {
                                        to_set.push((k, v));
                                    }
                                    sbproxy_modules::transform::CelHeaderMutation::Append(k, v) => {
                                        to_append.push((k, v));
                                    }
                                    sbproxy_modules::transform::CelHeaderMutation::Remove(k) => {
                                        to_remove.push(k);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Apply collected headers via Pingora's API (requires owned String for
        // IntoCaseHeaderName). Drain the vectors to get ownership.
        for key in to_remove {
            upstream_response.remove_header(&key);
        }
        for (key, value) in to_set {
            let _ = upstream_response.insert_header(key, &value);
        }
        for (key, value) in to_append {
            let _ = upstream_response.append_header(key, &value);
        }

        // Apply status code override from response modifiers.
        if let Some(status_code) = ctx.response_status_override {
            if let Ok(status) = http::StatusCode::from_u16(status_code) {
                upstream_response.set_status(status).ok();
            }
        }

        // 6. CSRF cookie (set on safe method responses).
        if let Some(ref cookie) = ctx.csrf_cookie {
            let _ = upstream_response.append_header("set-cookie", cookie);
        }

        // 7. Assertions: evaluate CEL against the response and log
        //    pass/fail. Assertions are observational only and never
        //    block or modify the response. Body size is not yet known
        //    at the header-phase, so we pass None for body_size.
        {
            let pipeline_a = reload::current_pipeline();
            if let Some(idx) = ctx.origin_idx {
                if let Some(policies) = pipeline_a.policies.get(idx) {
                    let req = session.req_header();
                    let method = req.method.as_str().to_string();
                    let path = req.uri.path().to_string();
                    let req_headers = req.headers.clone();
                    let query = req.uri.query().map(|q| q.to_string());
                    let client_ip = ctx.client_ip.map(|ip| ip.to_string());
                    let hostname = ctx.hostname.to_string();
                    let resp_status = upstream_response.status.as_u16();
                    let resp_headers = upstream_response.headers.clone();
                    for policy in policies {
                        if let Policy::Assertion(a) = policy {
                            let passed = a.evaluate(
                                &method,
                                &path,
                                &req_headers,
                                query.as_deref(),
                                client_ip.as_deref(),
                                &hostname,
                                resp_status,
                                &resp_headers,
                                None,
                            );
                            if passed {
                                tracing::info!(
                                    target: "sbproxy::assertion",
                                    assertion = %a.name,
                                    status = resp_status,
                                    "assertion passed"
                                );
                            } else {
                                tracing::warn!(
                                    target: "sbproxy::assertion",
                                    assertion = %a.name,
                                    status = resp_status,
                                    expression = %a.expression,
                                    "assertion failed"
                                );
                            }
                        }
                    }
                }
            }
        }

        // 8. Session cookie: set sbproxy_sid if session_config is present and cookie is absent.
        {
            let pipeline3 = reload::current_pipeline();
            if let Some(origin_idx) = ctx.origin_idx {
                let origin = &pipeline3.config.origins[origin_idx];
                if let Some(ref session_cfg) = origin.session {
                    let cookie_name = session_cfg.cookie_name.as_deref().unwrap_or("sbproxy_sid");

                    // Check if the client already sent this cookie.
                    let has_cookie = session
                        .req_header()
                        .headers
                        .get("cookie")
                        .and_then(|v| v.to_str().ok())
                        .map(|cookies| {
                            cookies.split(';').any(|c| {
                                let c = c.trim();
                                c.starts_with(cookie_name)
                                    && c[cookie_name.len()..].starts_with('=')
                            })
                        })
                        .unwrap_or(false);

                    if !has_cookie {
                        let sid = uuid::Uuid::new_v4().to_string();
                        let cookie_val = build_session_cookie(session_cfg, &sid);
                        let _ = upstream_response.append_header("set-cookie", &cookie_val);
                    }
                }
            }
        }

        // 9. Fire on_response callbacks.
        {
            let on_response_callbacks = {
                let pipeline4 = reload::current_pipeline();
                ctx.origin_idx.and_then(|idx| {
                    let origin = &pipeline4.config.origins[idx];
                    if origin.on_response.is_empty() {
                        None
                    } else {
                        Some((
                            origin.on_response.clone(),
                            pipeline4.config_revision.clone(),
                        ))
                    }
                })
            };
            if let Some((callbacks, config_revision)) = on_response_callbacks {
                let status = upstream_response.status.as_u16();
                let hostname = ctx.hostname.to_string();
                let path = session.req_header().uri.path().to_string();
                let request_id = ctx.request_id.to_string();
                let duration_ms = ctx.request_start.map(|s| s.elapsed().as_millis() as u64);
                let injected = fire_on_response_callbacks(
                    &callbacks,
                    status,
                    &hostname,
                    &path,
                    &request_id,
                    &config_revision,
                    duration_ms,
                )
                .await;
                for (key, value) in injected {
                    let _ = upstream_response.insert_header(key, &value);
                }
            }
        }

        // Capture response status for metrics in the logging phase.
        ctx.response_status = Some(upstream_response.status.as_u16());

        // --- Outlier detection + circuit breaker: per-target signals ---
        // 5xx counts as a failure for both the sliding-window outlier
        // detector and the formal circuit breaker. Earlier phases
        // already record connect/timeout failures via Pingora's
        // upstream error path; here we capture application-level
        // errors from the response itself.
        if let Some(target_idx) = ctx.lb_target_idx {
            let pipeline_o = reload::current_pipeline();
            if let Some(origin_idx) = ctx.origin_idx {
                if let Some(Action::LoadBalancer(lb)) = pipeline_o.actions.get(origin_idx) {
                    let status = upstream_response.status.as_u16();
                    if status >= 500 {
                        lb.record_target_failure(target_idx);
                        lb.record_breaker_failure(target_idx);
                    } else {
                        lb.record_target_success(target_idx);
                        lb.record_breaker_success(target_idx);
                    }
                }
            }
        }

        // --- Distributed tracing: echo traceparent/tracestate to downstream client ---
        if let Some(ref trace_ctx) = ctx.trace_ctx {
            let _ = upstream_response.insert_header("traceparent", trace_ctx.to_traceparent());
            if let Some(ref ts) = trace_ctx.tracestate {
                let _ = upstream_response.insert_header("tracestate", ts.as_str());
            }
        }

        // --- Echo correlation ID to the downstream client ---
        // The client sees the same identifier the upstream saw, even
        // when the proxy minted it (i.e. the inbound request had no
        // correlation header). This lets a client log the value and
        // hand it to support to find the matching upstream / proxy
        // logs.
        {
            let pipeline_c = reload::current_pipeline();
            let cfg = &pipeline_c.config.server.correlation_id;
            if cfg.enabled && cfg.echo_response && !ctx.request_id.is_empty() {
                let _ =
                    upstream_response.insert_header(cfg.header.clone(), ctx.request_id.as_str());
            }
        }

        // 10. Prepare for body transforms: remove Content-Length so Pingora
        //    sends chunked encoding once we buffer and modify the body.
        let pipeline2 = reload::current_pipeline();
        let has_transforms = ctx
            .origin_idx
            .map(|idx| idx < pipeline2.transforms.len() && !pipeline2.transforms[idx].is_empty())
            .unwrap_or(false);

        // Cache the upstream content-type early. SRI also reads this in the
        // body filter to decide whether to scan, and it is cheap to compute
        // once.
        let upstream_ct = upstream_response
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Decide whether to enable SRI scanning. Only when the origin has
        // an enforcing `sri` policy attached AND the response body is
        // text/html. Anything else passes through untouched. SRI is
        // observation-only: violations are logged at warn but the
        // response body is not modified.
        if let Some(idx) = ctx.origin_idx {
            if idx < pipeline2.policies.len() {
                let is_html = upstream_ct
                    .as_deref()
                    .and_then(|ct| ct.split(';').next())
                    .map(|t| t.trim().eq_ignore_ascii_case("text/html"))
                    .unwrap_or(false);
                if is_html {
                    let any_sri_enforcing = pipeline2.policies[idx]
                        .iter()
                        .any(|p| matches!(p, sbproxy_modules::Policy::Sri(s) if s.enforce));
                    if any_sri_enforcing {
                        ctx.sri_scan_enabled = true;
                    }
                }
            }
        }

        if has_transforms || ctx.sri_scan_enabled {
            ctx.upstream_content_type = upstream_ct.clone();
            upstream_response.remove_header("content-length");
            let _ = upstream_response.insert_header("transfer-encoding", "chunked");
        }

        // --- Response compression negotiation ---
        //
        // The upstream content-type drives the skip list (already-compressed
        // formats like image/jpeg, video/*, application/zip pass through
        // unchanged). We honour the origin's `min_size` floor up front when
        // the upstream advertised a `Content-Length`; chunked upstreams skip
        // the floor check here and let the body filter re-evaluate at
        // end-of-stream. Already-compressed responses (upstream already set
        // `Content-Encoding`) are left alone.
        if let Some(origin_idx) = ctx.origin_idx {
            let origin = &pipeline2.config.origins[origin_idx];
            if let Some(comp_cfg) = origin.compression.as_ref() {
                let upstream_already_encoded =
                    upstream_response.headers.contains_key("content-encoding");
                let ct_ok = sbproxy_middleware::compression::should_compress_content_type(
                    upstream_ct.as_deref(),
                );
                let upstream_len: Option<usize> = upstream_response
                    .headers
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse().ok());
                let size_ok = match upstream_len {
                    Some(n) => n >= comp_cfg.min_size,
                    None => true,
                };
                if !upstream_already_encoded && ct_ok && size_ok {
                    let accept = session
                        .req_header()
                        .headers
                        .get("accept-encoding")
                        .and_then(|v| v.to_str().ok());
                    let encoding =
                        sbproxy_middleware::compression::negotiate_encoding(comp_cfg, accept);
                    if !matches!(
                        encoding,
                        sbproxy_middleware::compression::Encoding::Identity
                    ) {
                        ctx.compression_encoding = Some(encoding);
                        ctx.compression_min_size = comp_cfg.min_size;
                        ctx.compression_buf = Some(bytes::BytesMut::with_capacity(8192));
                        let _ =
                            upstream_response.insert_header("content-encoding", encoding.as_str());
                        upstream_response.remove_header("content-length");
                        let _ = upstream_response.insert_header("transfer-encoding", "chunked");
                        let _ = upstream_response.append_header("vary", "Accept-Encoding");
                    }
                }
            }
        }

        // --- Response cache: capture status/headers ---
        //
        // If `request_filter` recorded a cache_key for this request (= cache
        // enabled, method cacheable, and the entry was not already in the
        // cache), this is the earliest point where we know the upstream
        // status. Gate on the `cacheable_status` list here so non-cacheable
        // statuses (e.g. 500) don't populate the cache.
        if ctx.cache_key.is_some() {
            let status = upstream_response.status.as_u16();
            let cache_status_ok = if let Some(idx) = ctx.origin_idx {
                match pipeline2
                    .config
                    .origins
                    .get(idx)
                    .and_then(|o| o.response_cache.as_ref())
                {
                    Some(cfg) => {
                        if cfg.cacheable_status.is_empty() {
                            status == 200
                        } else {
                            cfg.cacheable_status.contains(&status)
                        }
                    }
                    None => false,
                }
            } else {
                false
            };

            if cache_status_ok {
                ctx.cache_status = Some(status);
                // Capture a lossy view of the response headers. Hop-by-hop
                // headers that must not be forwarded by the cache (e.g.
                // Connection, Transfer-Encoding) are skipped.
                let mut captured: Vec<(String, String)> =
                    Vec::with_capacity(upstream_response.headers.len());
                for (name, value) in upstream_response.headers.iter() {
                    let n = name.as_str().to_ascii_lowercase();
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
                    if let Ok(v) = value.to_str() {
                        captured.push((n, v.to_string()));
                    }
                }
                ctx.cache_headers = Some(captured);
                ctx.cache_body_buf = Some(bytes::BytesMut::with_capacity(4096));
            } else {
                // Non-cacheable status: clear the key so the body filter
                // doesn't accumulate a response we're going to discard.
                ctx.cache_key = None;
            }
        }

        // --- Wave 4 day-5 Items 3 + 4: Content-Type rewrite ---
        //
        // The response-body wiring (in response_body_filter) replaces
        // the body with the JSON envelope or rewrites the Markdown
        // projection in place. Stamp the matching Content-Type here
        // before the headers go downstream. Requires `transfer-encoding:
        // chunked` (already set by the transforms guard above) so the
        // header emission isn't bound to a stale Content-Length.
        if let Some(shape) = ctx.content_shape_transform {
            match shape {
                sbproxy_modules::ContentShape::Json => {
                    let _ = upstream_response
                        .insert_header("content-type", sbproxy_modules::JSON_ENVELOPE_CONTENT_TYPE);
                    upstream_response.remove_header("content-length");
                    let _ = upstream_response.insert_header("transfer-encoding", "chunked");
                }
                sbproxy_modules::ContentShape::Markdown => {
                    let _ = upstream_response
                        .insert_header("content-type", "text/markdown; charset=utf-8");
                    upstream_response.remove_header("content-length");
                    let _ = upstream_response.insert_header("transfer-encoding", "chunked");
                }
                _ => {}
            }

            // --- Wave 4 day-5 Item 5: x-markdown-tokens header ---
            //
            // Stamp the response with the Markdown token estimate when
            // the negotiated shape is Markdown / Json. The estimate
            // may have been computed already (HtmlToMarkdown ran, or
            // the upstream response went through the body-filter
            // synth path); when neither has happened yet (early proxy
            // response_filter), fall back to the upstream
            // Content-Length times the per-origin `token_bytes_ratio`
            // (A4.2 follow-up). The header value is final at the time
            // we serialise it; it cannot change after headers go out.
            let upstream_len = upstream_response
                .headers
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            let ratio_override = ctx
                .origin_idx
                .and_then(|idx| pipeline2.config.origins[idx].token_bytes_ratio);
            if let Some(estimate) = x_markdown_tokens_header_value_with_ratio(
                Some(shape),
                ctx.markdown_token_estimate,
                upstream_len,
                ratio_override,
            ) {
                let _ = upstream_response.insert_header("x-markdown-tokens", estimate.to_string());
            }
        }

        // Phase-timing capture: snapshot the moment response_filter
        // returns. Paired with `ctx.upstream_first_byte_at` (set at
        // the top of this hook), this is the response-filter phase
        // latency in the access log and in
        // `sbproxy_phase_duration_seconds{phase="response_filter"}`.
        ctx.response_filter_finished_at = Some(std::time::Instant::now());

        Ok(())
    }

    /// Replace the request body before it is sent upstream (when a
    /// modifier produced one) and run any `RequestValidator` policies
    /// against the buffered body once the stream ends.
    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Track total request body bytes for the access log /
        // billing / ML pipeline. Always-on; the size-limit policy
        // below tracks its own counter so the cap is enforced
        // consistently regardless of policy ordering.
        if let Some(chunk) = body.as_ref() {
            ctx.request_body_bytes = ctx.request_body_bytes.saturating_add(chunk.len() as u64);
        }

        // --- RequestLimit max_body_size enforcement (streaming) ---
        //
        // `check_policies` only sees `Content-Length` (or 0 for
        // chunked / unknown-length uploads) at request_filter time, so
        // a client that omits or lies about Content-Length can still
        // smuggle an oversize body. Track accumulated bytes here and
        // synthesise a 413 once the configured cap is crossed. We piggy-
        // back on `validator_failed` so `fail_to_proxy` writes the
        // typed rejection without contacting the upstream.
        if let Some(cap) = ctx.body_size_limit {
            if let Some(chunk) = body.as_ref() {
                ctx.body_bytes_seen = ctx.body_bytes_seen.saturating_add(chunk.len());
                if ctx.body_bytes_seen > cap {
                    let detail = format!("body size {} exceeds limit {}", ctx.body_bytes_seen, cap);
                    debug!(detail = %detail, "request_limit: body size exceeded streaming cap");
                    let body_str = serde_json::json!({
                        "error": "request entity too large",
                        "detail": detail,
                    })
                    .to_string();
                    ctx.validator_failed = Some((413, body_str, "application/json".to_string()));
                    *body = None;
                    return Err(pingora_error::Error::explain(
                        pingora_error::ErrorType::HTTPStatus(413),
                        "request body exceeded max_body_size",
                    ));
                }
            }
        }

        // --- WOR-819: REST -> gRPC request body transcoding ---
        //
        // When `upstream_request_filter` matched a transcode route, hold
        // the JSON body back from the upstream and, at end_of_stream,
        // encode it into a unary gRPC frame via the descriptor-backed
        // transcoder (re-fetched from the pipeline). The original method
        // and path are read from the client request header; the upstream
        // `:path` and headers were already rewritten. A malformed body is
        // rejected without contacting the upstream. (An unmapped REST path
        // is rejected earlier, in `handle_action`.)
        if ctx.transcode_active {
            let buf = ctx
                .request_body_buf
                .get_or_insert_with(bytes::BytesMut::new);
            if let Some(chunk) = body.take() {
                buf.extend_from_slice(&chunk);
            }
            if end_of_stream {
                let collected = ctx.request_body_buf.take().unwrap_or_default();
                let method = session.req_header().method.as_str().to_string();
                let path = session
                    .req_header()
                    .uri
                    .path_and_query()
                    .map(|pq| pq.as_str().to_string())
                    .unwrap_or_else(|| session.req_header().uri.path().to_string());
                let result = {
                    let pipeline = reload::current_pipeline();
                    let action = ctx.origin_idx.and_then(|idx| {
                        if let Some(fwd_idx) = ctx.forward_rule_idx {
                            pipeline
                                .forward_rules
                                .get(idx)
                                .and_then(|r| r.get(fwd_idx))
                                .map(|r| &r.action)
                        } else {
                            pipeline.actions.get(idx)
                        }
                    });
                    match action {
                        Some(Action::Grpc(g)) => match g.transcoder.as_ref() {
                            Some(t) => t.transcode_request(&method, &path, &collected),
                            None => Ok(None),
                        },
                        _ => Ok(None),
                    }
                };
                match result {
                    Ok(Some(tr)) => {
                        *body = Some(Bytes::from(tr.framed_body));
                    }
                    Ok(None) => {
                        // The route vanished (config reload between phases).
                        // Reject without contacting the upstream.
                        ctx.validator_failed = Some((
                            404,
                            "{\"error\":\"no transcode route\"}".to_string(),
                            "application/json".to_string(),
                        ));
                        *body = None;
                        return Err(pingora_error::Error::explain(
                            pingora_error::ErrorType::HTTPStatus(404),
                            "no matching transcode route",
                        ));
                    }
                    Err(e) => {
                        let body_str = serde_json::json!({
                            "error": "invalid request body for gRPC transcoding",
                            "detail": e.to_string(),
                        })
                        .to_string();
                        ctx.validator_failed =
                            Some((400, body_str, "application/json".to_string()));
                        *body = None;
                        return Err(pingora_error::Error::explain(
                            pingora_error::ErrorType::HTTPStatus(400),
                            "gRPC request transcoding failed",
                        ));
                    }
                }
            }
            return Ok(());
        }

        // --- WOR-819: gRPC-Web -> native gRPC request de-framing ---
        //
        // Buffer the gRPC-Web request body and, at end_of_stream, decode
        // it into native gRPC message frames (base64-decoding the `-text`
        // variant). The upstream `:path`/method/content-type were already
        // set to the native gRPC shape in `upstream_request_filter`.
        if ctx.grpc_web_active {
            let buf = ctx
                .request_body_buf
                .get_or_insert_with(bytes::BytesMut::new);
            if let Some(chunk) = body.take() {
                buf.extend_from_slice(&chunk);
            }
            if end_of_stream {
                let collected = ctx.request_body_buf.take().unwrap_or_default();
                match sbproxy_transport::grpc::GrpcWebBridge::decode_request(
                    &collected,
                    ctx.grpc_web_text,
                ) {
                    Ok(native) => {
                        *body = Some(Bytes::from(native));
                    }
                    Err(e) => {
                        let body_str = serde_json::json!({
                            "error": "invalid gRPC-Web request frame",
                            "detail": e.to_string(),
                        })
                        .to_string();
                        ctx.validator_failed =
                            Some((400, body_str, "application/json".to_string()));
                        *body = None;
                        return Err(pingora_error::Error::explain(
                            pingora_error::ErrorType::HTTPStatus(400),
                            "gRPC-Web request decode failed",
                        ));
                    }
                }
            }
            return Ok(());
        }

        // --- Mirror body teeing ---
        //
        // When a mirror is pending and `mirror_body: true`, we need
        // to capture the inbound body for the shadow request. We
        // share the same scratch buffer with the request validator
        // so configs that use both don't double-buffer; the body
        // still streams to the upstream chunk-by-chunk in that case
        // because the validator sets `validate_request_body` which
        // triggers the buffer-then-release dance below.
        let need_mirror_body = ctx
            .mirror_pending
            .as_ref()
            .map(|m| m.mirror_body)
            .unwrap_or(false);
        if need_mirror_body && !ctx.validate_request_body {
            // Mirror-only buffering: keep a copy alongside the
            // upstream stream rather than holding the upstream back.
            let max = ctx
                .mirror_pending
                .as_ref()
                .map(|m| m.max_body_bytes)
                .unwrap_or(0);
            if let Some(chunk) = body.as_ref() {
                let buf = ctx
                    .request_body_buf
                    .get_or_insert_with(bytes::BytesMut::new);
                if buf.len() + chunk.len() <= max {
                    buf.extend_from_slice(chunk);
                } else {
                    // Body exceeded cap; abandon the buffer so the
                    // mirror fires without a body.
                    ctx.request_body_buf = None;
                    if let Some(m) = ctx.mirror_pending.as_mut() {
                        m.mirror_body = false;
                    }
                }
            }
            if end_of_stream {
                fire_pending_mirror(ctx);
            }
            // Pass the chunk through to the upstream untouched.
        }

        // --- Accumulate body for the request validator ---
        //
        // While `validate_request_body` is set we buffer every chunk
        // locally and emit `None` to Pingora, so the upstream does
        // not see a partial body until validation passes. On
        // end-of-stream we run all matching `RequestValidator`
        // policies; on success we release the buffered bytes as a
        // single chunk to the upstream. On failure we record a
        // status + body for the response phase, signal the validator
        // failure via `validator_failed`, and emit `None` so the
        // upstream is not contacted.
        if ctx.validate_request_body {
            let buf = ctx
                .request_body_buf
                .get_or_insert_with(bytes::BytesMut::new);
            if let Some(chunk) = body.take() {
                buf.extend_from_slice(&chunk);
            }
            if end_of_stream {
                let collected = ctx.request_body_buf.take().unwrap_or_default();
                let pipeline = reload::current_pipeline();
                let content_type = session
                    .req_header()
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let mut failed: Option<(u16, String, String)> = None;
                if let Some(origin_idx) = ctx.origin_idx {
                    if let Some(policies) = pipeline.policies.get(origin_idx) {
                        for policy in policies {
                            match policy {
                                Policy::RequestValidator(rv) => {
                                    if !rv.applies_to(content_type.as_deref()) {
                                        continue;
                                    }
                                    if let Err(msg) = rv.validate(&collected) {
                                        let body_str = rv.error_body.clone().unwrap_or_else(|| {
                                            serde_json::json!({
                                                "error": "request body validation failed",
                                                "detail": msg,
                                            })
                                            .to_string()
                                        });
                                        failed = Some((
                                            rv.status,
                                            body_str,
                                            rv.error_content_type.clone(),
                                        ));
                                        break;
                                    }
                                }
                                Policy::ContentDigest(cd) => {
                                    // WOR-805: verify inbound RFC 9530
                                    // `Content-Digest` against the
                                    // buffered request body. IMPORTANT:
                                    // this arm runs BEFORE any
                                    // request-body modifier
                                    // (transcoders, body modifiers).
                                    // The digest applies to the
                                    // pre-transform bytes, so the
                                    // ordering must not be swapped.
                                    if collected.len() > cd.max_body_bytes {
                                        // Mirror the request_limit
                                        // pattern: reject 413 the
                                        // moment the cap is exceeded.
                                        let body_str = serde_json::json!({
                                            "error": "request body exceeds content_digest max_body_bytes",
                                            "detail": format!(
                                                "body length {} > cap {}",
                                                collected.len(),
                                                cd.max_body_bytes
                                            ),
                                        })
                                        .to_string();
                                        failed =
                                            Some((413, body_str, "application/json".to_string()));
                                        break;
                                    }
                                    // WOR-805 PR2: try `Content-Digest`
                                    // first, fall back to `Repr-Digest`
                                    // per RFC 9530 §2. For inbound
                                    // requests where we do not decode
                                    // `Content-Encoding`, the two
                                    // headers carry equivalent
                                    // semantics; we honour whichever
                                    // the client sent. `Content-Digest`
                                    // wins on a tie since clients that
                                    // know to set both prefer it.
                                    let req_headers = &session.req_header().headers;
                                    let header_value = req_headers
                                        .get("content-digest")
                                        .or_else(|| req_headers.get("repr-digest"))
                                        .and_then(|v| v.to_str().ok());
                                    let outcome = cd.verify(header_value, &collected);
                                    // WOR-805 PR2: on a verified body,
                                    // stamp the audit flag so the
                                    // Message Signatures composition
                                    // check can attest "body matches
                                    // signed digest" without re-hashing
                                    // the body.
                                    if matches!(
                                        outcome,
                                        sbproxy_modules::ContentDigestVerifyOutcome::Verified
                                    ) {
                                        ctx.content_digest_verified = true;
                                    }
                                    if let Some(envelope) = cd.rejection_envelope(outcome) {
                                        failed = Some(envelope);
                                        break;
                                    }
                                }
                                Policy::OpenApiValidation(oa) => {
                                    use sbproxy_modules::{
                                        OpenApiValidationMode, OpenApiValidationResult,
                                    };
                                    let req = session.req_header();
                                    let method = req.method.as_str();
                                    let path = req.uri.path();
                                    match oa.validate(
                                        method,
                                        path,
                                        content_type.as_deref(),
                                        &collected,
                                    ) {
                                        OpenApiValidationResult::Failed(msg) => match oa.mode {
                                            OpenApiValidationMode::Enforce => {
                                                let body_str =
                                                    oa.error_body.clone().unwrap_or_else(|| {
                                                        serde_json::json!({
                                                            "error": "openapi validation failed",
                                                            "detail": msg,
                                                        })
                                                        .to_string()
                                                    });
                                                failed = Some((
                                                    oa.status,
                                                    body_str,
                                                    oa.error_content_type.clone(),
                                                ));
                                                break;
                                            }
                                            OpenApiValidationMode::Log => {
                                                tracing::warn!(
                                                    target: "sbproxy::openapi_validation",
                                                    detail = %msg,
                                                    "openapi validation failed (log mode)"
                                                );
                                            }
                                        },
                                        OpenApiValidationResult::Passed
                                        | OpenApiValidationResult::OutOfScope => {}
                                    }
                                }
                                Policy::PromptInjectionV2(p) => {
                                    // WOR-801: body-aware scan. The URI +
                                    // headers were scanned synchronously by
                                    // the request_filter enforcer; here we
                                    // scan the buffered request body. Block
                                    // mode rejects the request; tag/log are
                                    // advisory at this phase (the upstream
                                    // request was already stamped, so a
                                    // body-only hit cannot apply a trust
                                    // header).
                                    use sbproxy_modules::{
                                        PromptInjectionAction, PromptInjectionV2Outcome,
                                    };
                                    let body_text = String::from_utf8_lossy(&collected);
                                    if let PromptInjectionV2Outcome::Hit { result } =
                                        p.evaluate(&body_text)
                                    {
                                        match p.action() {
                                            PromptInjectionAction::Block => {
                                                tracing::warn!(
                                                    target: "sbproxy::prompt_injection_v2",
                                                    score = %result.score,
                                                    label = %result.label,
                                                    "blocked: detector matched request body"
                                                );
                                                failed = Some((
                                                    403,
                                                    p.block_body().to_string(),
                                                    "text/plain; charset=utf-8".to_string(),
                                                ));
                                                break;
                                            }
                                            PromptInjectionAction::Tag
                                            | PromptInjectionAction::Log => {
                                                tracing::warn!(
                                                    target: "sbproxy::prompt_injection_v2",
                                                    score = %result.score,
                                                    label = %result.label,
                                                    "prompt injection detected in request body \
                                                     (advisory; upstream already dispatched)"
                                                );
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                if let Some((status, body_str, ct)) = failed {
                    debug!(status = %status, "request body validator rejected");
                    ctx.validator_failed = Some((status, body_str, ct));
                    // Returning an error sends Pingora into
                    // fail_to_proxy, where we synthesise the typed
                    // rejection response. We never contact the
                    // upstream.
                    return Err(pingora_error::Error::explain(
                        pingora_error::ErrorType::HTTPStatus(status),
                        "request body failed schema validation",
                    ));
                }
                // WOR-805 F1.6.1: the auth phase flagged that
                // `bot_auth` verified a signature covering
                // `content-digest`, so the body's actual SHA-256 has
                // to match the `Content-Digest` header value the
                // signature attests to. Run the deferred check now
                // that the body is fully buffered. A failure here is
                // an authentication failure (the body the client
                // sent does not match the body the client signed),
                // so map it to 401 with a generic message.
                if ctx.bot_auth_digest_check_required {
                    let header_value = session
                        .req_header()
                        .headers
                        .get("content-digest")
                        .or_else(|| session.req_header().headers.get("repr-digest"))
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());
                    let ok = match header_value.as_deref() {
                        Some(hv) => {
                            sbproxy_middleware::digest::verify_content_digest(hv, &collected)
                        }
                        // A signature that covered `content-digest`
                        // without a corresponding header is a wire-
                        // shape contradiction; reject.
                        None => false,
                    };
                    if !ok {
                        debug!(
                            "bot_auth content-digest body binding check failed; rejecting request"
                        );
                        let body_str = serde_json::json!({
                            "error": "bot_auth: content-digest body mismatch",
                        })
                        .to_string();
                        ctx.validator_failed = Some((401, body_str, "application/json".into()));
                        return Err(pingora_error::Error::explain(
                            pingora_error::ErrorType::HTTPStatus(401),
                            "bot_auth: content-digest body binding failed",
                        ));
                    }
                    // Mirror the content_digest-policy path: surface
                    // a single audit flag so downstream composition
                    // can attest "body matches signed digest".
                    ctx.content_digest_verified = true;
                }
                // Validation passed - release the buffered body as one
                // chunk so the upstream sees the full payload.
                let frozen = if !collected.is_empty() {
                    let bytes = collected.freeze();
                    *body = Some(bytes.clone());
                    Some(bytes)
                } else {
                    None
                };
                // Tee to the mirror if requested (validator + mirror
                // configs share the buffer so we don't pay for it twice).
                //
                // WOR-168: previously this path called
                // `ctx.mirror_pending.take().unwrap()` after we had just
                // matched the slot via `as_mut()`. Under normal control
                // flow the slot is always `Some` here, but a future
                // refactor (or a panic in another task that observed
                // `&mut RequestContext`) could clear it between the
                // match and the take. We now bump
                // `sbproxy_mirror_state_drift_total` and skip firing the
                // mirror rather than panicking the worker.
                let want_body_mirror = ctx
                    .mirror_pending
                    .as_ref()
                    .map(|m| m.mirror_body)
                    .unwrap_or(false);
                if want_body_mirror {
                    if let Some(params) = ctx.mirror_pending.take() {
                        let body_for_mirror = frozen
                            .as_ref()
                            .filter(|b| b.len() <= params.max_body_bytes)
                            .cloned();
                        tokio::spawn(async move {
                            fire_request_mirror(
                                params.url,
                                params.timeout,
                                params.method,
                                params.path_and_query,
                                params.headers,
                                params.request_id,
                                body_for_mirror,
                            )
                            .await;
                        });
                    } else {
                        sbproxy_observe::metrics::record_mirror_state_drift();
                        tracing::warn!(
                            target: "sbproxy::mirror",
                            "mirror_pending unexpectedly empty when firing body mirror"
                        );
                    }
                }
            }
            // Mid-stream chunks: hold off forwarding until end_of_stream.
            return Ok(());
        }

        // --- Idempotency cache-miss body capture ---
        //
        // `request_filter` set `ctx.idempotency_buffering = true`
        // when the cache key-lookup found no entry (definite miss).
        // The body flows through Pingora normally to the upstream;
        // we just tee it into a local buffer so the response side
        // can pair the request body hash with the captured response
        // and call `record_response` for future retries.
        //
        // Cache hits and conflicts are handled in `request_filter`
        // before this filter runs; on those paths we already drained
        // the body and short-circuited the response.
        if ctx.idempotency_buffering {
            // Streaming-oversize guard: when content-length lied or
            // was absent, the buffer may grow past the cap. Abandon
            // caching for that request and stamp the skip marker;
            // chunks continue flowing through to the upstream
            // untouched.
            let max_req_bytes = {
                let pipeline = reload::current_pipeline();
                ctx.origin_idx
                    .and_then(|i| pipeline.idempotencies.get(i))
                    .and_then(|opt| opt.as_ref())
                    .map(|i| i.max_request_body_bytes)
                    .unwrap_or(usize::MAX)
            };
            let buf = ctx
                .request_body_buf
                .get_or_insert_with(bytes::BytesMut::new);
            let incoming = body.as_ref().map(|c| c.len()).unwrap_or(0);
            if buf.len().saturating_add(incoming) > max_req_bytes {
                // Disengage; the buffer is incomplete so we can't
                // hash, but the upstream still gets the chunks.
                ctx.idempotency_buffering = false;
                ctx.request_body_buf = None;
                ctx.idempotency_permit = None;
                ctx.idempotency_skip_reason = Some("SKIPPED-OVERSIZE-REQUEST");
                return Ok(());
            }
            if let Some(chunk) = body.as_ref() {
                buf.extend_from_slice(chunk);
            }
            if end_of_stream {
                let collected = ctx.request_body_buf.take().unwrap_or_default();
                let body_hash = sbproxy_middleware::idempotency::hash_body(&collected);
                let header_name = {
                    let pipeline = reload::current_pipeline();
                    ctx.origin_idx
                        .and_then(|i| pipeline.idempotencies.get(i))
                        .and_then(|opt| opt.as_ref())
                        .map(|i| i.header_name.clone())
                        .unwrap_or_else(|| "Idempotency-Key".to_string())
                };
                let key = session
                    .req_header()
                    .headers
                    .get(header_name.as_str())
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                ctx.idempotency_miss = Some((key, body_hash));
                ctx.idempotency_response_body_buf = Some(bytes::BytesMut::with_capacity(8192));
            }
            // Pass the chunk through to upstream unchanged.
            return Ok(());
        }

        // Mirror that doesn't need the body (mirror_body: false) -
        // fire on first body filter call so the shadow request is
        // not delayed by an upload it doesn't care about.
        //
        // WOR-168: same drift handling as the body-mirror branch above;
        // bump the state-drift counter instead of panicking if the slot
        // was cleared between the `as_ref` check and the `take`.
        if end_of_stream {
            let want_bodyless_mirror = ctx
                .mirror_pending
                .as_ref()
                .map(|m| !m.mirror_body)
                .unwrap_or(false);
            if want_bodyless_mirror {
                if let Some(params) = ctx.mirror_pending.take() {
                    tokio::spawn(async move {
                        fire_request_mirror(
                            params.url,
                            params.timeout,
                            params.method,
                            params.path_and_query,
                            params.headers,
                            params.request_id,
                            None,
                        )
                        .await;
                    });
                } else {
                    sbproxy_observe::metrics::record_mirror_state_drift();
                    tracing::warn!(
                        target: "sbproxy::mirror",
                        "mirror_pending unexpectedly empty when firing bodyless mirror"
                    );
                }
            }
        }

        if let Some(replacement) = ctx.replacement_request_body.take() {
            *body = Some(replacement);
        }
        Ok(())
    }

    /// Buffer upstream response body chunks and apply transforms on end-of-stream.
    ///
    /// When an origin has transforms configured, this method buffers all body
    /// chunks until the full response is received. Once complete, it runs each
    /// transform in sequence over the buffered body and emits the result as
    /// a single chunk. For origins without transforms, this is a no-op pass-through.
    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>>
    where
        Self::CTX: Send + Sync,
    {
        // Track outbound body bytes for the access log. Counts what
        // the client receives, including transformed / fallback /
        // cached bodies, since those are what downstream egress
        // billing and abuse models care about.
        if let Some(chunk) = body.as_ref() {
            ctx.response_body_bytes = ctx.response_body_bytes.saturating_add(chunk.len() as u64);
        }

        // --- WOR-819: gRPC -> REST/JSON response body transcoding ---
        //
        // Buffer the upstream gRPC response frame. Emission is split
        // between this filter and `response_trailer_filter` so the
        // real `grpc-status` (which gRPC normally puts in trailers,
        // arriving after the body) reaches the JSON envelope:
        //
        // * Trailers-only error response: `response_filter` captured
        //   `grpc-status` from the response headers (no separate
        //   trailer phase will fire). Emit the JSON envelope here at
        //   `end_of_stream` while the buffer is in hand.
        // * Normal response (success, or post-body trailers-only
        //   error): leave the buffer alone. `response_trailer_filter`
        //   reads the real `grpc-status` from the trailers and
        //   produces the JSON via the same `transcode_response` call.
        //
        // Suppress every chunk from going downstream while buffering:
        // the response body sent to the client is the JSON envelope,
        // not the raw gRPC frame.
        if ctx.transcode_active {
            if ctx.transcode_response_emitted {
                *body = None;
                return Ok(None);
            }
            if let Some(chunk) = body.take() {
                ctx.transcode_response_buf
                    .get_or_insert_with(bytes::BytesMut::new)
                    .extend_from_slice(&chunk);
            }
            if end_of_stream && ctx.transcode_grpc_status.is_some() {
                // Trailers-only path: emit JSON now using the status
                // captured from headers.
                let frame = ctx.transcode_response_buf.take().unwrap_or_default();
                let json = build_transcoded_json(ctx, &frame);
                ctx.transcode_response_emitted = true;
                *body = Some(Bytes::from(json));
            } else {
                *body = None;
            }
            return Ok(None);
        }

        // --- WOR-819: gRPC -> gRPC-Web response re-framing ---
        //
        // The bridge supports unary (one message frame) and
        // server-streaming (many message frames) calls, plus a final
        // trailer frame carrying `grpc-status`. The two text/binary
        // variants take different paths:
        //
        // * Binary (`application/grpc-web+proto`): stream each complete
        //   message frame downstream as soon as it is buffered. The
        //   trailer frame is emitted by `response_trailer_filter` (real
        //   trailers) or here at `end_of_stream` (trailers-only error,
        //   status already captured by `response_filter` from headers).
        // * Text (`application/grpc-web-text`): the whole body is a
        //   single base64 string, so we cannot stream chunks (base64
        //   has 3-byte alignment). Buffer everything; emit the full
        //   message-frames+trailer-frame block at `end_of_stream` for
        //   trailers-only responses, or in `response_trailer_filter`
        //   otherwise.
        //
        // gRPC-over-h2 typically sends the response DATA frame without
        // `END_STREAM` (the trailers carry `grpc-status` and set
        // END_STREAM themselves). The body filter still receives an
        // `end_of_stream` call when the upstream finishes sending body
        // bytes; whether trailers will follow is signalled by the
        // presence of `grpc-status` in `ctx.transcode_grpc_status`
        // (`response_filter` set it from headers iff trailers-only).
        if ctx.grpc_web_active {
            if ctx.grpc_web_emitted {
                *body = None;
                return Ok(None);
            }
            if let Some(chunk) = body.take() {
                ctx.grpc_web_buf
                    .get_or_insert_with(bytes::BytesMut::new)
                    .extend_from_slice(&chunk);
            }
            let trailers_only = ctx.transcode_grpc_status.is_some();
            if ctx.grpc_web_text {
                // Text variant: buffer until we know nothing more
                // is coming. On a trailers-only response there will
                // be no separate trailer phase, so emit here. The
                // common success / trailer-driven path is handled by
                // `response_trailer_filter`, which leaves the buffer
                // for itself.
                if end_of_stream && trailers_only {
                    let frames = ctx.grpc_web_buf.take().unwrap_or_default();
                    let trailers = sbproxy_transport::grpc::GrpcTrailers {
                        status: ctx.transcode_grpc_status.unwrap_or(0),
                        message: ctx.transcode_grpc_message.clone(),
                    };
                    let encoded = sbproxy_transport::grpc::GrpcWebBridge::encode_response(
                        &frames, &trailers, true,
                    );
                    ctx.grpc_web_emitted = true;
                    *body = Some(Bytes::from(encoded));
                } else {
                    *body = None;
                }
                return Ok(None);
            }
            // Binary variant: drain every complete frame from the
            // buffer and forward it. A frame is 1 compression byte +
            // 4 length bytes + N message bytes. Partial frames stay
            // in the buffer for the next chunk.
            let mut out = bytes::BytesMut::new();
            if let Some(buf) = ctx.grpc_web_buf.as_mut() {
                loop {
                    if buf.len() < 5 {
                        break;
                    }
                    let msg_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
                    let frame_end = 5 + msg_len;
                    if buf.len() < frame_end {
                        break;
                    }
                    let frame = buf.split_to(frame_end);
                    out.extend_from_slice(&frame);
                }
            }
            if end_of_stream && trailers_only {
                // No separate trailer phase will fire, so append the
                // trailer frame here. The remaining buffer (if any
                // unaligned trailing bytes) is dropped: the upstream
                // sent half a frame on a trailers-only response,
                // which is malformed.
                let trailers = sbproxy_transport::grpc::GrpcTrailers {
                    status: ctx.transcode_grpc_status.unwrap_or(0),
                    message: ctx.transcode_grpc_message.clone(),
                };
                out.extend_from_slice(&sbproxy_transport::grpc::web::encode_trailer_frame_only(
                    &trailers,
                ));
                ctx.grpc_web_emitted = true;
                ctx.grpc_web_buf = None;
            }
            *body = if out.is_empty() {
                None
            } else {
                Some(out.freeze())
            };
            return Ok(None);
        }

        // --- WOR-808 PR5: RSL <link rel="license"> HTML injection ---
        //
        // When `response_filter` armed this path (HTML response on a
        // hostname with an RSL `/licenses.xml` projection), buffer the
        // body and inject the `<link>` tag into the `<head>` once at
        // end_of_stream. The injection helper is a no-op when the
        // body already carries a license-rel link or has no parseable
        // `<head>`, so a re-proxied page is not double-tagged.
        if ctx.rsl_inject_link_pending {
            if ctx.rsl_inject_link_emitted {
                *body = None;
                return Ok(None);
            }
            if let Some(chunk) = body.take() {
                ctx.rsl_inject_link_buf
                    .get_or_insert_with(bytes::BytesMut::new)
                    .extend_from_slice(&chunk);
            }
            if end_of_stream {
                let buf = ctx.rsl_inject_link_buf.take().unwrap_or_default();
                let injected = match ctx.rsl_inject_link_feed {
                    Some(format) => sbproxy_modules::projections::inject_license_link_xml(
                        &buf,
                        "/licenses.xml",
                        format,
                    ),
                    None => {
                        sbproxy_modules::projections::inject_license_link(&buf, "/licenses.xml")
                    }
                };
                ctx.rsl_inject_link_emitted = true;
                *body = Some(Bytes::from(injected));
            } else {
                *body = None;
            }
            return Ok(None);
        }

        // --- Response cache: accumulate body chunks ---
        //
        // When request_filter decided the response is cacheable and
        // response_filter confirmed the status is in the cacheable set,
        // `ctx.cache_body_buf` is Some. Append every outgoing chunk (we see
        // the original upstream body here, before transforms below), then
        // on end_of_stream hand the full body off to the store via
        // `tokio::spawn`. The write is best-effort; failures are logged but
        // don't affect the response we deliver to the client.
        if ctx.cache_body_buf.is_some() {
            if let Some(chunk) = body.as_ref() {
                if let Some(buf) = &mut ctx.cache_body_buf {
                    buf.extend_from_slice(chunk);
                }
            }
            if end_of_stream {
                let key = ctx.cache_key.take();
                let body_buf = ctx.cache_body_buf.take();
                let status = ctx.cache_status.take();
                let headers = ctx.cache_headers.take();
                if let (Some(key), Some(body_buf), Some(status), Some(headers)) =
                    (key, body_buf, status, headers)
                {
                    let ttl = {
                        let pipeline_guard = reload::current_pipeline();
                        ctx.origin_idx
                            .and_then(|idx| pipeline_guard.config.origins.get(idx))
                            .and_then(|o| o.response_cache.as_ref())
                            .map(|c| c.ttl_secs)
                            .unwrap_or(300)
                    };
                    let pipeline_for_write = reload::current_pipeline();
                    if let Some(cache_store) = pipeline_for_write.cache_store.clone() {
                        let entry = sbproxy_cache::CachedResponse {
                            status,
                            headers,
                            body: body_buf.to_vec(),
                            cached_at: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                            ttl_secs: ttl,
                        };
                        // --- Cache Reserve admission ---
                        // Mirror into the cold tier subject to the
                        // configured admission filter. The reserve
                        // write fires before the hot-cache write moves
                        // `entry` so we don't have to round-trip
                        // through serde to clone it.
                        if let (Some(reserve), Some(admission)) = (
                            pipeline_for_write.cache_reserve.clone(),
                            pipeline_for_write.cache_reserve_admission,
                        ) {
                            let origin_id_for_reserve = ctx
                                .origin_idx
                                .and_then(|idx| pipeline_for_write.config.origins.get(idx))
                                .map(|o| o.origin_id.to_string())
                                .unwrap_or_default();
                            maybe_admit_to_reserve(
                                reserve,
                                admission,
                                key.clone(),
                                &entry,
                                origin_id_for_reserve,
                            );
                        }
                        // Dispatch the actual write in a blocking task so the
                        // Redis TCP I/O doesn't run on the reactor thread.
                        tokio::task::spawn_blocking(move || {
                            if let Err(e) = cache_store.put(&key, &entry) {
                                tracing::warn!(error = %e, "cache write failed");
                            }
                        });
                    }
                }
            }
        }

        // --- Idempotency cache-miss body capture ---
        //
        // When `request_body_filter` set `ctx.idempotency_miss`, the
        // upstream response is destined for the cache. Accumulate
        // every chunk passing through here; at `end_of_stream` pair
        // the body with the status / headers snapshotted by
        // `response_filter` and call `record_response`. The capture
        // is best-effort: a missing piece (status, headers, or buffer)
        // simply skips the write rather than holding up the response.
        if ctx.idempotency_response_body_buf.is_some() {
            // Response-size cap: when the upstream response grows
            // past `max_response_body_bytes` we abandon caching for
            // this request rather than buffering unbounded memory.
            // The chunk flows through to the client untouched; the
            // marker on the response tells operators we couldn't
            // cache it.
            let max_resp_bytes = {
                let pipeline = reload::current_pipeline();
                ctx.origin_idx
                    .and_then(|i| pipeline.idempotencies.get(i))
                    .and_then(|opt| opt.as_ref())
                    .map(|i| i.max_response_body_bytes)
                    .unwrap_or(usize::MAX)
            };
            if let Some(chunk) = body.as_ref() {
                if let Some(buf) = ctx.idempotency_response_body_buf.as_mut() {
                    if buf.len().saturating_add(chunk.len()) > max_resp_bytes {
                        // Drop the capture buffer; future chunks
                        // stream through unbuffered.
                        ctx.idempotency_response_body_buf = None;
                        ctx.idempotency_miss = None;
                        ctx.idempotency_response_status = None;
                        ctx.idempotency_response_headers = None;
                        ctx.idempotency_skip_reason = Some("SKIPPED-OVERSIZE-RESPONSE");
                        // Note: the header was already flushed to the
                        // client at this point so the skip marker is
                        // best-effort visible only via logs / events.
                        // Tracked as an enhancement; for now we still
                        // mark ctx so the request log captures the
                        // reason.
                    } else {
                        buf.extend_from_slice(chunk);
                    }
                }
            }
            if end_of_stream {
                if let Some((key, body_hash)) = ctx.idempotency_miss.take() {
                    let buf = ctx.idempotency_response_body_buf.take();
                    let status = ctx.idempotency_response_status.take();
                    let headers = ctx.idempotency_response_headers.take();
                    let workspace = ctx.idempotency_workspace.clone().unwrap_or_default();
                    if let (Some(buf), Some(status), Some(headers)) = (buf, status, headers) {
                        let pipeline = reload::current_pipeline();
                        if let Some(idem) = ctx
                            .origin_idx
                            .and_then(|i| pipeline.idempotencies.get(i))
                            .and_then(|opt| opt.as_ref())
                        {
                            sbproxy_middleware::idempotency::record_response(
                                idem.cache.as_ref(),
                                &workspace,
                                &key,
                                sbproxy_middleware::idempotency::RecordedResponse {
                                    status,
                                    headers,
                                    body: buf.to_vec(),
                                    body_hash,
                                    ttl_secs: idem.ttl_secs,
                                },
                            );
                        }
                    }
                }
            }
        }

        // If a fallback body was prepared (on_status fallback), replace the upstream body.
        if let Some(fb_body) = ctx.fallback_body.take() {
            *body = Some(fb_body);
            return Ok(None);
        }

        // If a response modifier specified a body replacement, swap it in.
        if let Some(replacement) = ctx.response_body_replacement.take() {
            *body = Some(replacement);
            return Ok(None);
        }

        let pipeline = reload::current_pipeline();
        let has_transforms = ctx
            .origin_idx
            .map(|i| i < pipeline.transforms.len() && !pipeline.transforms[i].is_empty())
            .unwrap_or(false);
        let has_compression = ctx.compression_encoding.is_some();

        // Pass through when there is nothing buffered-body-shaped to do.
        if !has_transforms && !ctx.sri_scan_enabled && !has_compression {
            return Ok(None);
        }

        // origin_idx is always Some past this point because at least one
        // pipeline-driven path (transforms, SRI scan, or compression) is active.
        let origin_idx = match ctx.origin_idx {
            Some(idx) => idx,
            None => return Ok(None),
        };

        // Start buffering on the first chunk.
        if !ctx.buffering_body {
            ctx.buffering_body = true;
            ctx.response_body_buf = Some(bytes::BytesMut::with_capacity(8192));
        }

        // Accumulate this chunk into the buffer.
        if let Some(chunk) = body.take() {
            if let Some(buf) = &mut ctx.response_body_buf {
                // Enforce the largest max_body_size across all transforms,
                // falling back to a 10 MiB default for SRI-only buffering
                // on origins that have no transforms attached.
                let max_size = if has_transforms {
                    pipeline.transforms[origin_idx]
                        .iter()
                        .map(|t| t.max_body_size)
                        .max()
                        .unwrap_or(10 * 1024 * 1024)
                } else {
                    10 * 1024 * 1024
                };
                if buf.len() + chunk.len() > max_size {
                    warn!(
                        hostname = %ctx.hostname,
                        buffered = buf.len(),
                        chunk = chunk.len(),
                        max = max_size,
                        "response body buffer exceeded max_body_size, passing through unmodified"
                    );
                    // Flush the buffer plus this chunk as-is and stop buffering.
                    let combined = buf.split().freeze();
                    let mut out = bytes::BytesMut::with_capacity(combined.len() + chunk.len());
                    out.extend_from_slice(&combined);
                    out.extend_from_slice(&chunk);
                    *body = Some(out.freeze());
                    ctx.response_body_buf = None;
                    ctx.buffering_body = false;
                    return Ok(None);
                }
                buf.extend_from_slice(&chunk);
            }
        }

        if end_of_stream {
            // All body received - apply transforms in sequence (when any),
            // then run the SRI scanner (when enabled) on the final body.
            if let Some(mut buf) = ctx.response_body_buf.take() {
                // Copy upstream_content_type out of ctx so the typed
                // transform helpers can mutate ctx without an aliasing
                // conflict.
                let content_type_owned: Option<String> = ctx.upstream_content_type.clone();
                let content_type = content_type_owned.as_deref();

                if has_transforms {
                    let ratio =
                        resolved_token_bytes_ratio(Some(&pipeline.config.origins[origin_idx]));
                    for compiled_transform in &pipeline.transforms[origin_idx] {
                        // For transforms that need a markdown
                        // projection (`citation_block`, `json_envelope`)
                        // synthesise one from the body bytes when the
                        // upstream didn't go through HtmlToMarkdown
                        // (e.g. upstream already returned Markdown).
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
                            // WOR-168: a `TransformError::InvariantViolated`
                            // or `TransformError::Plugin` is a code-level
                            // bug or a misbehaving plugin; both must
                            // surface as a 500 regardless of
                            // `fail_on_error`. The transform name flows
                            // onto the response as
                            // `x-sbproxy-transform-error` so the caller
                            // and operator can correlate.
                            let transform_name = compiled_transform.transform.transform_type();
                            let is_typed_transform_error = e
                                .downcast_ref::<sbproxy_modules::transform::TransformError>()
                                .is_some();
                            if is_typed_transform_error {
                                tracing::error!(
                                    hostname = %ctx.hostname,
                                    transform = transform_name,
                                    error = %e,
                                    "transform pipeline invariant violated, returning 500 with attribution"
                                );
                                ctx.response_status_override = Some(500);
                                ctx.transform_error_attribution = Some(transform_name.to_string());
                                buf.clear();
                                buf.extend_from_slice(b"{\"error\":\"internal server error\"}");
                                break;
                            }
                            if compiled_transform.fail_on_error {
                                warn!(
                                    hostname = %ctx.hostname,
                                    transform = transform_name,
                                    error = %e,
                                    "transform failed (fail_on_error=true), sending error"
                                );
                                // Replace body with generic error. Internal details are
                                // logged above but never sent to the client.
                                buf.clear();
                                buf.extend_from_slice(b"{\"error\":\"internal server error\"}");
                                break;
                            }
                            warn!(
                                hostname = %ctx.hostname,
                                transform = transform_name,
                                error = %e,
                                "transform failed, continuing with next transform"
                            );
                        }
                    }
                }

                // SRI scan runs after transforms so it sees the same
                // bytes that go to the client. Observation only: the
                // scanner logs each violation and bumps a metric but
                // does not modify the response body or headers.
                if ctx.sri_scan_enabled {
                    let ct = content_type.unwrap_or("");
                    for policy in &pipeline.policies[origin_idx] {
                        if let sbproxy_modules::Policy::Sri(s) = policy {
                            match s.check_html_body(&buf, ct) {
                                sbproxy_modules::SriCheckResult::Violations(v) => {
                                    for violation in &v {
                                        warn!(
                                            hostname = %ctx.hostname,
                                            tag = %violation.tag,
                                            url = %violation.url,
                                            reason = ?violation.reason,
                                            "sri: subresource missing or weak integrity attribute"
                                        );
                                    }
                                    sbproxy_observe::metrics::record_policy(
                                        &ctx.hostname,
                                        "sri",
                                        "violation",
                                    );
                                }
                                sbproxy_modules::SriCheckResult::Clean => {
                                    sbproxy_observe::metrics::record_policy(
                                        &ctx.hostname,
                                        "sri",
                                        "clean",
                                    );
                                }
                                sbproxy_modules::SriCheckResult::NotApplicable => {}
                            }
                        }
                    }
                }

                // --- Response compression (final body step) ---
                //
                // Runs after transforms + SRI so we compress exactly the bytes
                // the client receives. The `min_size` floor is re-checked here
                // because chunked upstreams skipped the floor in
                // `response_filter` (we did not know the body size yet) and
                // because transforms can shrink or grow the payload. When the
                // final body is below `min_size` the encoder is bypassed and
                // the body passes through; the `Content-Encoding` header was
                // already set in `response_filter`, so we do not flip it back
                // to identity from here. The floor is a CPU optimisation,
                // not a correctness requirement.
                if let Some(encoding) = ctx.compression_encoding.take() {
                    if buf.len() >= ctx.compression_min_size {
                        match sbproxy_middleware::compression::compress_body(&buf[..], encoding) {
                            Ok(compressed) => {
                                buf.clear();
                                buf.extend_from_slice(&compressed);
                            }
                            Err(e) => {
                                warn!(
                                    hostname = %ctx.hostname,
                                    encoding = %encoding.as_str(),
                                    error = %e,
                                    "response compression failed, sending uncompressed body"
                                );
                            }
                        }
                    }
                }

                *body = Some(buf.freeze());
            }
            ctx.buffering_body = false;
        } else {
            // Suppress this chunk from being sent downstream while buffering.
            *body = None;
        }

        Ok(None)
    }

    /// WOR-819: handle real HTTP/2 response trailers for the gRPC
    /// transcoding and gRPC-Web bridge paths. gRPC normally carries
    /// `grpc-status` and `grpc-message` in the trailers (the headers
    /// hold them only in trailers-only error responses, which
    /// `response_filter` already captured). This filter:
    ///
    /// * Reads the real `grpc-status` / `grpc-message` into `ctx`.
    /// * For the transcode path, emits the JSON envelope here when
    ///   `response_body_filter` deferred it. The returned `Bytes`
    ///   become the final body chunk before the framework writes
    ///   trailers downstream.
    /// * For the gRPC-Web binary path, emits the trailer frame so
    ///   browser clients see the end-of-stream marker even after a
    ///   streaming response. The text variant flushes the entire
    ///   base64 block here for the same reason.
    /// * Strips `grpc-status` / `grpc-message` from the downstream
    ///   trailers in either case: the value is now folded into the
    ///   body (JSON for transcode, trailer frame for gRPC-Web) and
    ///   forwarding the original trailer would confuse the client.
    async fn response_trailer_filter(
        &self,
        _session: &mut Session,
        upstream_trailers: &mut http::HeaderMap,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Bytes>>
    where
        Self::CTX: Send + Sync,
    {
        if !ctx.transcode_active && !ctx.grpc_web_active {
            return Ok(None);
        }
        // Real-trailer grpc-status wins over anything previously
        // captured (the header-borne value was a header-spoofed
        // synthesis; trailers are the canonical source).
        if let Some(status) = upstream_trailers
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<i32>().ok())
        {
            ctx.transcode_grpc_status = Some(status);
        }
        if let Some(msg) = upstream_trailers
            .get("grpc-message")
            .and_then(|v| v.to_str().ok())
        {
            ctx.transcode_grpc_message = Some(msg.to_string());
        }
        // The trailer value is folded into the body now; drop the
        // raw `grpc-status` / `grpc-message` so the downstream client
        // does not see contradictory signals.
        upstream_trailers.remove("grpc-status");
        upstream_trailers.remove("grpc-message");

        if ctx.transcode_active && !ctx.transcode_response_emitted {
            let frame = ctx.transcode_response_buf.take().unwrap_or_default();
            let json = build_transcoded_json(ctx, &frame);
            ctx.transcode_response_emitted = true;
            return Ok(Some(Bytes::from(json)));
        }

        if ctx.grpc_web_active && !ctx.grpc_web_emitted {
            let trailers = sbproxy_transport::grpc::GrpcTrailers {
                status: ctx.transcode_grpc_status.unwrap_or(0),
                message: ctx.transcode_grpc_message.clone(),
            };
            ctx.grpc_web_emitted = true;
            if ctx.grpc_web_text {
                // Text variant: the message frames have been buffered
                // here (the body filter forwarded nothing for text).
                // Build message-frames + trailer-frame and base64 the
                // whole block in one shot.
                let frames = ctx.grpc_web_buf.take().unwrap_or_default();
                let encoded = sbproxy_transport::grpc::GrpcWebBridge::encode_response(
                    &frames, &trailers, true,
                );
                return Ok(Some(Bytes::from(encoded)));
            }
            // Binary variant: message frames were already streamed in
            // `response_body_filter`; append just the trailer frame.
            let trailer_frame = sbproxy_transport::grpc::web::encode_trailer_frame_only(&trailers);
            return Ok(Some(Bytes::from(trailer_frame)));
        }

        Ok(None)
    }

    /// Pingora calls this when establishing the upstream TCP/TLS
    /// connection fails. If the action has a `retry` policy that
    /// allows `connect_error` and we are still under `max_attempts`,
    /// mark the error retryable so Pingora calls `upstream_peer`
    /// again. For load_balancer actions, the failed target is
    /// reported to the outlier detector so the next selection skips
    /// it.
    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<Error>,
    ) -> Box<Error> {
        let pipeline = reload::current_pipeline();
        let Some(origin_idx) = ctx.origin_idx else {
            return e;
        };
        let action = if let Some(fwd_idx) = ctx.forward_rule_idx {
            pipeline
                .forward_rules
                .get(origin_idx)
                .and_then(|rules| rules.get(fwd_idx))
                .map(|r| &r.action)
        } else {
            pipeline.actions.get(origin_idx)
        };
        let retry_cfg = match action {
            Some(Action::Proxy(p)) => p.retry.as_ref(),
            // LB targets share the LB-level retry policy. On retry the
            // outlier ejection (recorded just below) plus per-target
            // breaker steer select_target to a different peer.
            Some(Action::LoadBalancer(lb)) => lb.retry.as_ref(),
            _ => None,
        };
        let Some(cfg) = retry_cfg else {
            return e;
        };
        if !cfg.enabled() || !cfg.allows("connect_error") {
            return e;
        }
        // ctx.retry_count == 0 on first attempt; max_attempts == 3
        // means we allow attempts 0, 1, 2.
        if ctx.retry_count + 1 >= cfg.max_attempts {
            return e;
        }
        // For LB, mark the failed target so the next select_target
        // skips it via outlier detection AND advances the breaker
        // state (a connect failure is a failure for both signals).
        if let (Some(Action::LoadBalancer(lb)), Some(idx)) =
            (pipeline.actions.get(origin_idx), ctx.lb_target_idx)
        {
            lb.record_target_failure(idx);
            lb.record_breaker_failure(idx);
        }
        ctx.retry_count += 1;
        debug!(
            attempt = %ctx.retry_count,
            max = %cfg.max_attempts,
            "upstream connect error, retrying"
        );
        e.set_retry(true);
        e
    }

    /// Handle upstream connection failures. If a fallback origin with on_error
    /// is configured, serve the fallback response instead of an error page.
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &Error,
        ctx: &mut Self::CTX,
    ) -> FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        // --- Request body validator rejection ---
        // The body filter intentionally aborted the upstream after a
        // validation failure. Surface the configured status / body
        // here rather than the generic 502.
        if let Some((status, body, content_type)) = ctx.validator_failed.take() {
            let mut header = match pingora_http::ResponseHeader::build(status, Some(2)) {
                Ok(h) => h,
                Err(_) => {
                    let _ = send_error(session, status, "validation failed").await;
                    ctx.response_status = Some(status);
                    return FailToProxy {
                        error_code: status,
                        can_reuse_downstream: true,
                    };
                }
            };
            let _ = header.insert_header("content-type", content_type);
            let _ = header.insert_header("content-length", body.len().to_string());
            let _ = session.write_response_header(Box::new(header), false).await;
            let _ = session
                .write_response_body(Some(bytes::Bytes::from(body)), true)
                .await;
            ctx.response_status = Some(status);
            return FailToProxy {
                error_code: status,
                can_reuse_downstream: true,
            };
        }

        // Check if we have a fallback with on_error configured.
        if let Some(origin_idx) = ctx.origin_idx {
            let pipeline = reload::current_pipeline();
            if let Some(fallback) = &pipeline.fallbacks[origin_idx] {
                if fallback.on_error {
                    debug!(
                        hostname = %ctx.hostname,
                        error = %e,
                        "upstream failed, serving fallback origin (on_error)"
                    );
                    ctx.fallback_triggered = true;

                    // Serve the fallback action's response directly.
                    let result = serve_fallback_action(
                        session,
                        &fallback.action,
                        fallback.add_debug_header,
                        "error",
                    )
                    .await;

                    if let Ok(status) = result {
                        ctx.response_status = Some(status);
                        return FailToProxy {
                            error_code: status,
                            can_reuse_downstream: true,
                        };
                    }
                }
            }
        }

        // --- Default upstream-error handling ---
        //
        // The fallback path didn't catch this; render a synthesised
        // error response. The status code and `Proxy-Status` `error`
        // token derive from the actual failure mode via
        // `map_upstream_failure` so dashboards consuming RFC 9209 can
        // break down by failure mode (connection_timeout vs
        // tls_protocol_error vs ...) without scraping the body.
        //
        // When the resolved origin has `proxy_status.enabled: true`,
        // stamp the structured `Proxy-Status` header. When it also
        // has `problem_details.enabled: true`, render the body as
        // `application/problem+json` per RFC 9457. Both blocks are
        // opt-in and compose with the existing proxy-generated error
        // path (auth deny, policy deny, default 404).
        let (status_code, error_token) = map_upstream_failure(e);

        // Resolve per-origin config (when an origin is set; some
        // failure modes hit before request_filter completes the
        // origin lookup).
        let request_path = session.req_header().uri.path().to_string();
        let pipeline = reload::current_pipeline();
        let origin_cfg = ctx
            .origin_idx
            .and_then(|idx| pipeline.config.origins.get(idx));
        let proxy_status_cfg = origin_cfg.and_then(|o| o.proxy_status.as_ref());
        let problem_details_cfg = origin_cfg.and_then(|o| o.problem_details.as_ref());

        // Build the response body. Problem-details wins when enabled;
        // otherwise fall back to the existing plain-text "bad
        // gateway" payload.
        let (body_bytes, content_type) = match problem_details_cfg {
            Some(pd) if pd.enabled => {
                let detail = error_token.unwrap_or("upstream request failed");
                let body = render_problem_details(status_code, detail, pd, &request_path);
                (body.into_bytes(), "application/problem+json")
            }
            _ => (b"bad gateway".to_vec(), "text/plain; charset=utf-8"),
        };

        // Build the response header. Allocate room for content-type
        // + content-length + optional proxy-status; insert_header is
        // cheap if the slot is unused.
        let header_cap = 2 + usize::from(proxy_status_cfg.is_some_and(|c| c.enabled));
        let mut header = match pingora_http::ResponseHeader::build(status_code, Some(header_cap)) {
            Ok(h) => h,
            Err(_) => {
                let _ = send_error(session, status_code, "bad gateway").await;
                ctx.response_status = Some(status_code);
                return FailToProxy {
                    error_code: status_code,
                    can_reuse_downstream: false,
                };
            }
        };
        let _ = header.insert_header("content-type", content_type);
        let _ = header.insert_header("content-length", body_bytes.len().to_string());
        if let Some(ps) = proxy_status_cfg {
            if ps.enabled {
                let identity = ps.identity.as_deref().unwrap_or("sbproxy");
                let value = sbproxy_middleware::proxy_status::build_proxy_status_with_identity(
                    identity,
                    status_code,
                    error_token,
                );
                let _ = header.insert_header("proxy-status", value);
            }
        }
        let _ = session.write_response_header(Box::new(header), false).await;
        let _ = session
            .write_response_body(Some(bytes::Bytes::from(body_bytes)), true)
            .await;
        ctx.response_status = Some(status_code);
        FailToProxy {
            error_code: status_code,
            can_reuse_downstream: false,
        }
    }

    /// End-of-request callback for metrics, events, and connection tracking.
    ///
    /// Called when the response is fully sent or on fatal error. Records
    /// request metrics, emits events, and decrements load balancer counters.
    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Self::CTX)
    where
        Self::CTX: Send + Sync,
    {
        // Decrement active connections gauge (global + per-origin).
        metrics().active_connections.dec();

        // Phase 7: AI realtime WebSocket session-close hook. When the
        // request opened a realtime session, observe duration, tick
        // the active-sessions gauge down, and emit a session-end
        // AiBillingEvent with the wall-clock duration as an
        // approximation of the audio time forwarded. Frame-exact
        // audio metering would require terminating the WebSocket
        // (not transparent forwarding); the duration approximation
        // is the right OSS-v1 substitute since the session
        // lifetime IS the audio call.
        if let Some(rd) = ctx.ai_realtime_dispatch.take() {
            let duration_secs = rd.started_at.elapsed().as_secs_f64();
            let close_reason = if e.is_some() {
                "error"
            } else {
                "client_closed"
            };
            sbproxy_ai::ai_metrics::record_realtime_session_duration(
                &rd.provider_name,
                close_reason,
                duration_secs,
            );
            sbproxy_ai::ai_metrics::dec_realtime_sessions_active();
            let usage = sbproxy_ai::budget::AiUsage::AudioSeconds {
                seconds: duration_secs,
            };
            // Realtime audio pricing isn't in the catalog yet; cost
            // is reported as 0.0 so operators see the duration on the
            // event without a fabricated dollar figure.
            emit_ai_billing_event(
                rd.surface_label,
                &rd.provider_name,
                Some("gpt-4o-realtime-preview".to_string()),
                usage,
                0.0,
                Vec::new(),
            );
            info!(
                ai.surface = rd.surface_label,
                provider = %rd.provider_name,
                duration_secs = duration_secs,
                close_reason = close_reason,
                "AI realtime: session closed"
            );
        }

        // Record request metrics.
        let method = session.req_header().method.as_str().to_string();
        let hostname = ctx.hostname.to_string();
        let status_u16 = ctx.response_status.unwrap_or(0);

        // --- Wave 3 / G1.6 wire: per-agent labels on the hot path ---
        //
        // Read the agent dimensions out of the request context that
        // `agent_class::stamp_request_context` populated earlier in
        // `request_filter`. Empty strings are the documented sentinel
        // for "no resolution attempted" (legacy dashboards aggregating
        // by hostname / method / status keep working unchanged).
        //
        // `payment_rail` is left empty in OSS until the rail-resolver
        // lands (the existing `ai_provider` field on the context is
        // close but not the same vocabulary). `content_shape` is the
        // response shape; populating it requires a response-time
        // observation that bypasses the current logging hook. Both
        // labels run through the cardinality limiter regardless, so
        // tightening them is a follow-up.
        let agent_labels = build_agent_labels(ctx);
        sbproxy_observe::metrics::record_request_with_labels(
            &hostname,
            &method,
            status_u16,
            ctx.request_start
                .map(|s| s.elapsed().as_secs_f64())
                .unwrap_or(0.0),
            ctx.request_body_bytes,
            ctx.response_body_bytes,
            agent_labels,
        );

        // Record latency on the hostname-only histogram (legacy view).
        let duration = ctx
            .request_start
            .map(|s| s.elapsed().as_secs_f64())
            .unwrap_or(0.0);
        if duration > 0.0 {
            metrics()
                .request_duration
                .with_label_values(&[hostname.as_str()])
                .observe(duration);
            // Mirror to OTel when the operator enabled the OTLP
            // metrics pipeline; no-op when the meter provider is
            // the global default no-op.
            sbproxy_observe::otel::request_duration_histogram()
                .record(duration, &[sbproxy_observe::otel::origin_label(&hostname)]);
        }

        // Phase-duration histogram. Same source-of-truth as the
        // per-phase fields on the access log; this is the aggregate
        // view a Grafana dashboard slices by `phase` to spot
        // regressions in one component (slow auth, slow upstream,
        // slow transform) without staring at line logs.
        if let Some(start) = ctx.request_start {
            if let Some(end) = ctx.auth_finished_at {
                sbproxy_observe::metrics::record_phase_duration(
                    "auth",
                    hostname.as_str(),
                    end.saturating_duration_since(start).as_secs_f64(),
                );
            }
            if let Some(ttfb) = ctx.upstream_first_byte_at {
                sbproxy_observe::metrics::record_phase_duration(
                    "upstream_ttfb",
                    hostname.as_str(),
                    ttfb.saturating_duration_since(start).as_secs_f64(),
                );
            }
        }
        if let (Some(ttfb), Some(rf_end)) =
            (ctx.upstream_first_byte_at, ctx.response_filter_finished_at)
        {
            sbproxy_observe::metrics::record_phase_duration(
                "response_filter",
                hostname.as_str(),
                rf_end.saturating_duration_since(ttfb).as_secs_f64(),
            );
        }

        // Per-origin active-connection bookkeeping. The actual request
        // counter + per-origin views were updated in the
        // `record_request_with_labels` call above, so we only need to
        // decrement the active gauge here.
        if !hostname.is_empty() {
            sbproxy_observe::metrics::dec_active(&hostname);
        }

        // Record errors.
        if e.is_some() {
            metrics()
                .errors_total
                .with_label_values(&[hostname.as_str(), "proxy_error"])
                .inc();
        }

        // Decrement load balancer connection count if this request used one.
        if let Some(target_idx) = ctx.lb_target_idx.take() {
            if let Some(origin_idx) = ctx.origin_idx {
                let pipeline = reload::current_pipeline();
                if let Action::LoadBalancer(lb) = &pipeline.actions[origin_idx] {
                    lb.record_disconnect(target_idx);
                }
            }
        }

        // --- Access log emission (Prereq.A) ---
        //
        // Off by default. Gated on the compiled `access_log` block, then
        // filtered by status / method, then sampled. Each emit produces
        // one JSON line via the `access_log` tracing target. F2.11 will
        // build richer filter and sampling primitives on top of this; F2.12
        // will introduce enterprise sinks (S3, Kafka, Datadog).
        emit_access_log(session, ctx, status_u16, &method, &hostname, duration);

        // --- Wave 8 / T4.6 envelope dispatch ---
        //
        // Build the terminal RequestEvent and hand it to the
        // registered RequestEventSink. The OSS default is a no-op
        // sink, so this pays one OnceLock load + an early return when
        // no sink has been wired. Enterprise startup registers a NATS
        // producer adapter (separate slice) that ships the event to
        // the broker.
        let latency_ms_envelope: Option<u32> = ctx.request_start.map(|s| {
            let ms = s.elapsed().as_millis();
            // Saturate at u32::MAX rather than overflow on the
            // (impossibly long) request that runs longer than ~49
            // days; log emission must not panic.
            u32::try_from(ms).unwrap_or(u32::MAX)
        });
        let error_class = if e.is_some() {
            Some("proxy_error")
        } else {
            None
        };
        crate::wave8::dispatch_terminal_event(
            ctx,
            crate::wave8::DEFAULT_WORKSPACE_ID,
            latency_ms_envelope,
            error_class,
        );
    }
}

/// WOR-819: helper that turns the buffered gRPC response frame plus
/// the captured `grpc-status` / `grpc-message` into the JSON body the
/// transcoded REST response should carry. Re-fetches the transcoder
/// from the live pipeline (it lives on the matched `Action::Grpc`),
/// so the lookup composes with config hot-reload.
///
/// Used from both `response_body_filter` (trailers-only error path,
/// status known from headers) and `response_trailer_filter` (normal
/// path, status from trailers).
fn build_transcoded_json(ctx: &RequestContext, frame: &[u8]) -> Vec<u8> {
    let grpc_method = ctx.transcode_grpc_method.clone().unwrap_or_default();
    let grpc_status = ctx.transcode_grpc_status.unwrap_or(0);
    let grpc_message = ctx.transcode_grpc_message.clone();
    let pipeline = reload::current_pipeline();
    let action = ctx.origin_idx.and_then(|idx| {
        if let Some(fwd_idx) = ctx.forward_rule_idx {
            pipeline
                .forward_rules
                .get(idx)
                .and_then(|r| r.get(fwd_idx))
                .map(|r| &r.action)
        } else {
            pipeline.actions.get(idx)
        }
    });
    match action {
        Some(Action::Grpc(g)) => match g.transcoder.as_ref() {
            Some(t) => t
                .transcode_response(&grpc_method, frame, grpc_status, grpc_message.as_deref())
                .map(|tr| tr.json_body)
                .unwrap_or_else(|e| {
                    serde_json::json!({
                        "error": "gRPC response transcoding failed",
                        "detail": e.to_string(),
                    })
                    .to_string()
                    .into_bytes()
                }),
            None => b"{}".to_vec(),
        },
        _ => b"{}".to_vec(),
    }
}
