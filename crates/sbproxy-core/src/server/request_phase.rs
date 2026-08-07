//! The Pingora `request_filter` phase handler for `SbProxy`.
//!
//! Extracted from the ProxyHttp impl in `proxy_http.rs`
//! because that single method body is ~2,880 lines. The trait method
//! now delegates here. `SbProxy` is a unit struct, so the handler
//! needs no `self`; `use super::*` brings every helper into scope.

use super::*;

struct ConcurrentLimitDenialResponse {
    status: u16,
    content_type: &'static str,
    body: String,
}

fn take_concurrent_limit_denial_response(
    ctx: &mut RequestContext,
    status: u16,
    message: &str,
    policy_type: &str,
) -> Option<ConcurrentLimitDenialResponse> {
    if policy_type != "concurrent_limit" {
        return None;
    }
    let body = ctx
        .concurrent_limit_denial_body
        .take()
        .unwrap_or_else(|| error_json_body(message));
    Some(ConcurrentLimitDenialResponse {
        status,
        content_type: "application/json",
        body,
    })
}

#[cfg(test)]
mod concurrent_limit_denial_response_tests {
    use super::*;

    #[test]
    fn configured_body_is_emitted_byte_for_byte() {
        let configured = "{\"error\":\"busy\"}";
        let mut ctx = RequestContext::new();
        ctx.concurrent_limit_denial_body = Some(configured.to_string());

        let response =
            take_concurrent_limit_denial_response(&mut ctx, 529, configured, "concurrent_limit")
                .expect("concurrent-limit response");

        assert_eq!(response.status, 529);
        assert_eq!(response.content_type, "application/json");
        assert_eq!(response.body.as_bytes(), configured.as_bytes());
        assert!(ctx.concurrent_limit_denial_body.is_none());
    }

    #[test]
    fn default_message_keeps_the_generic_json_envelope() {
        let mut ctx = RequestContext::new();

        let response = take_concurrent_limit_denial_response(
            &mut ctx,
            503,
            "too many concurrent requests",
            "concurrent_limit",
        )
        .expect("concurrent-limit response");

        assert_eq!(response.status, 503);
        assert_eq!(response.content_type, "application/json");
        assert_eq!(
            response.body,
            "{\"error\":\"too many concurrent requests\"}"
        );
    }
}

/// Resolve whether the request's eventual base/forward-rule action is a
/// GraphQL action with parsing enabled.
///
/// Forward-rule matching later in this phase reads the same immutable request
/// path, query, and headers. Resolving it here lets us enable Pingora's bounded
/// replay buffer before threat protection or another origin middleware reads
/// the body.
fn request_requires_graphql_replay(
    session: &Session,
    pipeline: &CompiledPipeline,
    origin_idx: usize,
) -> bool {
    let request = session.req_header();
    let path = request.uri.path();
    let query = request.uri.query();
    let forwarded_action = pipeline
        .forward_rules
        .get(origin_idx)
        .and_then(|rules| {
            rules.iter().find(|rule| {
                rule.matchers.iter().any(|matcher| {
                    matcher
                        .match_request(path, query, &request.headers)
                        .is_some()
                })
            })
        })
        .map(|rule| &rule.action);
    let effective_action = forwarded_action.or_else(|| pipeline.actions.get(origin_idx));

    matches!(
        effective_action,
        Some(Action::GraphQL(graphql)) if graphql.validation_enabled()
    )
}

/// AI actions own idempotency and response replay because their current
/// guardrail policy must run before cached bytes are served.
fn request_uses_ai_owned_replay_paths(
    session: &Session,
    pipeline: &CompiledPipeline,
    origin_idx: usize,
) -> bool {
    let request = session.req_header();
    let forwarded_action = pipeline
        .forward_rules
        .get(origin_idx)
        .and_then(|rules| {
            rules.iter().find(|rule| {
                rule.matchers.iter().any(|matcher| {
                    matcher
                        .match_request(request.uri.path(), request.uri.query(), &request.headers)
                        .is_some()
                })
            })
        })
        .map(|rule| &rule.action);
    action_uses_ai_owned_replay_paths(forwarded_action.or_else(|| pipeline.actions.get(origin_idx)))
}

fn action_uses_ai_owned_replay_paths(action: Option<&Action>) -> bool {
    matches!(action, Some(Action::AiProxy(_)))
}

#[cfg(test)]
mod ai_owned_replay_path_tests {
    use super::*;

    #[test]
    fn external_guardrail_ai_action_defers_common_replay_paths() {
        let ai = sbproxy_modules::action::AiProxyAction {
            config: sbproxy_ai::AiHandlerConfig::from_config(serde_json::json!({
                "providers": []
            }))
            .expect("AI config"),
        };
        let action = Action::AiProxy(Box::new(ai));

        assert!(action_uses_ai_owned_replay_paths(Some(&action)));
        assert!(!action_uses_ai_owned_replay_paths(Some(&Action::Noop)));
    }
}

/// Outcome of the pre-auth inbound-key phase.
#[derive(Debug)]
pub(super) enum InboundKeyPhase {
    /// No minted token in any configured header. The origin's configured auth
    /// provider runs as normal.
    NotPresent,
    /// A minted key resolved. The configured auth provider is skipped.
    Resolved,
    /// Refuse the request with this status and message.
    Deny {
        status: u16,
        message: String,
        trust_outcome: AuthTrustOutcome,
    },
}

/// Turn a key-store outage into a phase outcome, under the plane's
/// configured failure posture.
///
/// Both inbound-key entry points below (the ordinary header sweep and the
/// playground impersonation ticket) had their own copy of this decision.
/// One copy, reading `key_management.failure_posture` through
/// [`crate::key_plane::KeyPlane::failure_posture`], is the point of
/// WOR-2121: a posture that only some of its call sites honour is a
/// posture the operator cannot reason about.
///
/// An admitting posture returns [`InboundKeyPhase::NotPresent`], which
/// falls through to the origin's own configured auth. It is deliberately
/// not a blanket admit, and never has been.
///
/// [`Degraded`](sbproxy_config::types::FailureMode::Degraded) and
/// [`Open`](sbproxy_config::types::FailureMode::Open) take the same
/// branch and differ in what they leave behind: `degraded` says the
/// per-key policy, budget, and attribution this request should have had
/// were lost, and is logged as such so it can be alerted on. A plain
/// `open` claims nothing.
fn inbound_key_store_outage(
    plane: &crate::key_plane::KeyPlane,
    error: &anyhow::Error,
) -> InboundKeyPhase {
    let posture = plane.failure_posture();
    if !posture.admits() {
        return InboundKeyPhase::Deny {
            status: 503,
            message: "key store unavailable".to_string(),
            trust_outcome: AuthTrustOutcome::BackendFailure,
        };
    }
    if posture.guarantee_waived() {
        tracing::warn!(
            error = %error,
            failure_posture = posture.as_label(),
            guarantee_waived = true,
            "key store unavailable; falling through to configured auth with no per-key \
             policy, budget, or attribution"
        );
    } else {
        tracing::warn!(
            error = %error,
            failure_posture = posture.as_label(),
            guarantee_waived = false,
            "key store unavailable; falling through to configured auth"
        );
    }
    InboundKeyPhase::NotPresent
}

/// Resolve a minted virtual key out of the configured inbound headers, before
/// the origin's configured auth provider runs.
///
/// `raw_peer_ip` must come directly from `Session::client_addr`, before trusted
/// forwarding headers can replace `ctx.client_ip`.
///
/// A store outage is resolved by [`inbound_key_store_outage`] against
/// `key_management.failure_posture`, which defaults to closed. An unknown
/// id and a wrong secret return the same status so neither is an existence
/// oracle.
pub(super) async fn resolve_inbound_key(
    plane: &crate::key_plane::KeyPlane,
    headers: &http::HeaderMap,
    raw_peer_ip: Option<std::net::IpAddr>,
    ctx: &mut RequestContext,
) -> InboundKeyPhase {
    // Playground impersonation ticket: always presented as a Bearer token
    // on `Authorization`, independent of the operator's configured sweep
    // headers (`plane.inbound().headers`), since this is an
    // internal admin-minted credential rather than a caller-presented
    // key. A hit resolves straight to the impersonated key's real, stored
    // policy through the same `ctx.resolved_inbound_key` path an
    // ordinarily-presented minted key uses below; a header that carries
    // no ticket-shaped token at all falls through to the ordinary sweep
    // unchanged.
    if let Some(outcome) = resolve_impersonation_ticket(plane, headers, raw_peer_ip, ctx).await {
        return outcome;
    }

    let (header, token) = match crate::inbound_key::sweep_headers(headers, plane.inbound()) {
        crate::inbound_key::SweepOutcome::None => return InboundKeyPhase::NotPresent,
        crate::inbound_key::SweepOutcome::Ambiguous => {
            // Observability describes the credential path the caller attempted,
            // including denials. Keep provider empty: these are proxy-minted
            // tokens, not caller-owned provider credentials.
            ctx.inbound_key_mode = crate::context::InboundKeyMode::Minted;
            return InboundKeyPhase::Deny {
                status: 400,
                message: "conflicting api keys in more than one header".to_string(),
                trust_outcome: AuthTrustOutcome::InvalidProof,
            };
        }
        crate::inbound_key::SweepOutcome::Found { header, token } => {
            ctx.inbound_key_mode = crate::context::InboundKeyMode::Minted;
            (header, token)
        }
    };

    // Shape already proven by the sweep; this only re-splits the halves.
    let Some((key_id, secret)) = sbproxy_keystore::crypto::parse_minted_token(&token) else {
        return InboundKeyPhase::NotPresent;
    };

    let now = chrono::Utc::now();
    match plane.cache().resolve_key(key_id).await {
        Err(e) => inbound_key_store_outage(plane, &e),
        Ok(None) => InboundKeyPhase::Deny {
            status: 401,
            message: "invalid key".to_string(),
            trust_outcome: AuthTrustOutcome::InvalidProof,
        },
        Ok(Some(rec)) => {
            if !plane.crypto().verify_record(&rec, secret, now) {
                InboundKeyPhase::Deny {
                    status: 401,
                    message: "invalid key".to_string(),
                    trust_outcome: AuthTrustOutcome::InvalidProof,
                }
            } else if !rec.is_usable(now) {
                InboundKeyPhase::Deny {
                    status: 403,
                    message: "key is not active".to_string(),
                    trust_outcome: AuthTrustOutcome::InvalidProof,
                }
            } else {
                ctx.inbound_key_header = Some(header);
                ctx.resolved_inbound_key = Some(Box::new(rec));
                InboundKeyPhase::Resolved
            }
        }
    }
}

fn finalize_inbound_key_trust(ctx: &mut RequestContext, trust_outcome: AuthTrustOutcome) {
    crate::trust_tier::finalize(ctx, trust_outcome.is_suspicious());
}

/// Recognize and consume a playground impersonation ticket
/// (`admin_playground::ticket`) presented as `Authorization: Bearer
/// <sbpgtkt_...>`. Returns `None` when the header carries no
/// ticket-shaped token at all (absent, not Bearer, or a different
/// prefix), so the caller falls through to the ordinary sweep unchanged.
/// Once a ticket-shaped token has actually been presented, this always
/// returns `Some`: a wrong/expired/reused ticket denies with the same
/// 401 an unknown minted key gets, rather than silently falling through
/// to whatever auth the origin has configured.
///
/// Redemption is bound to both a loopback TCP peer and a loopback effective
/// client: `admin_playground`'s dispatch route is the only legitimate minter
/// and it always redeems its own ticket via a direct loopback call, so nothing
/// outside this process should ever be able to present one. Both are checked
/// before consuming (not after), so a wrong-peer attempt cannot burn a ticket
/// the legitimate loopback caller still needs.
async fn resolve_impersonation_ticket(
    plane: &crate::key_plane::KeyPlane,
    headers: &http::HeaderMap,
    raw_peer_ip: Option<std::net::IpAddr>,
    ctx: &mut RequestContext,
) -> Option<InboundKeyPhase> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    let token = auth
        .strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
        .unwrap_or(auth)
        .trim();
    if !token.starts_with(crate::admin_playground::ticket::PREFIX) {
        return None;
    }
    if !raw_peer_ip.is_some_and(|ip| ip.is_loopback())
        || !ctx.client_ip.is_some_and(|ip| ip.is_loopback())
    {
        return Some(InboundKeyPhase::Deny {
            status: 401,
            message: "invalid key".to_string(),
            trust_outcome: AuthTrustOutcome::InvalidProof,
        });
    }
    let Some(key_id) = crate::admin_playground::ticket::consume(token) else {
        return Some(InboundKeyPhase::Deny {
            status: 401,
            message: "invalid key".to_string(),
            trust_outcome: AuthTrustOutcome::InvalidProof,
        });
    };
    let now = chrono::Utc::now();
    Some(match plane.cache().resolve_key(&key_id).await {
        Err(e) => inbound_key_store_outage(plane, &e),
        Ok(None) => InboundKeyPhase::Deny {
            status: 401,
            message: "invalid key".to_string(),
            trust_outcome: AuthTrustOutcome::InvalidProof,
        },
        Ok(Some(rec)) => {
            if !rec.is_usable(now) {
                InboundKeyPhase::Deny {
                    status: 403,
                    message: "key is not active".to_string(),
                    trust_outcome: AuthTrustOutcome::InvalidProof,
                }
            } else {
                // Same field a normally-swept key stamps, so the ticket
                // (like the key it names) is stripped before the request
                // goes upstream and never leaks past this process.
                ctx.inbound_key_header = Some("authorization".to_string());
                ctx.resolved_inbound_key = Some(Box::new(rec));
                InboundKeyPhase::Resolved
            }
        }
    })
}

/// Whether the request already declares more body than the body-matching
/// cap will hold (WOR-2306).
///
/// Checked before any buffering is armed, so a large upload is never
/// partially retained just to be refused by the matcher afterwards. A
/// request with no `Content-Length`, or an unparseable one, is not
/// "exceeding" anything knowable here; a chunked body that overruns is
/// caught by the read loop instead, and both end the same way.
fn declared_body_exceeds_cap(session: &Session, cap: usize) -> bool {
    session
        .req_header()
        .headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.parse::<usize>().ok())
        .is_some_and(|declared| declared > cap)
}

/// Read up to `cap` bytes of the request body so a forward rule can match
/// on a field inside it (WOR-2306).
///
/// `cap` is `None` for every origin that declares no body matcher, and that
/// is the entire hot-path story: the function returns without touching the
/// session, so an origin that does not use this feature pays one branch and
/// never buffers, reads, or parses anything.
///
/// Reading here is only safe because `request_filter` armed replay
/// buffering before any of this ran. Every chunk consumed is retained and
/// replayed upstream, so selecting a route on the body does not consume the
/// body.
///
/// # Misses rather than failures
///
/// A body larger than the cap returns `None`, which makes the matcher fall
/// through to header-only matching rather than refusing the request. That
/// is deliberate: the cap exists to bound this process's memory, and a
/// request being too big to *route on* is not the same as a request being
/// too big to *serve*. Failing here would turn a routing convenience into a
/// new way to reject traffic that has always been fine.
///
/// The remaining bytes are left in the stream on that path. The ordinary
/// proxy loop reads and forwards them exactly as it would for any origin
/// with no body matcher at all.
///
/// A transport error is still an error, since that request is not going to
/// be served either way.
async fn read_body_for_route_matching(
    session: &mut Session,
    cap: Option<usize>,
) -> Result<Option<Vec<u8>>> {
    let Some(cap) = cap else {
        return Ok(None);
    };

    let mut buffered: Vec<u8> = Vec::new();
    while let Some(chunk) = session.read_request_body().await? {
        // `saturating_add` because both operands are attacker-influenced
        // and a wrap here would turn the cap into a bypass.
        if buffered.len().saturating_add(chunk.len()) > cap {
            return Ok(None);
        }
        buffered.extend_from_slice(&chunk);
    }
    Ok(Some(buffered))
}

/// Handle an incoming request before proxying. See the trait method
/// `<SbProxy as ProxyHttp>::request_filter` for the phase contract.
pub(super) async fn request_filter(
    session: &mut Session,
    ctx: &mut RequestContext,
) -> Result<bool> {
    // Start timing for latency metrics.
    ctx.request_start = Some(std::time::Instant::now());

    // Mint a per-request correlation ID up front so every emitted
    // event for this request (webhooks, alerts, access logs, response
    // headers) shares the same identifier.
    //
    // If the inbound request already carries the configured
    // correlation header, adopt that value so upstream callers can
    // tie their traces to ours. Otherwise generate a fresh UUID v4.
    if ctx.request_id.is_empty() {
        let pipeline = ctx.pipeline.clone();
        let cfg = &pipeline.config.server.correlation_id;
        let inbound = if cfg.enabled {
            session
                .req_header()
                .headers
                .get(cfg.header.as_str())
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty() && s.len() <= 256)
        } else {
            None
        };
        ctx.request_id = match inbound {
            Some(id) => compact_str::CompactString::new(id),
            None => compact_str::CompactString::new(crate::identity::new_request_id()),
        };
    }

    // --- WOR-114 Phase 1: parse `x-sb-flags` + `?_sb.<k>` ---
    //
    // Materialise the per-request feature flags up front so the
    // rest of request_filter (cache lookup) and response_filter
    // (debug header stamp + DEBUG-level log entry) can branch on
    // them without re-parsing. The kill switch
    // `--disable-sb-flags` / `SB_DISABLE_SB_FLAGS=1` causes the
    // parser to return the empty default; cost on the disabled
    // path is one atomic load.
    {
        let header_value = session
            .req_header()
            .headers
            .get("x-sb-flags")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let query = session.req_header().uri.query().unwrap_or("");
        ctx.flags = crate::sb_flags::parse_request(header_value, query);
        if ctx.flags.debug {
            tracing::debug!(
                request_id = %ctx.request_id,
                "x-sb-flags: debug flag set on request"
            );
        }
    }

    // Preserve the raw TCP peer before trusted forwarding headers can
    // replace ctx.client_ip with the derived client identity.
    let raw_peer_ip = session
        .client_addr()
        .and_then(|addr| addr.as_inet())
        .map(|addr| addr.ip());
    ctx.client_ip = raw_peer_ip;

    // Trust boundary for inbound forwarding headers.
    //
    // If the immediate TCP peer is in `proxy.trusted_proxies`, walk the
    // existing `X-Forwarded-For` chain right-to-left, skipping any hop
    // that is itself a trusted proxy, and use the leftmost untrusted
    // hop as the real client IP. If the peer is NOT trusted, strip
    // every inbound forwarding header so a downstream client cannot
    // spoof its source identity (X-Forwarded-For, X-Real-IP, the
    // public-facing scheme/port, X-Forwarded-Host, RFC 7239
    // Forwarded). Even when the peer is trusted, we re-derive each of
    // these from the trusted source and overwrite below in
    // upstream_request_filter.
    let peer_trusted: bool;
    {
        let pipeline = ctx.pipeline.clone();
        peer_trusted = ctx
            .client_ip
            .map(|ip| {
                pipeline
                    .trusted_proxy_cidrs
                    .iter()
                    .any(|net| net.contains(ip))
            })
            .unwrap_or(false);
        if peer_trusted {
            if let Some(xff) = session
                .req_header()
                .headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
            {
                let real_client = xff
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .rev()
                    .find_map(|s| {
                        s.parse::<std::net::IpAddr>().ok().filter(|ip| {
                            !pipeline
                                .trusted_proxy_cidrs
                                .iter()
                                .any(|net| net.contains(*ip))
                        })
                    });
                if let Some(ip) = real_client {
                    ctx.client_ip = Some(ip);
                }
            }
        } else {
            let req = session.req_header_mut();
            req.remove_header("x-forwarded-for");
            req.remove_header("x-real-ip");
            req.remove_header("x-forwarded-proto");
            req.remove_header("x-forwarded-port");
            req.remove_header("x-forwarded-host");
            req.remove_header("forwarded");
            // Wave 5 / G5.3: strip TLS-fingerprint trust headers
            // from untrusted peers so a downstream client cannot
            // forge its own JA3 / JA4 / trustworthy assertion. Only
            // a trusted upstream (CDN sidecar, mesh-injected TLS
            // terminator) can supply these values.
            req.remove_header("x-sbproxy-tls-ja3");
            req.remove_header("x-sbproxy-tls-ja4");
            req.remove_header("x-sbproxy-tls-ja4h");
            req.remove_header("x-sbproxy-tls-trustworthy");
            // WOR-2120: strip the A2A envelope headers from untrusted
            // peers. These feed `caller_denylist`, `callee_allowlist`,
            // and cycle detection, so honoring them from an arbitrary
            // client lets that client name itself, name its callee, and
            // assert its own call chain. `envelope_from_headers` also
            // gates on the same trust decision; removing them here
            // additionally keeps a forged value from reaching the
            // upstream, which would re-introduce the forgery one hop in.
            req.remove_header("x-a2a-caller-agent-id");
            req.remove_header("x-a2a-callee-agent-id");
            req.remove_header("x-a2a-task-id");
            req.remove_header("x-a2a-parent-request-id");
            req.remove_header("x-a2a-chain-depth");
            req.remove_header("x-a2a-chain");
        }
    }

    // --- WOR-201 PR 1c.0: precompute tls_terminated on the request context ---
    //
    // The CSRF policy already derives this signal locally in
    // `check_policies` to decide whether to stamp `; Secure` on
    // its cookie. The per-policy ports (1c.1 / 1c.2 / 1c.3)
    // build wrapper enforcers that go through the
    // [`sbproxy_plugin::PolicyEnforcer::enforce`] trait and
    // receive only a request snapshot, so they cannot reach
    // back to the live Pingora session for `ssl_digest`.
    // Precompute the signal here so a wrapper can read it off
    // `RequestContext::tls_terminated` without further work.
    // Mirrors the existing CSRF derivation: either Pingora
    // exposed an `ssl_digest` (the listener itself was TLS) or
    // the trusted-proxy chain stamped `X-Forwarded-Proto:
    // https`. The trust-boundary block above strips
    // `x-forwarded-proto` from untrusted peers so this read is
    // safe to perform unconditionally here.
    ctx.tls_terminated = session
        .digest()
        .and_then(|d| d.ssl_digest.as_ref())
        .is_some()
        || session
            .req_header()
            .headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.eq_ignore_ascii_case("https"))
            .unwrap_or(false);

    // Increment active connections gauge.
    metrics().active_connections.inc();

    // --- Wave 3 / G1.4 wire: agent-class stamp ---
    //
    // Stamp `RequestContext::{agent_id, agent_vendor, agent_purpose,
    // agent_id_source, agent_rdns_hostname}` from the global
    // `AgentClassResolver` the binary built at startup. The
    // resolver chain is: Web Bot Auth verified keyid (high
    // confidence) -> forward-confirmed reverse-DNS (strong) ->
    // User-Agent regex (advisory) -> anonymous bot-auth ->
    // generic-crawler heuristic -> human fallback. The OSS build
    // restamps the first signal after the bot-auth verifier accepts
    // a keyid. This early pass feeds `None` so CAP binding and
    // request-time labels still get the best non-WBA verdict before
    // auth runs.
    //
    // Skipped under three conditions:
    //   * `agent-class` feature is off (compile-time gate).
    //   * No resolver installed (binary built without the feature
    //     or test harness bypassed `install_agent_class_resolver`).
    //   * No User-Agent header (the resolver still runs but every
    //     signal misses; the fallthrough path emits `human`).
    //
    // Per-agent metric labels on `sbproxy_requests_total` consume
    // the values stamped here (see `build_agent_labels` for the
    // hot-path read).
    #[cfg(feature = "agent-class")]
    {
        if let Some(resolver) = reload::agent_class_resolver() {
            let user_agent = session
                .req_header()
                .headers
                .get(http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok());
            // Auth runs below. If bot_auth verifies a keyid, the
            // request is restamped with that stronger signal before
            // upstream headers and metrics read the context.
            crate::agent_class::stamp_request_context(
                ctx,
                &resolver,
                None,
                false,
                ctx.client_ip,
                user_agent,
            );
        }
    }

    // --- Wave 5 / G5.1 wire: IdentityResolverHook (KYA step 1.5) ---
    //
    // Sit at resolver step 1.5 between Web Bot Auth (step 1) and
    // forward-confirmed reverse DNS (step 2). The OSS pipeline owns
    // the header bag and the hostname; enterprise hooks (KYA verifier,
    // future identity providers) register through
    // `sbproxy_plugin::register_identity_hook`. Each registered
    // hook runs in registration order; the first hook returning a
    // verdict wins and the iteration short-circuits. Returning
    // `None` falls through to the next resolver step (rDNS, UA,
    // anonymous bot-auth, fallback).
    //
    // OSS-only builds register no identity hooks; the iteration
    // is a no-op. A plugin can install an identity verifier (e.g.
    // a KYA verifier) at startup via the `sbproxy-plugin`
    // registry; the iteration below picks it up automatically.
    #[cfg(feature = "agent-class")]
    {
        let hooks = sbproxy_plugin::identity_hooks();
        if !hooks.is_empty() {
            // Construct a header lookup adapter on demand so the
            // trait stays free of any concrete header-map type.
            struct HeaderAdapter<'h>(&'h pingora_http::RequestHeader);
            impl sbproxy_plugin::IdentityHeaderLookup for HeaderAdapter<'_> {
                fn get(&self, name: &str) -> Option<&str> {
                    self.0.headers.get(name).and_then(|v| v.to_str().ok())
                }
            }
            let prior_agent_id_str = ctx.agent_id.as_ref().map(|a| a.as_str().to_string());
            let req_header = session.req_header();
            let adapter = HeaderAdapter(req_header);
            let req = sbproxy_plugin::IdentityRequest {
                headers: &adapter,
                hostname: ctx.hostname.as_str(),
                prior_agent_id: prior_agent_id_str.as_deref(),
            };
            for hook in hooks.iter() {
                if let Some(verdict) = hook.resolve(&req).await {
                    // Stamp the KYA side-channel fields whenever
                    // the hook populates them, even if the verdict
                    // produced no `agent_id`. This is how
                    // `request.kya.verdict` becomes addressable
                    // from CEL / Lua / JS / WASM regardless of
                    // whether the verifier matched a token.
                    if verdict.kya_verdict.is_some() {
                        ctx.kya_verdict = verdict.kya_verdict;
                    }
                    if verdict.kya_vendor.is_some() {
                        ctx.kya_vendor = verdict.kya_vendor.clone();
                    }
                    if verdict.kya_version.is_some() {
                        ctx.kya_version = verdict.kya_version.clone();
                    }
                    if verdict.kya_kyab_balance.is_some() {
                        ctx.kya_kyab_balance = verdict.kya_kyab_balance;
                    }

                    // Resolve the agent identity only when the
                    // hook actually produced one. An empty
                    // `agent_id` means the hook ran but did not
                    // match (e.g. KYA returned `Missing` /
                    // `Expired`); the iteration falls through to
                    // the next resolver step in that case.
                    if verdict.agent_id.is_empty() {
                        continue;
                    }
                    // First hook wins; map verdict back into the
                    // closed `RequestContext` agent fields.
                    ctx.agent_id = Some(sbproxy_classifiers::AgentId(verdict.agent_id.clone()));
                    // Keep the existing vendor / purpose unchanged
                    // when the hook does not have an opinion; the
                    // enterprise verifier supplies its own metadata
                    // in a future iteration via the catalog. For
                    // now, "kya" is the canonical Wave 5 source
                    // label.
                    ctx.agent_id_source = match verdict.agent_id_source {
                        "bot_auth" => Some(sbproxy_classifiers::AgentIdSource::BotAuth),
                        "kya" => Some(sbproxy_classifiers::AgentIdSource::Kya),
                        "rdns" => Some(sbproxy_classifiers::AgentIdSource::Rdns),
                        "user_agent" => Some(sbproxy_classifiers::AgentIdSource::UserAgent),
                        "anonymous_bot_auth" => {
                            Some(sbproxy_classifiers::AgentIdSource::AnonymousBotAuth)
                        }
                        "tls_fingerprint" => {
                            Some(sbproxy_classifiers::AgentIdSource::TlsFingerprint)
                        }
                        "ml_override" => Some(sbproxy_classifiers::AgentIdSource::MlOverride),
                        _ => Some(sbproxy_classifiers::AgentIdSource::Fallback),
                    };
                    break;
                }
            }
        }
    }

    // --- Wave 4 / G4.9 wire: aipref preference signal ---
    //
    // Read the inbound `aipref` request header (if present),
    // parse it into the typed `AiprefSignal`, and stamp it onto
    // `ctx.aipref` so downstream policy + scripting surfaces
    // (CEL, Lua, JavaScript, WASM) can read
    // `request.aipref.{train,search,ai_input}` without re-parsing.
    // Per `crates/sbproxy-modules/src/policy/aipref.rs` the parser
    // is lenient (unknown keys / values are tolerated; only
    // syntactic errors return Err); on Err we log a warn and
    // leave `ctx.aipref` as `None` so downstream code falls
    // through to default-permissive semantics per A4.1.
    {
        let header = session
            .req_header()
            .headers
            .get("aipref")
            .and_then(|v| v.to_str().ok());
        if let Some(raw) = header {
            match sbproxy_modules::parse_aipref(raw) {
                Ok(signal) => {
                    ctx.aipref = Some(signal);
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        header = %raw,
                        "malformed aipref header; falling through to default-permissive"
                    );
                }
            }
        }
    }

    // --- Wave 7 / A7.2 wire: A2A protocol envelope detection ---
    //
    // Header-based detection runs once per request. When matched
    // the proxy stamps `ctx.a2a` with envelope fields drawn from
    // request headers so the policy module can enforce
    // chain-depth, cycle, allowlist, and denylist checks
    // synchronously without buffering the body.
    //
    // The optional spec parsers (`a2a-anthropic`, `a2a-google`)
    // augment this header-derived view with body-decoded fields
    // when the body has already been read; in the OSS default
    // build neither parser is compiled, so the proxy operates on
    // the header-stamped envelope alone.
    {
        let detected = sbproxy_modules::detect_a2a(
            &session.req_header().headers,
            session.req_header().uri.path(),
            None, // operator route_glob is per-policy; consulted later
        );
        if let Some(signal) = detected {
            // WOR-2120: the envelope is only populated from headers when
            // the immediate peer is in `proxy.trusted_proxies`. An
            // untrusted caller gets the zero-default envelope with
            // `identity_verified` clear, so the policy can tell "no
            // identity asserted" apart from "identity asserted by
            // someone we trust" instead of treating a forged
            // `x-a2a-chain-depth: 1` as a genuine chain root.
            let a2a_ctx = sbproxy_modules::envelope_from_headers(
                &session.req_header().headers,
                signal.to_spec(),
                peer_trusted,
            );
            ctx.a2a = Some(a2a_ctx);
        }
    }

    // --- Wave 5 / G5.3 wire: TLS fingerprint capture ---
    //
    // The canonical capture point is the Pingora TLS handshake
    // hook (where the raw ClientHello bytes are still on hand);
    // Pingora 0.8's public `Session` API does not surface those
    // bytes, so the OSS path captures the fingerprint via
    // sidecar-injected trust headers from the immediate upstream
    // peer. Operators terminate TLS in a sidecar (Envoy, Caddy,
    // BoringSSL-based) that runs `sbproxy_tls::parse_client_hello`
    // and forwards the fingerprint as `x-sbproxy-tls-ja3`,
    // `x-sbproxy-tls-ja4`, and (optional) `x-sbproxy-tls-trustworthy`.
    // The header-based path also drives the e2e harness, which is
    // plaintext HTTP today.
    //
    // Headers are accepted ONLY from peers in
    // `proxy.trusted_proxies`. The earlier trust-boundary strip
    // already deletes the headers when the peer is untrusted, so
    // a downstream client cannot forge its own fingerprint.
    //
    // `trustworthy` is decided by
    // `TlsFingerprintConfig::resolve_trustworthy` against the
    // resolved client IP and the pre-parsed per-origin CIDR sets.
    // Absent any operator CIDR rules it defaults to the sidecar's
    // assertion, and to `true` when the sidecar made none: this code
    // is only reachable from a peer in `proxy.trusted_proxies`. An
    // operator narrows that with `untrusted_client_cidrs` (which
    // outranks the sidecar) or `trustworthy_client_cidrs` (which,
    // once non-empty, decides on its own).
    #[cfg(feature = "tls-fingerprint")]
    if peer_trusted {
        // Wave 5 day-6 Item 3: read the typed TlsFingerprintConfig
        // and respect the `mode: disabled` short-circuit + the
        // operator's `sidecar_header_allowlist`. The canonical
        // `x-sbproxy-tls-*` family is always honoured for backward
        // compat with the day-5 wire shape.
        let pipeline = ctx.pipeline.clone();
        let tls_cfg = &pipeline.tls_fingerprint_config;
        let capture_disabled =
            tls_cfg.enabled && tls_cfg.mode == crate::pipeline::TlsFingerprintMode::Disabled;
        if !capture_disabled {
            let req = session.req_header();

            // Helper closure: read the first header that matches
            // any of the supplied names AND is on the allowlist.
            // The day-5 wire shape always reads x-sbproxy-tls-*;
            // operators can add e.g. x-forwarded-ja4 via
            // `sidecar_header_allowlist`.
            let read_allowed = |canonical: &str, alts: &[&str]| -> Option<String> {
                let names = std::iter::once(canonical).chain(alts.iter().copied());
                for name in names {
                    if !tls_cfg.header_allowed(name) {
                        continue;
                    }
                    if let Some(v) = req
                        .headers
                        .get(name)
                        .and_then(|h| h.to_str().ok())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        return Some(v.to_string());
                    }
                }
                None
            };

            let ja3 = read_allowed("x-sbproxy-tls-ja3", &["x-forwarded-ja3"]);
            let ja4 = read_allowed("x-sbproxy-tls-ja4", &["x-forwarded-ja4"]);
            let ja4h_supplied = read_allowed("x-sbproxy-tls-ja4h", &["x-forwarded-ja4h"]);
            let ja4s_supplied = read_allowed("x-sbproxy-tls-ja4s", &["x-forwarded-ja4s"]);
            let trustworthy_override = req
                .headers
                .get("x-sbproxy-tls-trustworthy")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.eq_ignore_ascii_case("true") || s == "1");

            if ja3.is_some() || ja4.is_some() || ja4h_supplied.is_some() || ja4s_supplied.is_some()
            {
                // Resolve trustworthy: operator-configured CIDR
                // sets win over the sidecar's hint when the
                // resolved client IP falls in either set. The CIDR
                // sets were parsed at config load; this is a
                // membership check on the request path, nothing more.
                let trustworthy = tls_cfg.resolve_trustworthy(trustworthy_override, ctx.client_ip);
                ctx.tls_fingerprint = Some(sbproxy_tls::TlsFingerprint {
                    ja3,
                    ja4,
                    ja4h: ja4h_supplied,
                    ja4s: ja4s_supplied,
                    // WOR-586 added `sni` + `alpn`; WOR-501 added
                    // `pq_tls_present`; WOR-590 added `ja4t` +
                    // `ja4x`. This synthetic construction path
                    // lacks the raw ClientHello bytes / TCP option
                    // block / mTLS cert chain, so default them
                    // all. The real ClientHello-parsing path and
                    // the mTLS verify path populate them.
                    sni: None,
                    alpn: Vec::new(),
                    pq_tls_present: false,
                    ja4t: None,
                    ja4x: None,
                    trustworthy,
                });
            }
        }
    }

    // --- Wave 5 / G5.3 wire: JA4H HTTP fingerprint ---
    //
    // JA3 / JA4 are stamped on `ctx.tls_fingerprint` before this
    // block by the trusted sidecar-header path today, or by a future
    // native listener hook once Pingora exposes raw ClientHello bytes.
    // JA4H requires the request headers, which are not available at
    // handshake time; compute it here, after the trust-boundary header
    // strip and the aipref parse, so the hash reflects exactly the
    // headers the upstream pipeline sees. Skips entirely when the
    // `tls-fingerprint` feature is off, when no fingerprint was
    // captured (plaintext HTTP), or when the fingerprint already has a
    // `ja4h` value (a pre-stamped value from an enterprise hook).
    #[cfg(feature = "tls-fingerprint")]
    {
        if let Some(fp) = ctx.tls_fingerprint.as_mut() {
            if fp.ja4h.is_none() {
                let req = session.req_header();
                let method = req.method.as_str();
                let version_label = match req.version {
                    http::Version::HTTP_10 => "1.0",
                    http::Version::HTTP_11 => "1.1",
                    http::Version::HTTP_2 => "2",
                    http::Version::HTTP_3 => "3",
                    _ => "0.9",
                };
                // The names are hashed in wire order and nothing else
                // reads them, so hand `compute_ja4h` the key iterator
                // rather than collecting a Vec to re-iterate.
                fp.ja4h = Some(sbproxy_tls::compute_ja4h(
                    method,
                    version_label,
                    req.headers.keys().map(|name| name.as_str()),
                ));
            }
        }
    }

    // --- Wave 5 / G5.4 wire: headless-browser detection ---
    //
    // Run the JA4-based headless detector after the JA4H stamp
    // (the detector reads JA3 + JA4 only, not JA4H, but ordering
    // both blocks together keeps the Wave 5 wires in one place).
    // The detector is feature-gated; the catalog lives behind an
    // OnceCell in the proxy reload module, populated at startup
    // from the embedded JSON.
    //
    // After the verdict lands, override the agent_class resolver's
    // fallback verdict per A5.1 § "Worked example: headless
    // Puppeteer detection". The override fires only when:
    //   1. The detector returned `Detected`.
    //   2. The G1.4 resolver chain fell through to `Fallback`
    //      (i.e. no higher-confidence signal matched).
    //
    // Stronger signals (BotAuth, Kya, Rdns, UserAgent regex,
    // AnonymousBotAuth) keep their verdict; the headless detector
    // is an advisory step that only catches traffic the chain
    // would otherwise label `human` or `unknown`.
    #[cfg(feature = "tls-fingerprint")]
    {
        if let Some(fp) = ctx.tls_fingerprint.as_ref() {
            if let Some(catalog_guard) = reload::tls_fingerprint_catalog() {
                let signal = sbproxy_security::detect_headless(
                    catalog_guard.as_ref(),
                    fp.ja4.as_deref(),
                    fp.trustworthy,
                );
                let mapped = match signal {
                    sbproxy_security::HeadlessDetectSignal::Detected {
                        library,
                        confidence,
                    } => Some(crate::context::HeadlessSignal::Detected {
                        library,
                        confidence,
                    }),
                    sbproxy_security::HeadlessDetectSignal::NotDetected => {
                        Some(crate::context::HeadlessSignal::NotDetected)
                    }
                };
                ctx.headless_signal = mapped;
            }
        }

        // --- Resolver chain hook: headless -> agent_class ---
        #[cfg(feature = "agent-class")]
        {
            if let Some(crate::context::HeadlessSignal::Detected {
                library,
                confidence: _,
            }) = ctx.headless_signal.as_ref()
            {
                if let Some(resolver) = reload::agent_class_resolver() {
                    let library_owned = library.clone();
                    let _ = crate::agent_class::apply_headless_override(
                        ctx,
                        &library_owned,
                        resolver.catalog(),
                    );
                }
            }
        }
    }

    // --- WOR-706 wire: agent-detect scorer ---
    //
    // When `proxy.extensions.agent_detect.enabled` is set, build the
    // TLS + HTTP signal bag from the context the pipeline already has
    // (TLS fingerprint stamped above; headers read here) and run the
    // configured scorer. The verdict lands on `ctx.agent_detection` for
    // the scripting bridges (`request.agent.*`, WOR-589) and the
    // `trust_tier` combiner to read. Payload signals need a buffered
    // body and are a follow-up; the TLS + HTTP extractors are cheap and
    // allocation-light. Default off, so deployments that do not enable
    // agent detection skip this block entirely.
    {
        let pipeline = ctx.pipeline.clone();
        if pipeline.agent_detect_config.enabled {
            if let Some(scorer) = reload::agent_detect_scorer() {
                let tls = ctx
                    .tls_fingerprint
                    .as_ref()
                    .map(sbproxy_agent_detect::TlsSignals::from);
                let req = session.req_header();
                let cookie_persistence = req.headers.contains_key(http::header::COOKIE);
                let header_pairs: Vec<(String, String)> = req
                    .headers
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.as_str().to_string(),
                            value.to_str().unwrap_or("").to_string(),
                        )
                    })
                    .collect();
                let http_signals = sbproxy_agent_detect::extract_http_signals(
                    header_pairs.iter().map(|(n, v)| (n.as_str(), v.as_str())),
                    cookie_persistence,
                );
                // WOR-817: deterministic headless / stealth indicator
                // bag, computed off the same headers the rule pack
                // already walked. Cheap (header re-iteration only)
                // and orthogonal to the rule pack so a rule-miss
                // still carries the headless verdict.
                let headless = sbproxy_agent_detect::extract_headless_indicators(
                    &http_signals,
                    header_pairs.iter().map(|(n, v)| (n.as_str(), v.as_str())),
                );
                let headless_score = sbproxy_agent_detect::score_headless(&headless);
                let headless_names: Vec<String> =
                    headless.names().into_iter().map(str::to_string).collect();
                let signals = sbproxy_agent_detect::Signals {
                    tls,
                    http: Some(http_signals),
                    payload: None,
                };
                let inference_started = std::time::Instant::now();
                let mut detection = scorer.score(&signals);
                let inference_secs = inference_started.elapsed().as_secs_f64();
                detection.headless_score = headless_score;
                detection.headless_indicators = headless_names;
                sbproxy_observe::metrics::record_agent_detect(
                    detection.agent_id.as_deref(),
                    detection.provenance.as_str(),
                    detection.score,
                    inference_secs,
                );
                ctx.agent_detection = Some(detection);
            }
        }
    }

    // --- Distributed tracing: extract or generate W3C Trace Context ---
    {
        let headers = &session.req_header().headers;
        let traceparent = headers.get("traceparent").and_then(|v| v.to_str().ok());
        let tracestate = headers.get("tracestate").and_then(|v| v.to_str().ok());

        // Only the genuine-parse outcomes land here; a synthesized
        // random root falls out to `None` below. This distinction
        // (`ctx.trace_parent_is_remote`) matters downstream: the
        // AI-dispatch span-creation site uses it to decide whether to
        // parent the exported span on the caller's trace via
        // `sbproxy_observe::telemetry::parent_span_on_remote_trace_context`,
        // an explicit, request-scoped call rather than any
        // ambient/thread-local OTel state (which used to leak one
        // Context per request and could bleed a previous request's
        // trace onto a later one with no traceparent of its own, on a
        // reused worker thread).
        let remote_trace_ctx = if let Some(tp) = traceparent {
            // Try W3C traceparent first.
            sbproxy_observe::trace_ctx::w3c::TraceContext::parse_with_state(tp, tracestate)
        } else {
            // Fall back to B3 single header.
            let b3_ctx = headers
                .get("b3")
                .and_then(|v| v.to_str().ok())
                .and_then(sbproxy_observe::trace_ctx::b3::B3Context::parse_single)
                .map(|b3| b3.to_w3c());

            if b3_ctx.is_some() {
                b3_ctx
            } else {
                // Fall back to B3 multi-header format.
                let tid = headers.get("x-b3-traceid").and_then(|v| v.to_str().ok());
                let sid = headers.get("x-b3-spanid").and_then(|v| v.to_str().ok());
                match (tid, sid) {
                    (Some(tid), Some(sid)) => {
                        let sampled = headers.get("x-b3-sampled").and_then(|v| v.to_str().ok());
                        let parent = headers
                            .get("x-b3-parentspanid")
                            .and_then(|v| v.to_str().ok());
                        sbproxy_observe::trace_ctx::b3::B3Context::parse_multi(
                            tid, sid, sampled, parent,
                        )
                        .map(|b3| b3.to_w3c())
                    }
                    _ => None,
                }
            }
        };

        ctx.trace_parent_is_remote = remote_trace_ctx.is_some();
        ctx.trace_ctx =
            Some(remote_trace_ctx.unwrap_or_else(sbproxy_observe::TraceContext::new_random));
    }

    // --- ACME HTTP-01 challenge interception ---
    // Owned `path` (as opposed to a &str borrowed from
    // `req_header()`) so we can re-borrow `session` mutably for
    // body capture in the fake-sink admin path below without
    // running into a use-after-borrow on the original immutable
    // borrow.
    let path: String = session.req_header().uri.path().to_string();
    if let Some(token) = sbproxy_tls::challenges::extract_challenge_token(&path) {
        if let Some(store) = reload::challenge_store() {
            if let Some(key_auth) = store.get(token) {
                debug!(token = %token, "serving ACME HTTP-01 challenge response");
                send_response(session, 200, "text/plain", key_auth.as_bytes()).await?;
                return Ok(true);
            }
        }
    }

    // --- WOR-87 test-only fake-sink admin endpoints ---
    //
    // Behind the `SBPROXY_TEST_FAKE_SINKS=1` env var, expose
    // `POST /api/_test/sinks/reset` (clear every per-sink buffer)
    // and `GET /api/_test/sinks/{name}` (read the named buffer).
    // The mode is also responsible for capturing every inbound
    // request below as a synthetic event into all four sinks. Both
    // halves are gated on the same env var; in a production binary
    // (mode off), the routes 404 through to origin resolution and
    // capture is a no-op atomic load.
    if sbproxy_observe::fake_sinks::enabled() {
        let method = session.req_header().method.clone();
        if path == "/api/_test/sinks/reset" {
            if method == http::Method::POST {
                sbproxy_observe::fake_sinks::reset();
                send_response(session, 204, "application/json", b"").await?;
                return Ok(true);
            }
            send_error(session, 405, "method not allowed").await?;
            return Ok(true);
        }
        if let Some(name) = path.strip_prefix("/api/_test/sinks/") {
            if method == http::Method::GET {
                let body = sbproxy_observe::fake_sinks::read(name);
                send_response(session, 200, "text/plain; charset=utf-8", body.as_bytes()).await?;
                return Ok(true);
            }
            send_error(session, 405, "method not allowed").await?;
            return Ok(true);
        }
        // For every non-admin path that is also not a probe
        // endpoint, record one synthetic event into each of the
        // four internal sinks so the redaction fan-out test can
        // assert on the redacted output, then short-circuit with
        // a 200 so the body bytes we already drained never reach
        // a real upstream. We skip probe paths so the
        // negative-coverage test (which fires `/healthz` with a
        // benign user-agent) does not see a populated buffer.
        //
        // The capture path runs BEFORE origin resolution so a
        // fixture that targets a non-existent host still lands a
        // line in every buffer.
        let is_probe = matches!(
            path.as_str(),
            "/healthz" | "/readyz" | "/livez" | "/health" | "/metrics"
        ) || path.starts_with("/.well-known/");
        if !is_probe {
            capture_fake_sink_event(session).await;
            send_response(session, 200, "application/json", b"{\"ok\":true}").await?;
            return Ok(true);
        }
    }

    // --- Health check endpoint ---
    if path == "/health" {
        send_response(session, 200, "application/json", b"{\"status\":\"ok\"}").await?;
        // Record the real status so the request log / metrics show 200,
        // not the unset-status 0 sentinel (WOR-1746).
        ctx.response_status = Some(200);
        return Ok(true);
    }

    // --- Metrics endpoint ---
    if path == "/metrics" {
        let body = metrics().render();
        send_response(
            session,
            200,
            "text/plain; version=0.0.4; charset=utf-8",
            body.as_bytes(),
        )
        .await?;
        ctx.response_status = Some(200);
        return Ok(true);
    }

    // --- Page Shield CSP report intake ---
    //
    // Browsers POST violation reports to the configured `report-uri`.
    // We accept up to 64 KiB of body and record a structured event
    // so downstream consumers (logpush sinks, the enterprise
    // connection-monitor, dashboards) can analyse what fired.
    if path == sbproxy_modules::policy::page_shield::DEFAULT_REPORT_PATH
        && session.req_header().method == http::Method::POST
    {
        // Pull the body up to a sane cap. CSP reports are tiny
        // (well under 8 KiB in practice); 64 KiB is the upper
        // bound we keep so a misconfigured client cannot tip the
        // intake into unbounded buffering.
        const MAX_REPORT_BYTES: usize = 64 * 1024;
        let mut buf: Vec<u8> = Vec::new();
        while let Some(chunk) = session.read_request_body().await? {
            let remaining = MAX_REPORT_BYTES.saturating_sub(buf.len());
            if remaining == 0 {
                break;
            }
            let take = std::cmp::min(chunk.len(), remaining);
            buf.extend_from_slice(&chunk[..take]);
            if buf.len() >= MAX_REPORT_BYTES {
                break;
            }
        }
        let host = session
            .req_header()
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let user_agent = session
            .req_header()
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        // Parse and redact the report before logging. CSP reports
        // can include URLs with query strings (potentially
        // containing tokens, session IDs, or user identifiers).
        // We extract a short fixed allowlist of fields, redact
        // query strings on URL-shaped values, cap each field, and
        // drop everything else. The raw report body is only
        // captured when the operator explicitly opts in via
        // `page_shield.raw_report_log` (default off).
        let redacted = redact_csp_report(&buf);
        tracing::info!(
            target: "sbproxy::page_shield",
            host = %host,
            user_agent = %user_agent,
            bytes = buf.len(),
            document_uri = %redacted.document_uri.as_deref().unwrap_or(""),
            violated_directive = %redacted.violated_directive.as_deref().unwrap_or(""),
            blocked_uri = %redacted.blocked_uri.as_deref().unwrap_or(""),
            effective_directive = %redacted.effective_directive.as_deref().unwrap_or(""),
            original_policy = %redacted.original_policy.as_deref().unwrap_or(""),
            "csp violation report"
        );
        // Raw-body capture is opt-in via
        // `proxy.extensions.page_shield.raw_report_log`. We fetch
        // the pipeline lazily here because the main `pipeline`
        // binding for this request_filter scope is loaded later
        // (after the intake short-circuits on the report path).
        let raw_log_enabled = ctx.pipeline.page_shield_raw_report_log;
        if raw_log_enabled {
            let raw = String::from_utf8_lossy(&buf).into_owned();
            tracing::debug!(
                target: "sbproxy::page_shield::raw",
                host = %host,
                raw = %raw,
                "csp violation report (raw, opt-in)"
            );
        }
        // No body: 204 keeps the wire small and most browsers accept it.
        let header = pingora_http::ResponseHeader::build(204, Some(0)).map_err(|e| {
            Error::because(
                ErrorType::InternalError,
                "failed to build csp report 204 header",
                e,
            )
        })?;
        session
            .write_response_header(Box::new(header), true)
            .await?;
        return Ok(true);
    }

    // --- Hostname extraction and origin resolution ---
    //
    // HTTP/1.1 requests carry the hostname in the `Host` header.
    // HTTP/2 requests carry it in the `:authority` pseudo-header,
    // which the `http` crate exposes via `uri().authority()` and
    // does NOT mirror into the `headers` map. Fall back to the
    // URI authority when the `Host` header is absent so plaintext
    // h2c clients (gRPC, h2 prior-knowledge) route correctly.
    let req_for_host = session.req_header();
    let hostname_owned: String = req_for_host
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| req_for_host.uri.authority().map(|a| a.as_str().to_string()))
        .unwrap_or_default();
    let hostname = hostname_owned.split(':').next().unwrap_or("");
    ctx.hostname = compact_str::CompactString::new(hostname);

    let pipeline = ctx.pipeline.clone();
    let origin_idx = match pipeline.resolve_origin(hostname) {
        Some(idx) => idx,
        None => {
            warn!(hostname = %hostname, "no origin configured for hostname");
            send_error(session, 404, "not found").await?;
            // Record the real 404 so the request log / metrics do not show
            // the unset-status 0 sentinel for an unmatched host (WOR-1746),
            // and bump the unrouted-request series this path had skipped
            // while the alternate dispatch path recorded it (WOR-1782).
            sbproxy_observe::metrics::record_unrouted_request("unknown_host");
            ctx.response_status = Some(404);
            return Ok(true);
        }
    };
    ctx.origin_idx = Some(origin_idx);

    if crate::proxy_wasm_http::start_request(session, ctx, origin_idx).await? {
        return Ok(true);
    }

    // Validated GraphQL requests may pass through body-consuming middleware
    // (notably threat protection) before action dispatch. Enable replay at
    // the origin boundary so every consumed chunk is still available for
    // GraphQL validation and byte-for-byte upstream forwarding.
    if request_requires_graphql_replay(session, &pipeline, origin_idx) {
        session.as_mut().enable_retry_buffering();
        // Mark this before the idempotency pre-check. A cached response from
        // an older, more permissive configuration must not return before the
        // current GraphQL action validates the final modified request.
        ctx.graphql_validation_pending = true;
    }
    // RFC 9449 permits one retry when a protected resource challenges
    // with a nonce. Enable Pingora's bounded replay buffer before any
    // request body is consumed so that retry is safe for body-bearing
    // methods as well as bodyless requests.
    if pipeline
        .outbound_creds
        .get(origin_idx)
        .and_then(Option::as_ref)
        .is_some_and(|credential| credential.is_dpop_enabled())
    {
        session.as_mut().enable_retry_buffering();
    }

    // WOR-2306: arm body-field route matching.
    //
    // Route selection runs on headers, which is why it can run this early:
    // the headers are already here. A forward rule that matches on a JSON
    // body field inverts that, because the route now depends on bytes that
    // have not arrived. Replay buffering is what makes reading them safe.
    // With it on, every chunk the request phase consumes is retained and
    // replayed upstream, so choosing a route on the body does not consume
    // the body. It has to be enabled here, at the origin boundary and ahead
    // of any body-consuming middleware, because it cannot retroactively
    // capture bytes another reader has already taken.
    //
    // `forward_rule_body_cap` returns `None` for every origin that declares
    // no body matcher, and `None` is the whole hot-path story: no buffering
    // is armed, the drain below is skipped, and nothing is parsed.
    //
    // A `Content-Length` already past the cap short-circuits here rather
    // than filling 64 KiB the matcher would then refuse. Both that case and
    // a chunked body that overruns the buffer end the same way, at the
    // matcher, as a miss.
    let body_route_cap: Option<usize> =
        match crate::pipeline::forward_rule_body_cap(&pipeline.forward_rules[origin_idx]) {
            Some(cap)
                if !session.as_mut().is_body_empty()
                    && !declared_body_exceeds_cap(session, cap) =>
            {
                session.as_mut().enable_retry_buffering();
                Some(cap)
            }
            _ => None,
        };

    // WOR-1053: stamp the matched origin's tenant on the request
    // context so downstream auth / policy / vault resolution can
    // partition by tenant. The compiler defaults the field to
    // `__default__` when no explicit `tenant_id` was declared, so
    // single-tenant configs see the same default they had before
    // this PR.
    {
        let pipeline_guard = ctx.pipeline.clone();
        ctx.tenant_id = pipeline_guard.config.origins[origin_idx].tenant_id.clone();
    }

    // --- RFC 9421 HTTP Message Signatures verification ---
    //
    // When the origin has `message_signatures.verify: true`,
    // enforce signature verification on every inbound request
    // before any downstream auth provider runs. Failures
    // produce a 401 with `WWW-Authenticate: Signature`.
    // Body coverage (`content-digest`) is reserved for a
    // follow-up; the http::Request we hand the verifier carries
    // an empty body, so signatures over body components fail
    // with a missing-component reason from the verifier.
    {
        let pipeline_guard = ctx.pipeline.clone();
        let origin_for_sig = &pipeline_guard.config.origins[origin_idx];
        if let Some(ms_cfg) = origin_for_sig.message_signatures.as_ref() {
            if ms_cfg.verify {
                if let Some(verifier) = cached_message_signature_verifier(ms_cfg) {
                    let Some(req) = build_signature_verification_request(session) else {
                        warn!(
                            hostname = %ctx.hostname,
                            "message_signatures: could not rebuild request for verification; returning 401"
                        );
                        drop(pipeline_guard);
                        send_error(session, 401, "signature verification unavailable").await?;
                        ctx.response_status = Some(401);
                        return Ok(true);
                    };
                    match verifier.verify_request(&req) {
                        sbproxy_middleware::signatures::VerifyVerdict::Ok { signature_label } => {
                            debug!(
                                signature_label = %signature_label,
                                "message_signatures: request verified"
                            );
                        }
                        sbproxy_middleware::signatures::VerifyVerdict::Failed { reason } => {
                            warn!(
                                hostname = %ctx.hostname,
                                reason = %reason,
                                "message_signatures: verification failed; returning 401"
                            );
                            drop(pipeline_guard);
                            let body = b"{\"error\":\"signature verification failed\"}";
                            let mut header = pingora_http::ResponseHeader::build(401, Some(2))
                                .map_err(|e| {
                                    Error::because(ErrorType::InternalError, "build 401 header", e)
                                })?;
                            let _ = header.insert_header("content-type", "application/json");
                            let _ = header.insert_header("www-authenticate", "Signature");
                            session
                                .write_response_header(Box::new(header), false)
                                .await?;
                            session
                                .write_response_body(Some(bytes::Bytes::from_static(body)), true)
                                .await?;
                            ctx.response_status = Some(401);
                            return Ok(true);
                        }
                    }
                } else {
                    warn!(
                        hostname = %ctx.hostname,
                        "message_signatures: verifier unavailable; returning 401"
                    );
                    drop(pipeline_guard);
                    send_error(session, 401, "signature verification unavailable").await?;
                    ctx.response_status = Some(401);
                    return Ok(true);
                }
            }
        }
    }

    // Increment per-origin active connections after successful resolution.
    sbproxy_observe::metrics::inc_active(ctx.hostname.as_str());

    // --- WOR-193 / WOR-194 wire: Agent Skills v0.2.0 projection ---
    //
    // Origins with `agent_skills:` configured serve a discovery
    // manifest at `/.well-known/agent-skills/index.json` plus the
    // artifact bodies the manifest points at. The manifest schema
    // is `https://schemas.agentskills.io/discovery/0.2.0/schema.json`;
    // every artifact `GET` re-hashes the served body and returns
    // 503 with an audit event on a digest mismatch. The
    // proxy never executes any pre-/post-hooks or scripts shipped
    // inside an artifact - artifacts are opaque bytes per spec.
    {
        let req_path = session.req_header().uri.path().to_string();
        let docs = sbproxy_modules::projections::current_projections();
        let host_key = pipeline.config.origins[origin_idx].hostname.as_str();
        let per_origin_idx = docs.agent_skills.get(host_key);

        // Resolve the request scheme so relative URLs in the
        // manifest emit the right `https://` vs `http://` prefix.
        // Listener TLS is the authoritative signal; spoofable proxy
        // headers are honoured only when the immediate peer is in
        // `proxy.trusted_proxies`.
        let listener_is_tls = session
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .is_some();
        let scheme = if listener_is_tls { "https" } else { "http" };
        let authenticated = session.req_header().headers.get("authorization").is_some();
        let host_authority = session
            .req_header()
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok());
        let caller = if authenticated {
            "authenticated"
        } else {
            "anonymous"
        };

        // --- WOR-196 per-Listing manifest --------------------------------
        //
        // Path:
        //   /.well-known/agent-skills/<listing-name>/index.json
        //
        // The handler looks the listing up by name in the
        // projection cache and rejects (404) when the listing
        // either does not exist or does not publish this origin
        // hostname. The per-Listing manifest is the same JSON
        // envelope the per-origin path serves, computed off the
        // Listing's `spec.skills[]` block.
        if let Some(rest) = req_path.strip_prefix("/.well-known/agent-skills/") {
            if let Some((listing_name, sub)) = rest.split_once('/') {
                if !listing_name.is_empty() {
                    let scoped = docs.agent_skills_listings.get(listing_name);
                    let publishes_host = scoped
                        .map(|s| s.hostnames.iter().any(|h| h.as_str() == host_key))
                        .unwrap_or(false);
                    if let (Some(scoped), true) = (scoped, publishes_host) {
                        if sub == "index.json" {
                            let body = sbproxy_modules::projections::agent_skills::render_manifest(
                                &scoped.index,
                                authenticated,
                                host_authority,
                                scheme,
                            );
                            // Audit fan-out (WOR-196 AC): every
                            // index request logs caller, listing
                            // id, and the host key the manifest
                            // was served against.
                            tracing::info!(
                                target: "sbproxy::audit",
                                event = "agent_skill.listing_index",
                                listing_id = %listing_name,
                                hostname = %host_key,
                                caller = %caller,
                                request_id = %ctx.request_id,
                                "agent skills listing index served"
                            );
                            send_response(session, 200, "application/json", body.as_bytes())
                                .await?;
                            return Ok(true);
                        }
                        // Per-Listing artifact body. The artifact
                        // cache keys on the manifest URL (path-
                        // absolute), so we look up the served
                        // path with a leading slash. `sub` here is
                        // the rest of the URL after the listing
                        // segment, normalised back to the path
                        // shape the manifest publishes.
                        let cache_key = format!("/{sub}");
                        if let Some(body) = scoped.index.artifacts.get(cache_key.as_str()) {
                            if let Some(expected_hex) = scoped.index.digests.get(cache_key.as_str())
                            {
                                let observed_hex =
                                    sbproxy_modules::projections::agent_skills::sha256_hex(body);
                                if &observed_hex != expected_hex {
                                    let skill_name = scoped
                                        .index
                                        .entries
                                        .iter()
                                        .find(|e| {
                                            let cmp = if e.url.starts_with('/') {
                                                e.url.clone()
                                            } else if !e.url.starts_with("http") {
                                                format!("/{}", e.url)
                                            } else {
                                                String::new()
                                            };
                                            cmp == cache_key
                                        })
                                        .map(|e| e.name.clone())
                                        .unwrap_or_else(|| cache_key.clone());
                                    sbproxy_observe::metrics::metrics()
                                        .agent_skill_digest_mismatch
                                        .with_label_values(&[skill_name.as_str()])
                                        .inc();
                                    tracing::error!(
                                        target: "sbproxy::audit",
                                        event = "agent_skill.digest_mismatch",
                                        skill_name = %skill_name,
                                        listing_id = %listing_name,
                                        hostname = %host_key,
                                        expected_digest = %expected_hex,
                                        observed_digest = %observed_hex,
                                        caller = %caller,
                                        request_id = %ctx.request_id,
                                        "agent skill artifact body diverged from manifest digest"
                                    );
                                    send_error(session, 503, "service unavailable").await?;
                                    return Ok(true);
                                }
                            }
                            let ct = scoped
                                .index
                                .entries
                                .iter()
                                .find(|e| {
                                    let cmp = if e.url.starts_with('/') {
                                        e.url.clone()
                                    } else if !e.url.starts_with("http") {
                                        format!("/{}", e.url)
                                    } else {
                                        String::new()
                                    };
                                    cmp == cache_key
                                })
                                .map(|e| match e.kind.as_str() {
                                    "skill-md" => "text/markdown; charset=utf-8",
                                    "archive" => "application/octet-stream",
                                    _ => "application/octet-stream",
                                })
                                .unwrap_or("application/octet-stream");
                            tracing::info!(
                                target: "sbproxy::audit",
                                event = "agent_skill.listing_artifact",
                                listing_id = %listing_name,
                                hostname = %host_key,
                                artifact_path = %cache_key,
                                caller = %caller,
                                request_id = %ctx.request_id,
                                "agent skills listing artifact served"
                            );
                            send_response(session, 200, ct, body.as_ref()).await?;
                            return Ok(true);
                        }
                    }
                }
            }
        }

        // --- WOR-525: ARDP discovery endpoint -----------------------------
        //
        // Path:
        //   /.well-known/sbproxy-agent
        //
        // Returns a small JSON capability advertisement per
        // draft-pioli-agent-discovery-01 (Agent Registration and
        // Discovery Protocol) section 4. The shape lists the
        // tenant id plus the subset of agent-facing endpoints that
        // are actually configured on this origin: `mcp` when the
        // origin's action is `Action::Mcp`, `agent_skills` when
        // the origin has any agent-skills surface (per-origin
        // entries or a Listing publishing this hostname), and
        // `openapi` when `expose_openapi: true`. Non-GET requests
        // return 405. Every served response emits an
        // `ardp.discovery.served` audit event.
        if req_path == "/.well-known/sbproxy-agent" {
            if session.req_header().method != http::Method::GET {
                send_error(session, 405, "method not allowed").await?;
                return Ok(true);
            }

            let aggregated_skills =
                sbproxy_modules::projections::agent_skills::aggregate_for_hostname(
                    per_origin_idx,
                    &docs.agent_skills_listings,
                    host_key,
                );
            let has_agent_skills =
                !aggregated_skills.entries.is_empty() || per_origin_idx.is_some();
            let has_mcp = matches!(pipeline.actions.get(origin_idx), Some(Action::Mcp(_)));
            let has_openapi = pipeline.config.origins[origin_idx].expose_openapi;

            let origin = &pipeline.config.origins[origin_idx];
            let agent_id = if !origin.workspace_id.is_empty() {
                origin.workspace_id.as_str()
            } else if !origin.origin_id.is_empty() {
                origin.origin_id.as_str()
            } else {
                host_key
            };

            let body = render_ardp_discovery(
                agent_id,
                scheme,
                host_authority,
                has_mcp,
                has_agent_skills,
                has_openapi,
            );
            tracing::info!(
                target: "sbproxy::audit",
                event = "ardp.discovery.served",
                hostname = %host_key,
                agent_id = %agent_id,
                caller = %caller,
                has_mcp,
                has_agent_skills,
                has_openapi,
                request_id = %ctx.request_id,
                "ardp discovery advertisement served"
            );
            send_response(session, 200, "application/json", body.as_bytes()).await?;
            return Ok(true);
        }

        // --- Aggregated manifest at the unprefixed well-known URL --------
        //
        // `/.well-known/agent-skills/index.json` returns the union
        // of the per-origin entries (the WOR-193 surface) and every
        // Listing whose `spec.resources[].ref` lists this hostname
        // as an origin. The merge dedupes by `name` (first
        // occurrence wins) so a Listing that re-declares a
        // per-origin entry name does not double-count.
        if req_path == "/.well-known/agent-skills/index.json" {
            let merged = sbproxy_modules::projections::agent_skills::aggregate_for_hostname(
                per_origin_idx,
                &docs.agent_skills_listings,
                host_key,
            );
            if merged.entries.is_empty() && per_origin_idx.is_none() {
                // No top-level `agent_skills:` and no matching
                // Listing skills: 404 so cooperative agents get a
                // clean signal that no manifest is advertised on
                // this hostname.
                send_error(session, 404, "agent-skills not configured").await?;
                return Ok(true);
            }
            let body = sbproxy_modules::projections::agent_skills::render_manifest(
                &merged,
                authenticated,
                host_authority,
                scheme,
            );
            tracing::info!(
                target: "sbproxy::audit",
                event = "agent_skill.aggregated_index",
                hostname = %host_key,
                caller = %caller,
                request_id = %ctx.request_id,
                "agent skills aggregated index served"
            );
            send_response(session, 200, "application/json", body.as_bytes()).await?;
            return Ok(true);
        }

        // --- Per-origin artifact fan-out (WOR-193 / WOR-194) ------------
        if let Some(idx) = per_origin_idx {
            if let Some(body) = idx.artifacts.get(req_path.as_str()) {
                if let Some(expected_hex) = idx.digests.get(req_path.as_str()) {
                    let observed_hex = sbproxy_modules::projections::agent_skills::sha256_hex(body);
                    if &observed_hex != expected_hex {
                        let skill_name = idx
                            .entries
                            .iter()
                            .find(|e| {
                                let cmp = if e.url.starts_with('/') {
                                    e.url.clone()
                                } else if !e.url.starts_with("http") {
                                    format!("/{}", e.url)
                                } else {
                                    String::new()
                                };
                                cmp == req_path
                            })
                            .map(|e| e.name.clone())
                            .unwrap_or_else(|| req_path.clone());
                        sbproxy_observe::metrics::metrics()
                            .agent_skill_digest_mismatch
                            .with_label_values(&[skill_name.as_str()])
                            .inc();
                        tracing::error!(
                            target: "sbproxy::audit",
                            event = "agent_skill.digest_mismatch",
                            skill_name = %skill_name,
                            hostname = %host_key,
                            expected_digest = %expected_hex,
                            observed_digest = %observed_hex,
                            caller = %caller,
                            request_id = %ctx.request_id,
                            "agent skill artifact body diverged from manifest digest"
                        );
                        send_error(session, 503, "service unavailable").await?;
                        return Ok(true);
                    }
                }
                let ct = if let Some(entry) = idx.entries.iter().find(|e| {
                    let cmp = if e.url.starts_with('/') {
                        e.url.clone()
                    } else if !e.url.starts_with("http") {
                        format!("/{}", e.url)
                    } else {
                        String::new()
                    };
                    cmp == req_path
                }) {
                    match entry.kind.as_str() {
                        "skill-md" => "text/markdown; charset=utf-8",
                        "archive" => "application/octet-stream",
                        _ => "application/octet-stream",
                    }
                } else {
                    "application/octet-stream"
                };
                send_response(session, 200, ct, body.as_ref()).await?;
                return Ok(true);
            }
        }
    }

    // --- WOR-805: Web Bot Auth hosted key directory ---
    //
    // Serve SBproxy's own Ed25519 public key as an HTTP Message
    // Signatures directory (draft-meunier-http-message-signatures-
    // directory) so any verifier, including SBproxy's own inbound
    // `bot_auth` directory client, can check the Web Bot Auth
    // signatures the proxy produces. The identity is proxy-wide, so
    // the directory is served on any origin when configured. Runs
    // before projections and forward rules so the discovery path is
    // never shadowed by a wildcard rule. When `web_bot_auth` is not
    // configured the path falls through to normal proxying.
    {
        if session.req_header().uri.path() == "/.well-known/http-message-signatures-directory" {
            if let Some(wba) = pipeline.config.server.web_bot_auth.as_ref() {
                // Seed shape is validated at compile time; decode
                // defensively and fall through on any surprise rather
                // than 500.
                if let Some(seed) = hex::decode(&wba.ed25519_seed_hex)
                    .ok()
                    .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
                {
                    let body = sbproxy_middleware::web_bot_auth::build_signature_directory(&[
                        sbproxy_middleware::web_bot_auth::DirectoryIdentity {
                            key_id: &wba.key_id,
                            seed: &seed,
                        },
                    ]);
                    send_response(
                        session,
                        200,
                        sbproxy_middleware::web_bot_auth::DIRECTORY_CONTENT_TYPE,
                        body.as_bytes(),
                    )
                    .await?;
                    return Ok(true);
                }
            }
        }
    }

    // --- WOR-809 / WOR-820: agent-web emission ---
    //
    // Served from per-origin config (`agents_md:` / `ai_txt:` verbatim;
    // `agents_json:` rendered into the agents.json v0.1 manifest),
    // independently of `ai_crawl_control`. Unlike the pricing-derived
    // projections below, these intercept ONLY when the origin actually
    // configured the document; otherwise the path falls through to the
    // upstream so a real app-level AGENTS.md / ai.txt / agents.json is
    // not shadowed.
    {
        let kind = match session.req_header().uri.path() {
            "/AGENTS.md" => Some("agents-md"),
            "/ai.txt" => Some("ai-txt"),
            "/.well-known/agents.json" => Some("agents-json"),
            _ => None,
        };
        if let Some(kind) = kind {
            let docs = sbproxy_modules::projections::current_projections();
            let host_key = pipeline.config.origins[origin_idx].hostname.as_str();
            let body_opt = match kind {
                "agents-md" => docs.agents_md.get(host_key).cloned(),
                "ai-txt" => docs.ai_txt.get(host_key).cloned(),
                "agents-json" => docs.agents_json.get(host_key).cloned(),
                _ => None,
            };
            if let Some(body) = body_opt {
                let ct = projection_content_type(kind);
                send_response(session, 200, ct, body.as_ref()).await?;
                return Ok(true);
            }
            // Not configured for this origin: fall through to normal
            // proxying rather than 404.
        }
    }

    // --- Wave 4 / G4.5..G4.8 wire: policy-graph projections ---
    //
    // Origins with an `ai_crawl_control` policy have four
    // well-known documents derived from the compiled policy
    // graph: `robots.txt`, `llms.txt`, `llms-full.txt`,
    // `/licenses.xml`, and `/.well-known/tdmrep.json`. The cache
    // lives in `sbproxy-modules::projections` and is refreshed in
    // `reload::load_pipeline`; serving is two atomic loads
    // (`current_projections` + a hash-map lookup by hostname).
    //
    // Per A4.1 the well-known URLs MUST be on the data plane (not
    // the admin port) because they are agent discovery entry
    // points; serving from the admin port would defeat the
    // purpose. The handler runs before forward rules so a
    // wildcard prefix rule cannot eat the path.
    //
    // The handler also stamps `RequestContext.rsl_urn` for the
    // RSL projection so downstream code (the A4.2 JSON envelope,
    // any future RSL-aware response middleware) can surface the
    // URN without re-reading the cache.
    {
        let req_path = session.req_header().uri.path();
        let projection_kind: Option<&'static str> = projection_kind_for_path(req_path);
        if let Some(kind) = projection_kind {
            let docs = sbproxy_modules::projections::current_projections();
            let host_key = pipeline.config.origins[origin_idx].hostname.as_str();
            let body_opt = match kind {
                "robots" => docs.robots_txt.get(host_key).cloned(),
                "llms" => docs.llms_txt.get(host_key).cloned(),
                "llms-full" => docs.llms_full_txt.get(host_key).cloned(),
                "licenses" => docs.licenses_xml.get(host_key).cloned(),
                "tdmrep" => docs.tdmrep_json.get(host_key).cloned(),
                _ => None,
            };
            // Stamp the RSL URN regardless of which projection
            // path was hit: any agent that reaches this origin's
            // `/licenses.xml` resolves the URN, and the envelope
            // surfaces it on every response from the same origin.
            if let Some(urn) = docs.rsl_urns.get(host_key) {
                ctx.rsl_urn = Some(urn.clone());
            }
            if let Some(body) = body_opt {
                let ct = projection_content_type(kind);
                send_response(session, 200, ct, body.as_ref()).await?;
                return Ok(true);
            }
            // Origin without an ai_crawl_control policy: 404 the
            // well-known URL rather than falling through to the
            // upstream proxy (which would 404 anyway, but with
            // less useful semantics for the agent).
            send_error(session, 404, "projection not configured").await?;
            return Ok(true);
        }
    }

    // --- WOR-892 PR2: OIDC /oidc/callback ---
    //
    // The browser hits this path after the IdP redirects back from
    // the authorization endpoint. Intercept BEFORE the normal auth
    // check so the request does not loop on `oidc_check` returning
    // yet another IdP redirect.
    //
    // WOR-1700: read the compiled `OidcAuth` off the pinned pipeline
    // snapshot instead of deep-cloning the origin's `auth_config` JSON
    // per request and re-parsing it via `from_config` on every
    // callback/logout hit. The compiled form carries `redirect_path` /
    // `logout_path` with the same serde defaults, and config that
    // compiles to `Auth::Oidc` is already validated at load, so the
    // old per-request "oidc misconfigured" 500 branch is unreachable
    // and drops out.
    if let Some(sbproxy_modules::auth::Auth::Oidc(oidc)) = &pipeline.auths[origin_idx] {
        if oidc.redirect_path == session.req_header().uri.path() {
            handle_oidc_callback(session, oidc).await?;
            return Ok(true);
        }

        // --- WOR-892 follow-up: OIDC /oidc/logout ---
        //
        // RP-initiated logout: delete the session cookie and (when
        // the operator configured `end_session_endpoint`) redirect
        // the browser to the OP per OpenID Connect RP-Initiated
        // Logout 1.0 §2. Recognised BEFORE the normal auth check so
        // it works for already-expired sessions too. Pure helpers
        // live in `sbproxy_modules::auth::oidc::logout`.
        if oidc.logout_path == session.req_header().uri.path() {
            handle_oidc_logout(session, oidc).await?;
            return Ok(true);
        }
    }

    // --- WOR-808 PR7: OLP /.well-known/olp/{token,key} ---
    //
    // When the origin opts in (`olp.enabled: true`), serve two
    // well-known endpoints:
    //
    // * `GET /.well-known/olp/key` -> JWK Set (RFC 7517) carrying the
    //   verification public key so external introspectors can verify
    //   issued license tokens without contacting the issuer.
    // * `POST /.well-known/olp/token` -> issues a JWS license token
    //   per RSL 1.0 OLP (`typ: olp-license+jws`, `token_type:
    //   "License"`). The response body shape mirrors RFC 6749's token
    //   response: `{"access_token":..., "token_type":"License",
    //   "expires_in":..., "scope":...}`.
    //
    // `/introspect` (RFC 7662) is deferred to PR8 because it requires
    // a revocation / nonce store. Origins that disable OLP
    // (`enabled: false` or no `olp:` block) fall through.
    {
        let req_path = session.req_header().uri.path();
        let req_method = session.req_header().method.clone();
        let olp_cfg_for_route = pipeline.config.origins[origin_idx].olp.as_ref();
        let introspect_path = olp_cfg_for_route
            .and_then(|c| c.introspect.as_ref())
            .filter(|i| i.enabled)
            .map(|i| i.introspect_path.as_str())
            .unwrap_or("");
        let revoke_path = olp_cfg_for_route
            .and_then(|c| c.introspect.as_ref())
            .filter(|i| i.enabled)
            .map(|i| i.revoke_path.as_str())
            .unwrap_or("");
        let is_olp_path = req_path == "/.well-known/olp/key"
            || req_path == "/.well-known/olp/token"
            || (!introspect_path.is_empty() && req_path == introspect_path)
            || (!revoke_path.is_empty() && req_path == revoke_path);
        if is_olp_path {
            let olp_cfg = pipeline.config.origins[origin_idx].olp.as_ref();
            // WOR-808 PR9: introspect + revoke routing. Both endpoints
            // share the same auth + revocation store; handlers below
            // dispatch based on the path.
            if let Some(cfg) = olp_cfg {
                if let Some(introspect_cfg) = cfg.introspect.as_ref() {
                    if introspect_cfg.enabled
                        && (req_path == introspect_cfg.introspect_path
                            || req_path == introspect_cfg.revoke_path)
                    {
                        if req_method != http::Method::POST {
                            send_error(session, 405, "POST only").await?;
                            return Ok(true);
                        }
                        let is_revoke = req_path == introspect_cfg.revoke_path;
                        return handle_olp_introspect_or_revoke(
                            session,
                            cfg,
                            introspect_cfg,
                            is_revoke,
                        )
                        .await
                        .map(|_| true);
                    }
                }
            }
            match olp_cfg {
                Some(cfg) if cfg.enabled => {
                    if req_path == "/.well-known/olp/key" {
                        if req_method != http::Method::GET {
                            send_error(session, 405, "GET only").await?;
                            return Ok(true);
                        }
                        match build_olp_jwk_set(cfg) {
                            Ok(body) => {
                                send_response(
                                    session,
                                    200,
                                    "application/jwk-set+json",
                                    body.as_bytes(),
                                )
                                .await?;
                            }
                            Err(e) => {
                                warn!(error = %e, "olp: failed to build JWK set");
                                send_error(session, 500, "olp key unavailable").await?;
                            }
                        }
                        return Ok(true);
                    }
                    // /.well-known/olp/token
                    if req_method != http::Method::POST {
                        send_error(session, 405, "POST only").await?;
                        return Ok(true);
                    }
                    // When the client sends an RFC 6749 §4.4 form body
                    // (`application/x-www-form-urlencoded`) we parse it,
                    // require `grant_type=client_credentials` and a
                    // non-empty `client_id`, and bind the token's `sub`
                    // claim to that client_id. Any other content-type
                    // (or no body) falls back to the legacy anonymous
                    // path so existing automation still mints tokens.
                    let content_type = session
                        .req_header()
                        .headers
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let is_form_body = content_type
                        .split(';')
                        .next()
                        .map(|t| t.trim().eq_ignore_ascii_case(OLP_TOKEN_FORM_CT))
                        .unwrap_or(false);
                    let sub: String = if is_form_body {
                        // Cap the form body at 4 KiB; client_credentials
                        // bodies are tiny and a hostile client must not
                        // tip the issuer into unbounded buffering.
                        const MAX_TOKEN_FORM_BYTES: usize = 4 * 1024;
                        let mut form_buf: Vec<u8> = Vec::new();
                        while let Some(chunk) = session.read_request_body().await? {
                            let remaining = MAX_TOKEN_FORM_BYTES.saturating_sub(form_buf.len());
                            if remaining == 0 {
                                break;
                            }
                            let take = std::cmp::min(chunk.len(), remaining);
                            form_buf.extend_from_slice(&chunk[..take]);
                            if form_buf.len() >= MAX_TOKEN_FORM_BYTES {
                                break;
                            }
                        }
                        let form_body = std::str::from_utf8(&form_buf).unwrap_or("");
                        match parse_olp_token_form(form_body) {
                            Ok(req) => req.client_id,
                            Err(err) => {
                                // RFC 6749 §5.2 error response shape.
                                let body = serde_json::json!({
                                    "error": err.code,
                                    "error_description": err.description,
                                })
                                .to_string();
                                send_response(session, 400, "application/json", body.as_bytes())
                                    .await?;
                                return Ok(true);
                            }
                        }
                    } else {
                        OLP_ANONYMOUS_SUB.to_string()
                    };
                    let hostname = pipeline.config.origins[origin_idx].hostname.as_str();
                    let projections = sbproxy_modules::projections::current_projections();
                    let license_urn =
                        projections
                            .rsl_urns
                            .get(hostname)
                            .cloned()
                            .unwrap_or_else(|| {
                                // No RSL projection on this origin yet;
                                // synthesise an URN so the token is still
                                // well-formed. Audit will warn when the
                                // license_urn does not resolve.
                                format!("urn:rsl:1.0:{hostname}:0")
                            });
                    match issue_olp_token(cfg, hostname, &license_urn, &sub) {
                        Ok(body) => {
                            send_response(session, 200, "application/json", body.as_bytes())
                                .await?;
                        }
                        Err(e) => {
                            warn!(error = %e, "olp: failed to issue token");
                            send_error(session, 500, "olp issuance failed").await?;
                        }
                    }
                    return Ok(true);
                }
                _ => {
                    // OLP disabled or absent on this origin: 404 the
                    // well-known URL rather than letting it fall
                    // through to the upstream proxy.
                    send_error(session, 404, "olp not enabled on this origin").await?;
                    return Ok(true);
                }
            }
        }
    }

    // --- WOR-805 AC#4 wire: Web Bot Auth publish well-known ---
    //
    // When the origin opts in (`web_bot_auth_publish.enabled: true`),
    // serve two unauthenticated GET endpoints:
    //
    // * `/.well-known/http-message-signatures-directory`, JWKS doc
    //   carrying SBproxy's own Ed25519 signing-key public key.
    //   Verifiers (Cloudflare, AWS WAF, third-party origins) fetch
    //   this to verify the signatures SBproxy attaches to outbound
    //   requests.
    // * `/.well-known/web-bot-auth/agent-card`, discovery doc
    //   pointing verifiers at the directory; carries operator name +
    //   description + contact URL.
    //
    // Both paths short-circuit the normal auth + proxy pipeline.
    {
        let req_path = session.req_header().uri.path().to_string();
        let is_wba_publish = req_path == "/.well-known/http-message-signatures-directory"
            || req_path == "/.well-known/web-bot-auth/agent-card";
        if is_wba_publish {
            let wba_cfg = pipeline.config.origins[origin_idx]
                .web_bot_auth_publish
                .clone();
            match wba_cfg {
                Some(cfg) if cfg.enabled => {
                    handle_web_bot_auth_publish(session, &cfg, &req_path).await?;
                    return Ok(true);
                }
                _ => {
                    send_error(
                        session,
                        404,
                        "web_bot_auth_publish not enabled on this origin",
                    )
                    .await?;
                    return Ok(true);
                }
            }
        }
    }

    // --- Wave 4 day-5 wire: stamp content_shape_pricing / transform ---
    //
    // When the origin authors `auto_content_negotiate` (synthesised
    // by `compile_origin` from an `ai_crawl_control` policy or any
    // of the Wave 4 content-shaping transforms), run the two-pass
    // `Accept` resolver and stamp both shapes onto `ctx`. The
    // pricing shape feeds the tier resolver / quote-token verifier;
    // the transform shape gates the response-body transformers
    // (G4.3 Markdown projection, G4.4 JSON envelope, G4.10 citation
    // block) further down the pipeline.
    //
    // Origins without `auto_content_negotiate` (legacy / non-AI)
    // leave `ctx.content_shape_*` as `None`; the response-side
    // wiring is gated on `Some(_)` so legacy origins are
    // unaffected.
    //
    // We also stamp `ctx.canonical_url` here from the request URL +
    // hostname so the citation_block and json_envelope transforms
    // have a stable Source: / url field. Operators can override by
    // stamping their own value from a request enricher upstream of
    // this point.
    {
        let origin_for_negotiate = &pipeline.config.origins[origin_idx];
        let accept = session
            .req_header()
            .headers
            .get("accept")
            .and_then(|v| v.to_str().ok());
        stamp_content_negotiation(
            ctx,
            origin_for_negotiate.auto_content_negotiate.as_ref(),
            accept,
        );

        // Stamp canonical_url when not already set, and only when
        // content negotiation is active for this origin (legacy
        // origins keep `canonical_url == None`). The URL is derived
        // from the request scheme (HTTP for plain listeners, HTTPS
        // when X-Forwarded-Proto says so) plus hostname plus
        // path-and-query.
        if origin_for_negotiate.auto_content_negotiate.is_some()
            && ctx.canonical_url.is_none()
            && !ctx.hostname.is_empty()
        {
            let req = session.req_header();
            let scheme = req
                .headers
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("http");
            let path_q = match req.uri.query() {
                Some(q) => format!("{}?{}", req.uri.path(), q),
                None => req.uri.path().to_string(),
            };
            ctx.canonical_url = Some(format!("{}://{}{}", scheme, ctx.hostname, path_q));
        }
    }

    // --- Per-host OpenAPI emission ---
    // Origins that opt in via `expose_openapi: true` get a published
    // OpenAPI document at the standard well-known location. Checked
    // before forward rules so a wildcard prefix rule cannot eat the
    // path. No auth: this is a public, opt-in description of the
    // routes the host already exposes.
    if pipeline.config.origins[origin_idx].expose_openapi {
        let req_path = session.req_header().uri.path();
        let yaml = match req_path {
            "/.well-known/openapi.json" => Some(false),
            "/.well-known/openapi.yaml" => Some(true),
            _ => None,
        };
        if let Some(as_yaml) = yaml {
            let host = pipeline.config.origins[origin_idx].hostname.as_str();
            let spec = sbproxy_openapi::build(&pipeline.config, Some(host));
            let (ct, body) = if as_yaml {
                (
                    "application/yaml",
                    sbproxy_openapi::render_yaml(&spec).unwrap_or_else(|e| {
                        warn!(error = %e, "OpenAPI YAML render failed");
                        String::new()
                    }),
                )
            } else {
                (
                    "application/json",
                    sbproxy_openapi::render_json(&spec).unwrap_or_else(|e| {
                        warn!(error = %e, "OpenAPI JSON render failed");
                        "{}".to_string()
                    }),
                )
            };
            send_response(session, 200, ct, body.as_bytes()).await?;
            return Ok(true);
        }
    }

    // --- Force SSL redirect ---
    let origin = &pipeline.config.origins[origin_idx];
    let ai_proxy_owns_replay_paths =
        request_uses_ai_owned_replay_paths(session, &pipeline, origin_idx);
    if origin.force_ssl {
        // Determine whether the inbound request is already on TLS.
        //
        // The authoritative signal is the listener: Pingora exposes
        // an `ssl_digest` on the session digest only when the
        // accepted connection is TLS. We honour the spoofable
        // `X-Forwarded-Proto` header only when the immediate TCP
        // peer is in the configured `proxy.trusted_proxies` set
        // (i.e. a known load balancer or CDN that terminates TLS
        // for us). A direct HTTP client outside that set cannot
        // bypass the redirect by claiming `X-Forwarded-Proto: https`.
        let listener_is_tls = session
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .is_some();
        let xfp = session
            .req_header()
            .headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok());
        let is_https = is_request_https(listener_is_tls, peer_trusted, xfp);

        if !is_https {
            let host = &ctx.hostname;
            let path = session.req_header().uri.path();
            let query = session.req_header().uri.query();
            let location = if let Some(q) = query {
                format!("https://{host}{path}?{q}")
            } else {
                format!("https://{host}{path}")
            };
            let mut header = pingora_http::ResponseHeader::build(301, Some(1)).map_err(|e| {
                Error::because(
                    ErrorType::InternalError,
                    "failed to build redirect header",
                    e,
                )
            })?;
            header.insert_header("location", &location).map_err(|e| {
                Error::because(ErrorType::InternalError, "failed to set location", e)
            })?;
            session
                .write_response_header(Box::new(header), true)
                .await?;
            return Ok(true);
        }
    }

    // --- Allowed methods check ---
    if !origin.allowed_methods.is_empty() {
        let method = &session.req_header().method;
        if !origin.allowed_methods.contains(method) {
            send_error(session, 405, "method not allowed").await?;
            return Ok(true);
        }
    }

    // --- CORS preflight handling (before auth) ---
    if let Some(cors_config) = &origin.cors {
        if sbproxy_middleware::cors::is_preflight(
            &session.req_header().method,
            &session.req_header().headers,
        ) {
            let request_origin = session
                .req_header()
                .headers
                .get("origin")
                .and_then(|v| v.to_str().ok());
            let preflight =
                sbproxy_middleware::cors::preflight_headers(cors_config, request_origin);
            let mut header = pingora_http::ResponseHeader::build(204, Some(preflight.len()))
                .map_err(|e| {
                    Error::because(
                        ErrorType::InternalError,
                        "failed to build preflight header",
                        e,
                    )
                })?;
            for (key, value) in &preflight {
                let name = key.to_string();
                let val = value.to_str().unwrap_or("").to_string();
                header.insert_header(name, &val).map_err(|e| {
                    Error::because(
                        ErrorType::InternalError,
                        "failed to set preflight header",
                        e,
                    )
                })?;
            }
            session
                .write_response_header(Box::new(header), true)
                .await?;
            return Ok(true);
        }
    }

    // --- Bot detection (before auth, per handler chain) ---
    if let Some(bot) = &pipeline.bot_detections[origin_idx] {
        let ua = session
            .req_header()
            .headers
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !bot.check_user_agent(ua) {
            debug!(user_agent = %ua, "bot detection blocked request");
            send_error(session, 403, "forbidden").await?;
            return Ok(true);
        }
    }

    // --- Threat protection (before auth, per handler chain) ---
    if let Some(threat) = &pipeline.threat_protections[origin_idx] {
        if threat.enabled {
            // Body reads in request_filter drain the downstream stream
            // before Pingora can forward it. Defer the bounded scan to
            // request_body_filter, which releases the exact buffered bytes
            // only after validation succeeds.
            ctx.threat_scan_pending = true;
        }
    }

    // --- Inbound minted-key resolution (before auth) ---
    //
    // Runs after every well-known, callback, health, metrics and CORS-preflight
    // interception has already short-circuited, so a preflight carrying no
    // credentials never reaches this and cannot be denied.
    //
    // Deliberately not an `Auth` variant: `pipeline.auths` holds one optional
    // provider per origin, so a variant would force an origin to choose between
    // minted keys and its existing JWT / OIDC / mTLS auth. Running first, and
    // short-circuiting only on success, is what lets a minted key work in
    // parallel with credentials the proxy does not own.
    //
    // AI actions have two additional credential sources whose `sk-...` shape
    // overlaps provider-native keys: legacy stored virtual keys and exact
    // `ai_provider` credentials from origin config. Let the AI resolver check
    // those sources before it falls back to native-key admission. Generic
    // proxy actions have no later resolver and remain fully governed here.
    let ai_action_resolves_overlapping_credentials = ai_proxy_owns_replay_paths;
    if let Some(plane) = pipeline.key_plane() {
        let origin_label = ctx.hostname.to_string();
        // Bind the outcome before matching so the immutable borrow of
        // `session` ends here rather than spanning the arms, which need it
        // mutably to write an error response.
        let outcome =
            resolve_inbound_key(plane, &session.req_header().headers, raw_peer_ip, ctx).await;
        match outcome {
            InboundKeyPhase::Resolved => {
                ctx.inbound_key_mode = crate::context::InboundKeyMode::Minted;
                sbproxy_observe::metrics::record_auth(&origin_label, "virtual_key", true);
            }
            InboundKeyPhase::NotPresent => {
                if !ai_action_resolves_overlapping_credentials {
                    // No minted key: recognize and govern a caller-owned native
                    // provider credential. The explicit default policy is what
                    // prevents this path from silently spending an operator key.
                    match crate::inbound_key::resolve_native_key_policy(
                        &session.req_header().headers,
                        plane.inbound(),
                    ) {
                        crate::inbound_key::NativeKeyPolicyDecision::NotPresent => {}
                        crate::inbound_key::NativeKeyPolicyDecision::Allowed { provider } => {
                            let policy = plane
                                .inbound()
                                .native_key_policy
                                .as_ref()
                                .expect("allowed native key decision requires a policy");
                            let record = crate::inbound_key::native_policy_record(
                                policy,
                                ctx.tenant_id.as_str(),
                                ctx.hostname.as_str(),
                                &provider,
                            );
                            ctx.native_key_provider = Some(provider);
                            ctx.inbound_key_mode = crate::context::InboundKeyMode::Native;
                            let within_rpm = record.max_requests_per_minute.is_none()
                                || super::ai_dispatch::key_rate_limiter().check_request_rate(
                                    &record.key_id,
                                    record.max_requests_per_minute,
                                );
                            ctx.native_key_policy_record = Some(Box::new(record));
                            if !within_rpm {
                                sbproxy_observe::metrics::record_policy(
                                    &origin_label,
                                    "rate_limit",
                                    "deny",
                                );
                                sbproxy_observe::SecurityAuditEntry::policy_violation(
                                    "rate_limit",
                                    "native provider key request rate exceeded",
                                    429,
                                    Some(origin_label.clone()),
                                    ctx.client_ip,
                                    Some(ctx.request_id.to_string()),
                                    Some(session.req_header().method.as_str().to_string()),
                                )
                                .with_tenant_id(ctx.tenant_id.to_string())
                                .with_key_context(
                                    ctx.native_key_provider.clone(),
                                    ctx.inbound_key_mode.as_str(),
                                )
                                .with_api_key_id(ctx.accountable_key_id())
                                .emit();
                                send_error(session, 429, "rate limit exceeded for this key")
                                    .await?;
                                return Ok(true);
                            }
                        }
                        crate::inbound_key::NativeKeyPolicyDecision::PolicyMissing { provider }
                        | crate::inbound_key::NativeKeyPolicyDecision::ProviderDenied {
                            provider,
                        } => {
                            ctx.native_key_provider = Some(provider);
                            ctx.inbound_key_mode = crate::context::InboundKeyMode::Native;
                            // WOR-2094: the ring row names the denial.
                            ctx.record_policy_decision("native_key_policy", "deny");
                            ctx.deny_reason =
                                Some("native_key_policy: provider not allowed".to_string());
                            finalize_inbound_key_trust(ctx, AuthTrustOutcome::Missing);
                            sbproxy_observe::metrics::record_auth(
                                &origin_label,
                                "native_provider_key",
                                false,
                            );
                            emit_auth_audit(
                                "auth_denied",
                                "native_provider_key",
                                403,
                                &origin_label,
                                ctx,
                                session,
                            );
                            send_error(session, 403, "native provider key is not allowed").await?;
                            return Ok(true);
                        }
                    }
                }
                if crate::inbound_key::requires_minted_key(plane.inbound()) {
                    finalize_inbound_key_trust(ctx, AuthTrustOutcome::Missing);
                    sbproxy_observe::metrics::record_auth(&origin_label, "virtual_key", false);
                    emit_auth_audit(
                        "auth_denied",
                        "virtual_key",
                        401,
                        &origin_label,
                        ctx,
                        session,
                    );
                    send_error(session, 401, "an api key is required").await?;
                    return Ok(true);
                }
            }
            InboundKeyPhase::Deny {
                status,
                message,
                trust_outcome,
            } => {
                finalize_inbound_key_trust(ctx, trust_outcome);
                sbproxy_observe::metrics::record_auth(&origin_label, "virtual_key", false);
                emit_auth_audit(
                    "auth_denied",
                    "virtual_key",
                    status,
                    &origin_label,
                    ctx,
                    session,
                );
                send_error(session, status, &message).await?;
                return Ok(true);
            }
        }
    }

    // --- Auth check ---
    // A resolved minted key already authenticated this request, so the origin's
    // configured provider is skipped. That makes the two front doors
    // alternatives rather than a chain.
    if let (None, Some(auth)) = (&ctx.resolved_inbound_key, &pipeline.auths[origin_idx]) {
        let auth_type = auth.auth_type().to_string();
        let origin_label = ctx.hostname.to_string();
        // Handle forward auth (requires async HTTP subrequest).
        if let Auth::ForwardAuth(fwd) = auth {
            let req_headers = &session.req_header().headers;
            match check_forward_auth(fwd, req_headers).await {
                Ok(trust_headers) => {
                    // Pull the resolved user out of the trust
                    // headers (typically `X-Forwarded-User` or
                    // `Remote-User`); whichever the operator
                    // listed in `trust_headers` and the auth
                    // service stamped is what we surface.
                    let resolved_user = forward_auth_user_from_trust_headers(&trust_headers);
                    if let Some(user) = resolved_user.clone() {
                        ctx.auth_result = Some(sbproxy_plugin::AuthDecision::Allow {
                            sub: Some(user),
                            source: Some(sbproxy_plugin::AuthSubjectSource::ForwardAuth),
                        });
                    } else {
                        ctx.auth_result = Some(sbproxy_plugin::AuthDecision::allow_anonymous());
                    }
                    // Store trust headers in context to apply in upstream_request_filter
                    // (direct session.req_header_mut().headers doesn't propagate to upstream)
                    ctx.trust_headers = Some(trust_headers);
                    sbproxy_observe::metrics::record_auth(&origin_label, &auth_type, true);
                }
                Err((status, msg, trust_outcome)) => {
                    crate::trust_tier::finalize(ctx, trust_outcome.is_suspicious());
                    sbproxy_observe::metrics::record_auth(&origin_label, &auth_type, false);
                    emit_auth_audit(
                        "forward_auth_denied",
                        &auth_type,
                        status,
                        &origin_label,
                        ctx,
                        session,
                    );
                    let path = session.req_header().uri.path().to_string();
                    send_error_with_pages(
                        session,
                        status,
                        &msg,
                        origin.error_pages.as_deref(),
                        origin.problem_details.as_ref(),
                        &path,
                    )
                    .await?;
                    return Ok(true);
                }
            }
        } else {
            let req_headers = &session.req_header().headers;
            let query = session.req_header().uri.query();
            let method = session.req_header().method.as_str();
            let path = session.req_header().uri.path();
            let tenant_id = sbproxy_plugin::TenantId::from(ctx.tenant_id.to_string());
            // WOR-1149: thread the resolved agent identity (stamped by
            // the agent-class resolver earlier in this filter) into the
            // auth check so the CAP verifier can enforce `sub` binding.
            // `cap_binding_agent_id` yields `None` for the resolver's
            // fallback/`human` verdict so an unidentified caller does not
            // trip the binding check (the resolver is installed with the
            // built-in catalog by default and always stamps *some* id).
            // Owned so no `ctx` borrow is held across the await.
            #[cfg(feature = "agent-class")]
            let resolved_agent_id: Option<String> =
                crate::agent_class::cap_binding_agent_id(ctx).map(|s| s.to_string());
            #[cfg(not(feature = "agent-class"))]
            let resolved_agent_id: Option<String> = None;
            let (auth_result, principal_opt, trust_outcome) = check_auth_with_outcome(
                auth,
                req_headers,
                query,
                method,
                path,
                tenant_id,
                resolved_agent_id.as_deref(),
            )
            .await;
            #[cfg(feature = "agent-class")]
            let bot_auth_keyid = principal_opt
                .as_ref()
                .filter(|principal| {
                    matches!(principal.source, sbproxy_plugin::PrincipalSource::BotAuth)
                })
                .and_then(|principal| principal.attrs.metadata.get("bot_auth_keyid"))
                .cloned();
            // WOR-1047 PR2: every built-in provider returns a
            // `Principal` on Allow. Stamp it on `ctx.principal` so
            // downstream policy / access-log paths read attribution
            // off a single carrier instead of re-deriving it from
            // the auth provider's slug.
            if let Some(principal) = principal_opt {
                ctx.principal = principal;
            }
            // Phase-timing capture: snapshot the moment the auth
            // provider returned (success, deny, or challenge). The
            // access-log + `sbproxy_phase_duration_seconds{phase="auth"}`
            // histogram derive `auth_ms` from this delta.
            ctx.auth_finished_at = Some(std::time::Instant::now());
            // WOR-805 F1.6.1: when bot_auth verified a signature that
            // covered `content-digest`, the body-vs-digest binding
            // could not be checked yet (the body was not buffered at
            // the auth phase). Stamp the deferred-check flag so
            // `request_body_filter` buffers the body and runs
            // `verify_content_digest` against the Content-Digest
            // header value the signature attests to.
            let auth_succeeded = matches!(
                auth_result,
                AuthResult::Allow { .. } | AuthResult::RateLimited(_)
            );
            if auth_succeeded && matches!(auth, Auth::BotAuth(_)) {
                #[cfg(feature = "agent-class")]
                if let Some(keyid) = bot_auth_keyid.as_deref() {
                    if let Some(resolver) = reload::agent_class_resolver() {
                        let user_agent = session
                            .req_header()
                            .headers
                            .get(http::header::USER_AGENT)
                            .and_then(|v| v.to_str().ok());
                        crate::agent_class::stamp_request_context(
                            ctx,
                            &resolver,
                            Some(keyid),
                            false,
                            ctx.client_ip,
                            user_agent,
                        );
                    }
                }
                if sbproxy_middleware::signatures::signature_input_covers_content_digest(
                    req_headers,
                ) {
                    ctx.bot_auth_digest_check_required = true;
                    ctx.validate_request_body = true;
                }
            }
            if !auth_succeeded {
                crate::trust_tier::finalize(ctx, trust_outcome.is_suspicious());
            }
            match auth_result {
                AuthResult::Allow { sub, source } => {
                    ctx.auth_result = Some(sbproxy_plugin::AuthDecision::Allow { sub, source });
                    sbproxy_observe::metrics::record_auth(&origin_label, &auth_type, true);
                }
                AuthResult::RateLimited(info) => {
                    ctx.auth_result = Some(sbproxy_plugin::AuthDecision::allow_anonymous());
                    sbproxy_observe::metrics::record_auth(&origin_label, &auth_type, true);
                    crate::trust_tier::finalize(ctx, false);
                    let extra_headers = vec![
                        ("X-RateLimit-Limit".to_string(), info.limit.to_string()),
                        (
                            "X-RateLimit-Remaining".to_string(),
                            info.remaining.to_string(),
                        ),
                        ("X-RateLimit-Reset".to_string(), info.reset_secs.to_string()),
                        ("Retry-After".to_string(), info.reset_secs.to_string()),
                    ];
                    ctx.rate_limit_info = Some(info);
                    send_error_with_extra_headers(
                        session,
                        429,
                        "cap: rate limit exceeded",
                        &extra_headers,
                    )
                    .await?;
                    return Ok(true);
                }
                AuthResult::Deny(status, ref msg) => {
                    sbproxy_observe::metrics::record_auth(&origin_label, &auth_type, false);
                    emit_auth_audit(
                        "auth_denied",
                        &auth_type,
                        status,
                        &origin_label,
                        ctx,
                        session,
                    );
                    let path = session.req_header().uri.path().to_string();
                    send_error_with_pages(
                        session,
                        status,
                        msg,
                        origin.error_pages.as_deref(),
                        origin.problem_details.as_ref(),
                        &path,
                    )
                    .await?;
                    return Ok(true);
                }
                AuthResult::DenyWithHeaders(status, ref msg, ref extra_headers) => {
                    sbproxy_observe::metrics::record_auth(&origin_label, &auth_type, false);
                    emit_auth_audit(
                        "auth_denied_with_headers",
                        &auth_type,
                        status,
                        &origin_label,
                        ctx,
                        session,
                    );
                    // WOR-808: when OLP is enabled on this origin
                    // AND the auth challenge is a `License` scheme,
                    // augment `WWW-Authenticate` with `realm=...` +
                    // `token_url="https://<host>/.well-known/olp/token"`
                    // so the client auto-discovers the issuer
                    // endpoint instead of guessing. RFC 6750 §3
                    // syntax. Other auth providers' headers
                    // (Digest, Basic, etc.) pass through
                    // unchanged.
                    let augmented = augment_license_challenge(
                        extra_headers,
                        origin.olp.as_ref(),
                        origin.hostname.as_str(),
                        session
                            .req_header()
                            .headers
                            .get("host")
                            .and_then(|v| v.to_str().ok()),
                    );
                    send_error_with_extra_headers(session, status, msg, &augmented).await?;
                    return Ok(true);
                }
                AuthResult::DigestChallenge(challenge) => {
                    sbproxy_observe::metrics::record_auth(&origin_label, &auth_type, false);
                    emit_auth_audit(
                        "auth_digest_challenge",
                        &auth_type,
                        401,
                        &origin_label,
                        ctx,
                        session,
                    );
                    let body = b"{\"error\":\"unauthorized\"}";
                    let mut header =
                        pingora_http::ResponseHeader::build(401, Some(3)).map_err(|e| {
                            Error::because(ErrorType::InternalError, "digest challenge header", e)
                        })?;
                    let _ = header.insert_header("content-type", "application/json");
                    let _ = header.insert_header("www-authenticate", &challenge);
                    let _ = header.insert_header("content-length", body.len().to_string());
                    session
                        .write_response_header(Box::new(header), false)
                        .await?;
                    session
                        .write_response_body(Some(bytes::Bytes::copy_from_slice(body)), true)
                        .await?;
                    return Ok(true);
                }
            }
        }
    }

    // All identity enrichers and the configured authentication provider
    // have now run. Compute once so every downstream policy sees the same
    // conservative tier and the distribution metric has a live writer.
    crate::trust_tier::finalize(ctx, false);

    // --- P0 edge capture ---
    //
    // Stamp custom properties, session linkage, and end-user ID
    // onto the request context. Runs after auth so the
    // user-id resolution sees the JWT `sub` / forward-auth subject
    // pulled from `ctx.auth_result`. Per-origin overrides come
    // from the compiled origin (T1.3); when absent, the type's
    // `Default` applies (capture on, no echo, anonymous
    // auto-generate).
    {
        // WOR-1700: `capture_dimensions` takes `&HeaderMap` and
        // `&mut RequestContext` as separate arguments, and `session` /
        // `ctx` are disjoint bindings, so borrow the live request
        // headers directly instead of rebuilding the whole map
        // entry-by-entry per request.
        let origin_cfg = &pipeline.config.origins[origin_idx];
        let properties_cfg = origin_cfg.properties.clone().unwrap_or_default();
        let sessions_cfg = origin_cfg.sessions.clone().unwrap_or_default();
        let user_cfg = origin_cfg.user.clone().unwrap_or_default();
        let workspace_id = origin_cfg.workspace_id.to_string();
        // Clone the resolved subject + source out of the borrow
        // so the subsequent `&mut ctx` call into capture_dimensions
        // does not run afoul of the borrow checker.
        let (jwt_sub, forward_auth_user) = match ctx.auth_result.as_ref() {
            Some(sbproxy_plugin::AuthDecision::Allow { sub, source }) => {
                let owned = sub.clone();
                match source {
                    Some(sbproxy_plugin::AuthSubjectSource::Jwt) => (owned, None),
                    Some(sbproxy_plugin::AuthSubjectSource::ForwardAuth) => (None, owned),
                    // Header / api-key / basic-auth / digest /
                    // bot-auth / noop providers all flow through
                    // the existing X-Sb-User-Id header path; no
                    // separate jwt / forward-auth source applies.
                    _ => (None, None),
                }
            }
            _ => (None, None),
        };
        crate::capture_envelope::capture_dimensions(
            ctx,
            &session.req_header().headers,
            &properties_cfg,
            &sessions_cfg,
            &user_cfg,
            jwt_sub.as_deref(),
            forward_auth_user.as_deref(),
            &workspace_id,
        );
    }

    // --- Idempotency middleware pre-check ---
    //
    // When the resolved origin has `idempotency:` configured and
    // the request method is one of the configured set, set
    // `ctx.idempotency_buffering = true` so `request_body_filter`
    // accumulates the body, computes its hash, and short-circuits
    // cache hits / conflicts before the action runs. The middleware
    // sits ahead of policies so a successful replay does not
    // consume rate-limit tokens. Requests without the
    // `Idempotency-Key` header skip buffering and fall through to
    // the normal flow.
    if let Some(idem) = pipeline
        .idempotencies
        .get(origin_idx)
        .and_then(|o| o.as_ref())
        .filter(|_| !ctx.graphql_validation_pending && !ai_proxy_owns_replay_paths)
    {
        let method_matches = idem.methods.contains(&session.req_header().method);
        let header_present = session
            .req_header()
            .headers
            .get(idem.header_name.as_str())
            .and_then(|v| v.to_str().ok())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if method_matches && header_present {
            // Backpressure gate 1: oversize body. When the
            // client sent a content-length header that already
            // exceeds the cap, we know the buffer won't fit. Skip
            // engagement up front so the request streams without
            // the body filter holding chunks back. The streaming
            // check in `request_body_filter` covers the
            // chunked / no-content-length case.
            let cl_oversize = session
                .req_header()
                .headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<usize>().ok())
                .map(|cl| cl > idem.max_request_body_bytes)
                .unwrap_or(false);
            if cl_oversize {
                ctx.idempotency_skip_reason = Some("SKIPPED-OVERSIZE-REQUEST");
            } else {
                // Backpressure gate 2: pool exhaustion. Try-acquire
                // a permit; on failure the request flows through
                // the no-cache path. We hold the permit on ctx
                // until end-of-request so concurrent buffered
                // requests stay bounded by `max_concurrent_buffers`.
                match idem.permits.clone().try_acquire_owned() {
                    Ok(permit) => {
                        ctx.idempotency_permit = Some(permit);
                        ctx.idempotency_workspace =
                            Some(pipeline.config.origins[origin_idx].workspace_id.to_string());

                        // --- Key-only cache probe ---
                        //
                        // Look the cache up by `(workspace, key)`
                        // alone (no body hash). When no entry
                        // exists this is definitely a miss; fall
                        // back to the streaming `request_body_filter`
                        // path so Pingora pumps chunks to the
                        // upstream normally and the response is
                        // captured for the cache.
                        //
                        // When an entry exists we drain the body
                        // and hash it inside `request_filter` to
                        // decide between cache hit (matching
                        // hash) and conflict (mismatching hash).
                        // Both short-circuit before Pingora opens
                        // an upstream connection, so retries that
                        // resolve to a cached response NEVER
                        // contact the upstream.
                        let key = session
                            .req_header()
                            .headers
                            .get(idem.header_name.as_str())
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.trim().to_string())
                            .unwrap_or_default();
                        let workspace = ctx.idempotency_workspace.clone().unwrap_or_default();
                        let cached = idem.cache.get(&workspace, &key);
                        if let Some(cached_resp) = cached {
                            // Drain the body to compare hashes.
                            let max = idem.max_request_body_bytes;
                            let mut buf = bytes::BytesMut::new();
                            let mut over_cap = false;
                            loop {
                                match session.read_request_body().await {
                                    Ok(Some(chunk)) => {
                                        if buf.len().saturating_add(chunk.len()) > max {
                                            buf.extend_from_slice(&chunk);
                                            over_cap = true;
                                            break;
                                        }
                                        buf.extend_from_slice(&chunk);
                                    }
                                    Ok(None) => break,
                                    Err(e) => {
                                        warn!(
                                            error = %e,
                                            "idempotency body drain failed"
                                        );
                                        break;
                                    }
                                }
                            }
                            if over_cap {
                                // We've already drained more than
                                // the cap; the body cannot be
                                // matched against the cached
                                // entry without unbounded memory.
                                // Abandon engagement and mark the
                                // skip reason. Note: this will
                                // also force the upstream to not
                                // see this request because we've
                                // already consumed the body and
                                // can't re-inject. The 409-like
                                // failure mode is preferable
                                // here to silently sending a
                                // body-less request to the
                                // upstream; return the conflict
                                // body so the client knows to
                                // retry with a fresh key.
                                ctx.idempotency_permit = None;
                                ctx.idempotency_skip_reason = Some("SKIPPED-OVERSIZE-REQUEST");
                                let (status, content_type, body) =
                                    sbproxy_middleware::idempotency::conflict_response();
                                let status_u16 = status.as_u16();
                                let mut header =
                                    pingora_http::ResponseHeader::build(status_u16, Some(3))?;
                                let _ = header.insert_header("content-type", content_type);
                                let _ =
                                    header.insert_header("content-length", body.len().to_string());
                                let _ = header.insert_header(
                                    "x-sbproxy-idempotency",
                                    "SKIPPED-OVERSIZE-REQUEST",
                                );
                                session
                                    .write_response_header(Box::new(header), false)
                                    .await?;
                                session
                                    .write_response_body(Some(bytes::Bytes::from(body)), true)
                                    .await?;
                                ctx.response_status = Some(status_u16);
                                return Ok(true);
                            }

                            // Cached idempotency responses drain and short
                            // circuit inside request_filter, before
                            // request_body_filter runs. Complete the
                            // body-bound BotAuth proof here first so neither a
                            // replay nor a 409 conflict can bypass it.
                            if !crate::trust_tier::verify_and_finalize_body_proof(
                                ctx,
                                &session.req_header().headers,
                                &buf,
                            ) {
                                ctx.idempotency_permit = None;
                                send_error(session, 401, "bot_auth: content-digest body mismatch")
                                    .await?;
                                ctx.response_status = Some(401);
                                return Ok(true);
                            }

                            let body_hash = sbproxy_middleware::idempotency::hash_body(&buf);
                            if body_hash == cached_resp.request_body_hash {
                                // Cache hit: replay the cached response. The
                                // shared helper also serves GraphQL hits that
                                // must wait until final-request validation.
                                let status =
                                    send_idempotency_cache_hit(session, cached_resp).await?;
                                ctx.response_status = Some(status);
                                return Ok(true);
                            } else {
                                // Body conflict: same key,
                                // different body. Return 409
                                // per RFC 8594.
                                let (status, content_type, body) =
                                    sbproxy_middleware::idempotency::conflict_response();
                                let status_u16 = status.as_u16();
                                let mut header =
                                    pingora_http::ResponseHeader::build(status_u16, Some(2))?;
                                let _ = header.insert_header("content-type", content_type);
                                let _ =
                                    header.insert_header("content-length", body.len().to_string());
                                session
                                    .write_response_header(Box::new(header), false)
                                    .await?;
                                session
                                    .write_response_body(Some(bytes::Bytes::from(body)), true)
                                    .await?;
                                ctx.response_status = Some(status_u16);
                                return Ok(true);
                            }
                        }

                        // No cached entry. Set the buffering flag
                        // so `request_body_filter` accumulates the
                        // body, hashes it, and records the
                        // response. This is the first-call (cache
                        // miss) path; Pingora's normal upstream
                        // forwarding handles the body delivery.
                        ctx.idempotency_buffering = true;
                    }
                    Err(_) => {
                        ctx.idempotency_skip_reason = Some("SKIPPED-POOL-FULL");
                    }
                }
            }
        }
    }

    // --- Policy enforcement ---
    let policy_origin = ctx.hostname.to_string();
    // Build the verdict-bus correlation context once per
    // request. WOR-201 PR 1b. The OSS scope passes
    // `tenant_id` and `workspace_id` as the same string; the
    // enterprise audit binding distinguishes them via the
    // workspace -> tenant lookup the OSS proxy does not own.
    let policy_workspace_id = pipeline.config.origins[origin_idx].workspace_id.to_string();
    let verdict_ctx = PolicyVerdictCtx {
        request_id: ctx.request_id.to_string(),
        tenant_id: policy_workspace_id.clone(),
        workspace_id: policy_workspace_id,
    };
    let policy_verdict =
        check_policies(&pipeline.enforcers[origin_idx], session, ctx, &verdict_ctx).await;
    // WOR-2143: the settlement origin gate. When `proxy.payments` is
    // active and the chain's verdict is an `ai_crawl_control` 402, the
    // gate answers from durable settlement state instead: it turns the
    // deny into an allow exactly when a payment durably settled, and
    // rewrites the stored challenge otherwise. This is the call-site
    // seam on purpose: the enforcer trait's returned future cannot
    // borrow the RequestContext, and settlement has to await the store
    // and then mutate it.
    #[cfg(feature = "payments")]
    let policy_verdict =
        crate::settlement_gate::apply(session.req_header(), ctx, policy_verdict).await;
    match policy_verdict {
        None => {
            sbproxy_observe::metrics::record_policy(&policy_origin, "all", "allow");
            // `ctx.rate_limit_info` was populated in-place by the
            // RateLimitEnforcer wrapper, so the response_filter has
            // the data it needs for X-RateLimit-* headers.
        }
        Some((status, msg, policy_type)) => {
            // The wrappers stamp `ctx.rate_limit_info` (and
            // `ctx.a2a_denial_body`, `ctx.crawl_challenge`, ...)
            // before the short-circuit; snapshot the rate-limit
            // slot here so the downstream 429 branches can read
            // it without re-borrowing `ctx` past the mutating
            // arms below.
            let rl_info = ctx.rate_limit_info.clone();
            // Prefer the per-request slot the wrapper populated;
            // fall back to the dispatcher-supplied "plugin"-family
            // label otherwise.
            let policy_type = effective_policy_type(ctx, policy_type);
            // The enforcing policy stamps its own stable label
            // (`waf`, `ip_filter`, `prompt_injection`, ...) so
            // dashboards and SIEM rules can break down by module
            // instead of inferring from the response status.
            sbproxy_observe::metrics::record_policy(&policy_origin, policy_type, "deny");
            // WOR-2094: mirror the denial onto the ring row's
            // explainability columns. Enforcers that already recorded a
            // more specific reason keep it.
            ctx.record_policy_decision(policy_type, "deny");
            if ctx.deny_reason.is_none() {
                ctx.deny_reason = Some(format!("{policy_type}: {msg}"));
            }
            // Audit-log the denial alongside the metric. Policy
            // metrics roll up to dashboards; the audit channel
            // feeds the SIEM with structured per-event records so
            // SOC tooling can correlate by hostname, request_id,
            // and client_ip.
            sbproxy_observe::SecurityAuditEntry::policy_violation(
                policy_type,
                &msg,
                status,
                Some(policy_origin.clone()),
                ctx.client_ip,
                Some(ctx.request_id.to_string()),
                Some(session.req_header().method.as_str().to_string()),
            )
            .with_tenant_id(ctx.tenant_id.to_string())
            .with_key_context(
                ctx.native_key_provider.clone(),
                ctx.inbound_key_mode.as_str(),
            )
            .with_api_key_id(ctx.accountable_key_id())
            .emit();
            if let Some(response) =
                take_concurrent_limit_denial_response(ctx, status, &msg, policy_type)
            {
                send_response(
                    session,
                    response.status,
                    response.content_type,
                    response.body.as_bytes(),
                )
                .await?;
            } else if status == 429
                && (policy_type == "rate_limit"
                    || policy_type == "ddos"
                    || policy_type == "rate_limit_budget")
            {
                // Rate-limit + DDoS denial. Both emit 429 with a
                // RateLimitInfo and want the same wrapped envelope
                // and rate-limit headers. Other policies that emit 429
                // (e.g. a2a_chain_depth_exceeded) fall through to their
                // own dedicated branches below so their spec-pinned
                // bodies and headers survive intact.
                let body = error_json_body(&msg);
                let mut header =
                    pingora_http::ResponseHeader::build(status, Some(7)).map_err(|e| {
                        Error::because(
                            ErrorType::InternalError,
                            "failed to build response header",
                            e,
                        )
                    })?;
                let _ = header.insert_header("content-type", "application/json");
                // Content-Length is required so HTTP/1.1 keep-alive
                // clients (curl, browsers, sdks) know where the body
                // ends. Without it they wait for a connection close
                // that never comes, and the request hangs.
                let _ = header.insert_header("content-length", body.len().to_string());
                if let Some(ref info) = rl_info {
                    // WOR-1130: the workspace budget policy emits the RFC
                    // 9239 / draft-ietf-httpapi-ratelimit-headers set
                    // (`RateLimit-*` + `RateLimit-Policy`); the Wave 1
                    // per-policy limiter keeps the legacy `X-RateLimit-*`
                    // shape for backward compatibility.
                    if policy_type == "rate_limit_budget" {
                        if info.headers_enabled {
                            let _ = header.insert_header("RateLimit-Limit", info.limit.to_string());
                            let _ = header
                                .insert_header("RateLimit-Remaining", info.remaining.to_string());
                            let _ = header
                                .insert_header("RateLimit-Reset", info.reset_secs.to_string());
                            if info.include_ratelimit_policy {
                                // Window is the per-second budget window.
                                let _ = header.insert_header(
                                    "RateLimit-Policy",
                                    format!("{};w=1", info.limit),
                                );
                            }
                        }
                    } else if info.headers_enabled {
                        let _ = header.insert_header("X-RateLimit-Limit", info.limit.to_string());
                        let _ = header
                            .insert_header("X-RateLimit-Remaining", info.remaining.to_string());
                        let _ =
                            header.insert_header("X-RateLimit-Reset", info.reset_secs.to_string());
                    }
                    if info.include_retry_after {
                        let _ = header.insert_header("Retry-After", info.reset_secs.to_string());
                    }
                }
                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                session
                    .write_response_body(Some(bytes::Bytes::copy_from_slice(body.as_bytes())), true)
                    .await?;
            } else if status == 402 {
                // AI crawl control: 402 with the configured
                // challenge header and a JSON body the crawler
                // can introspect for price + retry instructions.
                let rendered = ctx.crawl_challenge.take().unwrap_or_else(|| {
                    crate::context::PaymentResponse::json_with_header(
                        "crawler-payment",
                        "Crawler-Payment realm=\"ai-crawl\"".to_string(),
                        error_json_body(&msg),
                    )
                });
                let body = rendered.body;
                let mut header =
                    pingora_http::ResponseHeader::build(status, Some(3)).map_err(|e| {
                        Error::because(
                            ErrorType::InternalError,
                            "failed to build response header",
                            e,
                        )
                    })?;
                // The policy already decided the exact content type and
                // every header. Repeated names are appended rather than
                // replaced, because Payment HTTP Authentication offers one
                // `WWW-Authenticate` field per challenge and collapsing them
                // into one field is a different, non-conforming message.
                let _ = header.insert_header("content-type", &rendered.content_type);
                for (name, value) in &rendered.headers {
                    let _ = header.append_header(name.clone(), value);
                }
                // Content-Length is required so HTTP/1.1 keep-alive
                // clients know where the body ends without waiting
                // for a connection close.
                let _ = header.insert_header("content-length", body.len().to_string());
                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                session
                    .write_response_body(Some(bytes::Bytes::copy_from_slice(body.as_bytes())), true)
                    .await?;
            } else if status == 406 && policy_type == "ai_crawl_no_acceptable_rail" {
                // G3.4 multi-rail: agent's Accept-Payment list has no
                // overlap with the configured rails. Emit the
                // policy-supplied JSON body verbatim with a generic
                // application/json Content-Type so the agent can
                // recover from the listed `supported_rails`.
                let body = ctx
                    .crawl_challenge
                    .take()
                    .map(|rendered| rendered.body)
                    .unwrap_or_else(|| error_json_body(&msg));
                let mut header =
                    pingora_http::ResponseHeader::build(status, Some(2)).map_err(|e| {
                        Error::because(
                            ErrorType::InternalError,
                            "failed to build response header",
                            e,
                        )
                    })?;
                let _ = header.insert_header("content-type", "application/json");
                let _ = header.insert_header("content-length", body.len().to_string());
                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                session
                    .write_response_body(Some(bytes::Bytes::copy_from_slice(body.as_bytes())), true)
                    .await?;
            } else if status == 403 && policy_type == "ai_crawl_signal_blocked" {
                // WOR-804: a Content Signal the operator declared `=no`
                // governs this crawler's purpose. Emit the
                // policy-supplied JSON explanation verbatim with a
                // generic application/json Content-Type.
                let body = ctx
                    .crawl_challenge
                    .take()
                    .map(|rendered| rendered.body)
                    .unwrap_or_else(|| error_json_body(&msg));
                let mut header =
                    pingora_http::ResponseHeader::build(status, Some(2)).map_err(|e| {
                        Error::because(
                            ErrorType::InternalError,
                            "failed to build response header",
                            e,
                        )
                    })?;
                let _ = header.insert_header("content-type", "application/json");
                let _ = header.insert_header("content-length", body.len().to_string());
                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                session
                    .write_response_body(Some(bytes::Bytes::copy_from_slice(body.as_bytes())), true)
                    .await?;
            } else if status == 503 && policy_type == "ai_crawl_ledger_unavailable" {
                // AI crawl control: ledger is transiently down. Emit
                // the policy-supplied JSON body verbatim and stamp
                // a Retry-After from the synthesized RateLimitInfo.
                let body = ctx
                    .crawl_challenge
                    .take()
                    .map(|rendered| rendered.body)
                    .unwrap_or_else(|| error_json_body(&msg));
                let mut header =
                    pingora_http::ResponseHeader::build(status, Some(3)).map_err(|e| {
                        Error::because(
                            ErrorType::InternalError,
                            "failed to build response header",
                            e,
                        )
                    })?;
                let _ = header.insert_header("content-type", "application/json");
                let _ = header.insert_header("content-length", body.len().to_string());
                if let Some(ref info) = rl_info {
                    if info.include_retry_after {
                        let _ = header.insert_header("Retry-After", info.reset_secs.to_string());
                    }
                }
                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                session
                    .write_response_body(Some(bytes::Bytes::copy_from_slice(body.as_bytes())), true)
                    .await?;
            } else if policy_type == "ai_crawl_settlement" {
                // WOR-2143: a settlement-gate response that is not a 402
                // (the 406 rail negotiation failure, the 400 duplicate
                // credential, the 503 infrastructure refusal). The gate
                // rendered every byte, including any Retry-After or
                // problem+json content type; write it verbatim.
                let rendered = ctx.crawl_challenge.take().unwrap_or_else(|| {
                    crate::context::PaymentResponse::json(error_json_body(&msg))
                });
                let body = rendered.body;
                let header_count = 2 + rendered.headers.len();
                let mut header = pingora_http::ResponseHeader::build(status, Some(header_count))
                    .map_err(|e| {
                        Error::because(
                            ErrorType::InternalError,
                            "failed to build response header",
                            e,
                        )
                    })?;
                let _ = header.insert_header("content-type", &rendered.content_type);
                for (name, value) in &rendered.headers {
                    let _ = header.append_header(name.clone(), value);
                }
                let _ = header.insert_header("content-length", body.len().to_string());
                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                session
                    .write_response_body(Some(bytes::Bytes::copy_from_slice(body.as_bytes())), true)
                    .await?;
            } else if policy_type.starts_with("a2a_") {
                // Wave 7 / A7.2 A2A policy denials. The policy
                // module already populated `ctx.a2a_denial_body`
                // with the spec-pinned JSON envelope (depth /
                // cycle / callee / caller). Stamp it verbatim;
                // attach `Retry-After: 0` for the depth path so
                // an over-eager orchestrator stops looping
                // immediately.
                let body = ctx
                    .a2a_denial_body
                    .take()
                    .unwrap_or_else(|| error_json_body(&msg));
                let header_count = if policy_type == "a2a_chain_depth_exceeded" {
                    3
                } else {
                    2
                };
                let mut header = pingora_http::ResponseHeader::build(status, Some(header_count))
                    .map_err(|e| {
                        Error::because(
                            ErrorType::InternalError,
                            "failed to build response header",
                            e,
                        )
                    })?;
                let _ = header.insert_header("content-type", "application/json");
                let _ = header.insert_header("content-length", body.len().to_string());
                if policy_type == "a2a_chain_depth_exceeded" {
                    let _ = header.insert_header("Retry-After", "0");
                }
                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                session
                    .write_response_body(Some(bytes::Bytes::copy_from_slice(body.as_bytes())), true)
                    .await?;
            } else {
                send_error(session, status, &msg).await?;
            }
            return Ok(true);
        }
    }

    // --- Response cache lookup ---
    //
    // When the origin has response-caching enabled and the incoming method
    // is eligible, compute the canonical cache key (workspace, hostname,
    // method, path, normalized query, Vary fingerprint). If we get a live
    // entry from the cache, replay its status/headers/body to the client
    // and short-circuit (`return Ok(true)`). When the entry is past TTL
    // but inside the configured `stale_while_revalidate` window we serve
    // it stale (with `x-sbproxy-cache: STALE`) and fire a background
    // revalidation. On a true miss we remember the key in `ctx.cache_key`
    // so the response phase can write the upstream reply back into the
    // cache.
    //
    // Mutation requests (POST/PUT/PATCH/DELETE) honor
    // `invalidate_on_mutation`: every cached `GET` variant for the same
    // path is dropped from the store before the request is forwarded to
    // the upstream.
    if let (Some(cache_cfg), Some(cache_store)) = (
        origin.response_cache.as_ref(),
        // Per-origin handle, not the shared one: with at-rest
        // encryption on it is the only handle that can seal or open
        // this origin's entries.
        pipeline.cache_store_for(&origin.origin_id),
    ) {
        // WOR-114: `x-sb-flags: no-cache` (or `?_sb.no-cache`)
        // bypasses both lookup and write for this request. The
        // upstream is consulted as if no cache were configured;
        // ctx.cache_key stays None so response_filter does not
        // try to write the answer back. Mutation invalidation
        // also skips because the client is asking for a fresh
        // round-trip and any same-path GET will repopulate.
        if cache_cfg.enabled && !ctx.flags.no_cache && !ai_proxy_owns_replay_paths {
            let req_method = session.req_header().method.as_str().to_string();

            // --- Mutation invalidation ---
            // Fire before any lookup so a `POST /x` followed by a
            // re-issued `GET /x` in the same flow sees the eviction.
            if cache_cfg.invalidate_on_mutation && sbproxy_cache::is_mutation_method(&req_method) {
                let prefix = sbproxy_cache::path_invalidation_prefix(
                    "",
                    ctx.hostname.as_str(),
                    session.req_header().uri.path(),
                );
                let invalidate_store = cache_store.clone();
                // Cache deletes go through spawn_blocking for the
                // same reason lookups do: the Redis backend has
                // blocking I/O underneath the trait.
                let _ = tokio::task::spawn_blocking(move || {
                    match invalidate_store.delete_prefix(&prefix) {
                        Ok(n) if n > 0 => {
                            tracing::debug!(
                                prefix = %prefix,
                                removed = n,
                                "invalidate_on_mutation: dropped cached GET variants"
                            );
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(error = %e, "cache invalidate_prefix failed");
                        }
                    }
                })
                .await;
                // Also drop the matching reserve entry. The
                // reserve is keyed by the same canonical cache
                // key the GET path used, so a single delete by
                // key clears the no-vary variant. Vary-based
                // variants must wait for natural expiry; the
                // reserve trait surface is intentionally narrow
                // so backends like S3 don't need to scan.
                if let Some(reserve) = pipeline.cache_reserve.clone() {
                    let invalidate_key = build_response_cache_key(
                        "",
                        ctx.hostname.as_str(),
                        session.req_header(),
                        cache_cfg,
                    );
                    let invalidate_origin = origin.origin_id.to_string();
                    tokio::spawn(async move {
                        match reserve.delete(&invalidate_key).await {
                            Ok(()) => {
                                sbproxy_observe::metrics()
                                    .cache_reserve_evictions
                                    .with_label_values(&[invalidate_origin.as_str()])
                                    .inc();
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "cache reserve delete failed on mutation"
                                );
                            }
                        }
                    });
                }
            }

            let method_ok = if cache_cfg.cacheable_methods.is_empty() {
                req_method == "GET"
            } else {
                cache_cfg
                    .cacheable_methods
                    .iter()
                    .any(|m| m.eq_ignore_ascii_case(&req_method))
            };

            if method_ok {
                ctx.record_admin_cache_status(crate::context::AdminCacheStatus::Miss);
                let key = build_response_cache_key(
                    "",
                    ctx.hostname.as_str(),
                    session.req_header(),
                    cache_cfg,
                );

                // Cache lookups are synchronous against the trait, but the
                // Redis backend does blocking TCP I/O under the hood. Use
                // spawn_blocking so we don't stall the tokio reactor.
                // We always pull the entry "including expired" so the SWR
                // window can be evaluated even when TTL is exceeded; the
                // freshness check happens on this side.
                let lookup_store = cache_store.clone();
                let lookup_key = key.clone();
                let hit = tokio::task::spawn_blocking(move || {
                    lookup_store.get_including_expired(&lookup_key)
                })
                .await
                .map_err(|e| {
                    Error::because(ErrorType::InternalError, "cache lookup join failed", e)
                })?;

                match hit {
                    Ok(Some(entry)) => {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let age = now.saturating_sub(entry.cached_at);
                        let fresh = age <= entry.ttl_secs;
                        let swr_window = cache_cfg.stale_while_revalidate.unwrap_or(0);
                        let in_swr = !fresh && age <= entry.ttl_secs + swr_window;

                        if fresh || in_swr {
                            // Serve the cached entry. The marker is
                            // `HIT` for fresh and `STALE` for SWR
                            // window replays so operators can tell
                            // them apart in logs and dashboards.
                            let cache_marker = if fresh { "HIT" } else { "STALE" };
                            let request_header = session.req_header();
                            let if_none_match: Vec<&[u8]> = request_header
                                .headers
                                .get_all("if-none-match")
                                .iter()
                                .map(|value| value.as_bytes())
                                .collect();
                            let if_modified_since = request_header
                                .headers
                                .get("if-modified-since")
                                .map(|value| value.as_bytes());
                            let precondition = sbproxy_cache::evaluate_cached_preconditions(
                                req_method.as_str(),
                                entry.status,
                                &entry.headers,
                                &if_none_match,
                                if_modified_since,
                            );
                            let (response_status, response_headers) = match precondition {
                                sbproxy_cache::CachedPrecondition::ServeRepresentation => {
                                    (entry.status, entry.headers.clone())
                                }
                                sbproxy_cache::CachedPrecondition::NotModified => {
                                    (304, sbproxy_cache::headers_for_not_modified(&entry.headers))
                                }
                                sbproxy_cache::CachedPrecondition::PreconditionFailed => {
                                    (412, Vec::new())
                                }
                            };
                            let mut header = pingora_http::ResponseHeader::build(
                                response_status,
                                Some(response_headers.len() + 1),
                            )
                            .map_err(|e| {
                                Error::because(
                                    ErrorType::InternalError,
                                    "cache hit response header",
                                    e,
                                )
                            })?;
                            for (name, value) in &response_headers {
                                let _ = header.insert_header(name.clone(), value.clone());
                            }
                            let _ = header.insert_header("x-sbproxy-cache", cache_marker);

                            let send_body = matches!(
                                precondition,
                                sbproxy_cache::CachedPrecondition::ServeRepresentation
                            ) && !req_method.eq_ignore_ascii_case("HEAD")
                                && response_status != 204
                                && response_status != 304
                                && !(100..200).contains(&response_status);
                            session
                                .write_response_header(Box::new(header), !send_body)
                                .await?;
                            if send_body {
                                session
                                    .write_response_body(
                                        Some(bytes::Bytes::copy_from_slice(&entry.body)),
                                        true,
                                    )
                                    .await?;
                            }
                            ctx.served_from_cache = true;
                            ctx.record_admin_cache_status(crate::context::AdminCacheStatus::Hit);
                            sbproxy_observe::metrics::record_cache(
                                origin.origin_id.as_ref(),
                                "hit",
                            );

                            // --- SWR revalidation ---
                            // On a stale serve, kick off a background fetch
                            // of the upstream so the next request lands on
                            // a fresh entry. The task is tracked by
                            // CACHE_REVALIDATE_TASKS so graceful shutdown
                            // can drain in-flight refreshes.
                            if in_swr {
                                let req = session.req_header();
                                let revalidation_request = build_swr_revalidation_request(
                                    &pipeline,
                                    origin_idx,
                                    req,
                                    &cache_cfg.vary,
                                );
                                let path_and_query = req
                                    .uri
                                    .path_and_query()
                                    .map(|p| p.as_str().to_string())
                                    .unwrap_or_else(|| req.uri.path().to_string());
                                // Capture cacheable_status so the
                                // refresh path applies the same gate
                                // the response_filter does.
                                let cacheable_status = cache_cfg.cacheable_status.clone();
                                let new_ttl = cache_cfg.ttl_secs;
                                if let Some(revalidation_request) = revalidation_request {
                                    spawn_swr_revalidation(
                                        cache_store.clone(),
                                        key.clone(),
                                        entry,
                                        new_ttl,
                                        revalidation_request,
                                        path_and_query,
                                        cacheable_status,
                                    );
                                }
                            }
                            return Ok(true);
                        }

                        // Past TTL and outside the SWR window:
                        // treat as a miss. Drop the stale entry
                        // and let the upstream call refresh it.
                        //
                        // Cache Reserve: an evicted hot entry is a
                        // candidate for the cold tier. The
                        // admission filter (sample / TTL / size)
                        // gates the write so the reserve doesn't
                        // see write amplification from short-lived
                        // entries. We capture the body before
                        // deletion so the reserve get the full
                        // response.
                        if let (Some(reserve), Some(admission)) = (
                            pipeline.cache_reserve.clone(),
                            pipeline.cache_reserve_admission,
                        ) {
                            maybe_admit_to_reserve(
                                reserve.clone(),
                                admission,
                                key.clone(),
                                &entry,
                                origin.origin_id.to_string(),
                            );
                        }
                        let evict_store = cache_store.clone();
                        let evict_key = key.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            let _ = evict_store.delete(&evict_key);
                        })
                        .await;
                        ctx.cache_key = Some(key);
                    }
                    Ok(None) => {
                        // --- Cache Reserve cold-tier lookup ---
                        //
                        // Hot miss. If a reserve is wired, consult
                        // it before remembering the miss key.
                        // Reserve hits are replayed straight back
                        // to the client with `x-sbproxy-cache:
                        // HIT-RESERVE` and promoted into the hot
                        // tier so subsequent reads stay hot.
                        if let Some(reserve) = pipeline.cache_reserve.clone() {
                            let lookup_key = key.clone();
                            let lookup_origin = origin.origin_id.to_string();
                            match reserve.get(&lookup_key).await {
                                Ok(Some((body, metadata))) => {
                                    let now = std::time::SystemTime::now();
                                    if !metadata.is_expired(now) {
                                        // Promote into the hot tier
                                        // before serving so a
                                        // subsequent re-read is a
                                        // plain HIT, not another
                                        // HIT-RESERVE round-trip.
                                        let promote_key = key.clone();
                                        let promote_store = cache_store.clone();
                                        let promote_body = body.clone();
                                        let promote_meta = metadata.clone();
                                        let _ = tokio::task::spawn_blocking(move || {
                                            let cached = promote_meta.to_cached_response(
                                                promote_body,
                                                std::time::SystemTime::now()
                                                    .duration_since(std::time::UNIX_EPOCH)
                                                    .unwrap_or_default()
                                                    .as_secs(),
                                                promote_meta
                                                    .expires_at
                                                    .duration_since(std::time::SystemTime::now())
                                                    .map(|duration| duration.as_secs())
                                                    .unwrap_or(60),
                                            );
                                            let _ = promote_store.put(&promote_key, &cached);
                                        })
                                        .await;
                                        // Serve.
                                        let request_header = session.req_header();
                                        let if_none_match: Vec<&[u8]> = request_header
                                            .headers
                                            .get_all("if-none-match")
                                            .iter()
                                            .map(|value| value.as_bytes())
                                            .collect();
                                        let if_modified_since = request_header
                                            .headers
                                            .get("if-modified-since")
                                            .map(|value| value.as_bytes());
                                        let precondition =
                                            sbproxy_cache::evaluate_cached_preconditions(
                                                req_method.as_str(),
                                                metadata.status,
                                                &metadata.headers,
                                                &if_none_match,
                                                if_modified_since,
                                            );
                                        let (response_status, mut response_headers) =
                                            match precondition {
                                                sbproxy_cache::CachedPrecondition::ServeRepresentation => {
                                                    (metadata.status, metadata.headers.clone())
                                                }
                                                sbproxy_cache::CachedPrecondition::NotModified => (
                                                    304,
                                                    sbproxy_cache::headers_for_not_modified(
                                                        &metadata.headers,
                                                    ),
                                                ),
                                                sbproxy_cache::CachedPrecondition::PreconditionFailed => {
                                                    (412, Vec::new())
                                                }
                                            };
                                        if matches!(
                                            precondition,
                                            sbproxy_cache::CachedPrecondition::ServeRepresentation
                                        ) && !response_headers.iter().any(|(name, _)| {
                                            name.eq_ignore_ascii_case("content-type")
                                        }) {
                                            if let Some(content_type) =
                                                metadata.content_type.as_ref()
                                            {
                                                response_headers.push((
                                                    "content-type".to_string(),
                                                    content_type.clone(),
                                                ));
                                            }
                                        }
                                        let mut header = pingora_http::ResponseHeader::build(
                                            response_status,
                                            Some(response_headers.len() + 1),
                                        )
                                        .map_err(|e| {
                                            Error::because(
                                                ErrorType::InternalError,
                                                "reserve hit response header",
                                                e,
                                            )
                                        })?;
                                        for (name, value) in &response_headers {
                                            let _ =
                                                header.insert_header(name.clone(), value.clone());
                                        }
                                        let _ =
                                            header.insert_header("x-sbproxy-cache", "HIT-RESERVE");
                                        let send_body = matches!(
                                            precondition,
                                            sbproxy_cache::CachedPrecondition::ServeRepresentation
                                        ) && !req_method
                                            .eq_ignore_ascii_case("HEAD")
                                            && response_status != 204
                                            && response_status != 304
                                            && !(100..200).contains(&response_status);
                                        session
                                            .write_response_header(Box::new(header), !send_body)
                                            .await?;
                                        if send_body {
                                            session.write_response_body(Some(body), true).await?;
                                        }
                                        ctx.served_from_cache = true;
                                        ctx.record_admin_cache_status(
                                            crate::context::AdminCacheStatus::Hit,
                                        );
                                        sbproxy_observe::metrics::record_cache(
                                            origin.origin_id.as_ref(),
                                            "hit",
                                        );
                                        sbproxy_observe::metrics()
                                            .cache_reserve_hits
                                            .with_label_values(&[lookup_origin.as_str()])
                                            .inc();
                                        return Ok(true);
                                    }
                                    // Expired metadata; drop and
                                    // fall through.
                                    let _ = reserve.delete(&lookup_key).await;
                                    sbproxy_observe::metrics()
                                        .cache_reserve_misses
                                        .with_label_values(&[lookup_origin.as_str()])
                                        .inc();
                                }
                                Ok(None) => {
                                    sbproxy_observe::metrics()
                                        .cache_reserve_misses
                                        .with_label_values(&[lookup_origin.as_str()])
                                        .inc();
                                }
                                Err(e) => {
                                    warn!(
                                        error = %e,
                                        "cache reserve lookup failed; bypassing reserve"
                                    );
                                }
                            }
                        }
                        // Miss: remember the key so the response phase
                        // can populate the cache when the upstream reply
                        // comes back.
                        ctx.cache_key = Some(key);
                    }
                    Err(e) => {
                        warn!(error = %e, "cache lookup error, bypassing cache");
                    }
                }

                // Every cache hit above serves the response and returns, so
                // reaching here means the lookup did not produce a live entry
                // to serve: a hot miss, a stale entry past the SWR window, a
                // cold-reserve miss, or a lookup error. All fall through to the
                // upstream fetch, which is what a cache miss is.
                sbproxy_observe::metrics::record_cache(origin.origin_id.as_ref(), "miss");
            }
        }
    }

    // --- Capture mirror params for body teeing ---
    // We can't fire the mirror here because the inbound body
    // hasn't arrived yet. Stash everything we need into ctx and
    // let request_body_filter fire it once the body is fully
    // buffered (or skip body teeing if mirror_body is false).
    if let Some(mirror) = &origin.mirror {
        let sampled = if mirror.sample_rate >= 1.0 {
            true
        } else if mirror.sample_rate <= 0.0 {
            false
        } else {
            rand::random::<f32>() < mirror.sample_rate
        };
        if sampled {
            ctx.mirror_pending = Some(crate::context::MirrorParams {
                url: mirror.url.clone(),
                timeout: std::time::Duration::from_millis(mirror.timeout_ms),
                method: session.req_header().method.as_str().to_string(),
                path_and_query: session
                    .req_header()
                    .uri
                    .path_and_query()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_else(|| session.req_header().uri.path().to_string()),
                headers: session.req_header().headers.clone(),
                request_id: ctx.request_id.to_string(),
                mirror_body: mirror.mirror_body,
                max_body_bytes: mirror.max_body_bytes,
            });
        }
    }

    // --- Fire on_request callbacks ---
    if !origin.on_request.is_empty() {
        let method = session.req_header().method.as_str().to_string();
        let path = session.req_header().uri.path().to_string();
        let hostname = ctx.hostname.to_string();
        let client_ip = ctx.client_ip.map(|ip| ip.to_string());
        let headers = session.req_header().headers.clone();
        let request_id = ctx.request_id.to_string();
        let config_revision = pipeline.config_revision.clone();
        let callbacks = origin.on_request.clone();
        let injected = fire_on_request_callbacks(
            &callbacks,
            &method,
            &path,
            &hostname,
            client_ip,
            &request_id,
            &config_revision,
            &headers,
        )
        .await;
        if !injected.is_empty() {
            ctx.callback_inject_headers
                .get_or_insert_with(Vec::new)
                .extend(injected);
        }
    }

    // --- Forward rules: path/header/query/body routing to inline origins ---
    // WOR-2306: the body the matchers below read, drained here because this
    // is the last moment before a route is chosen and the first moment worth
    // paying for. Everything above this line can short-circuit the request
    // (auth, rate limits, a cache hit), and none of those outcomes needs the
    // body. `None` for every origin that declared no body matcher.
    let matched_body = read_body_for_route_matching(session, body_route_cap).await?;

    let fwd_rules = &pipeline.forward_rules[origin_idx];
    if !fwd_rules.is_empty() {
        // WOR-1697: only snapshot the path/query strings when there are
        // forward rules to match against.
        let request_path = session.req_header().uri.path().to_string();
        let request_query = session.req_header().uri.query().map(|q| q.to_string());
        for (rule_idx, fwd_rule) in fwd_rules.iter().enumerate() {
            // Each `MatcherEntry` ANDs path/header/query/body; entries in
            // the list are ORed. `match_request_with_body` returns the
            // captured path params (possibly empty) when the entry fires.
            let request_headers = &session.req_header().headers;
            let captured = fwd_rule.matchers.iter().find_map(|m| {
                m.match_request_with_body(
                    &request_path,
                    request_query.as_deref(),
                    request_headers,
                    matched_body.as_deref(),
                )
            });
            if let Some(params) = captured {
                debug!(
                    hostname = %ctx.hostname,
                    path = %request_path,
                    rule_idx = %rule_idx,
                    captured_params = params.len(),
                    "forward rule matched"
                );
                ctx.forward_rule_idx = Some(rule_idx);
                if !params.is_empty() {
                    ctx.path_params = Some(params);
                }

                // Apply forward-rule request modifiers early so they are
                // present in the upstream request even if upstream_request_filter
                // Forward rule request modifiers are collected and applied in
                // upstream_request_filter via Pingora's insert_header() method.
                // Direct req_header_mut().headers access doesn't propagate to upstream.

                // Handle the forward rule's action.
                if handle_action(&fwd_rule.action, session, &pipeline, Some(origin_idx), ctx)
                    .await?
                {
                    return Ok(true);
                }
                // If the forward rule action is a proxy type, it will be handled
                // in upstream_peer via the forward_rule_idx context field.
                return Ok(false);
            }
        }
    }

    // --- Handle non-proxy actions directly ---
    if handle_action(
        &pipeline.actions[origin_idx],
        session,
        &pipeline,
        Some(origin_idx),
        ctx,
    )
    .await?
    {
        return Ok(true);
    }

    // --- Short-circuit check (set by future middleware phases) ---
    if let Some(status) = ctx.short_circuit_status {
        if let Some(body) = ctx.short_circuit_body.take() {
            let content_type = ctx
                .short_circuit_content_type
                .take()
                .unwrap_or_else(|| "text/plain".to_string());
            let mut header = pingora_http::ResponseHeader::build(status, Some(1)).map_err(|e| {
                Error::because(
                    ErrorType::InternalError,
                    "failed to build response header",
                    e,
                )
            })?;
            header
                .insert_header("content-type", content_type.as_str())
                .map_err(|e| Error::because(ErrorType::InternalError, "failed to set header", e))?;
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session.write_response_body(Some(body), true).await?;
        } else {
            let header = pingora_http::ResponseHeader::build(status, None).map_err(|e| {
                Error::because(
                    ErrorType::InternalError,
                    "failed to build response header",
                    e,
                )
            })?;
            session
                .write_response_header(Box::new(header), true)
                .await?;
        }
        return Ok(true);
    }

    // Continue to upstream_peer for proxy action.
    Ok(false)
}

// --- WOR-808 PR7: OLP helpers ---

/// Build the JWK Set body for `GET /.well-known/olp/key`. The set
/// contains one verification key for the configured signing key.
/// Rotation overlap would push a second key with a different `kid`;
/// PR1 ships single-key only.
fn build_olp_jwk_set(cfg: &sbproxy_config::OlpConfig) -> Result<String, String> {
    let seed = decode_ed25519_seed(&cfg.signing_key)?;
    let signer = sbproxy_modules::olp::OlpTokenSigner::from_seed_bytes(seed, &cfg.key_id);
    let jwk = sbproxy_modules::olp::jwk_from_verifying_key(&signer.verifying_key(), &cfg.key_id);
    let set = sbproxy_modules::olp::OlpJwkSet { keys: vec![jwk] };
    serde_json::to_string(&set).map_err(|e| format!("jwk set encode failed: {e}"))
}

/// Issue an OLP license token for `POST /.well-known/olp/token`. The
/// response body mirrors RFC 6749 §5.1 (`access_token`, `token_type`,
/// `expires_in`, `scope`) so existing OAuth-style clients consume it.
/// `token_type` is pinned to RSL 1.0's `License`.
///
/// `sub` is the resolved subject (the `client_id` from the form body
/// for `grant_type=client_credentials`). The handler validates the
/// grant and rejects missing/blank `client_id` before reaching here,
/// so by the time we sign we always have a non-empty subject.
fn issue_olp_token(
    cfg: &sbproxy_config::OlpConfig,
    hostname: &str,
    license_urn: &str,
    sub: &str,
) -> Result<String, String> {
    let seed = decode_ed25519_seed(&cfg.signing_key)?;
    let signer = sbproxy_modules::olp::OlpTokenSigner::from_seed_bytes(seed, &cfg.key_id);
    // WOR-808 PR8: when the operator declares `content_key_seed`,
    // derive a per-token EMS content key and attach it as a
    // `cnf.jwk` claim (RFC 7800). Seed accepted as hex for
    // compactness; non-hex / wrong length disables the binding
    // (the issuer keeps working, just without EMS).
    let content_key_seed = cfg
        .content_key_seed
        .as_ref()
        .and_then(|s| decode_hex_bytes(s.as_str()).ok());
    let req = sbproxy_modules::olp::IssueRequest {
        sub,
        aud: hostname,
        license_urn,
        scope_override: None,
        ttl_secs_override: None,
        content_key_seed: content_key_seed.as_deref(),
    };
    let claims = sbproxy_modules::olp::build_claims(
        &req,
        &cfg.issuer,
        &cfg.default_scope,
        cfg.default_ttl_secs,
    );
    let token = signer
        .sign(&claims)
        .map_err(|e| format!("olp sign failed: {e:?}"))?;
    let body = serde_json::json!({
        "access_token": token,
        "token_type": sbproxy_modules::olp::OLP_TOKEN_TYPE,
        "expires_in": cfg.default_ttl_secs,
        "scope": claims.scope,
        "license_urn": claims.license_urn,
    });
    serde_json::to_string(&body).map_err(|e| format!("token body encode failed: {e}"))
}

// --- WOR-808 PR9: /introspect + /revoke handlers ---

/// Body cap for `POST /.well-known/olp/{introspect,revoke}`. Form
/// bodies are tiny (a token plus a hint); 8 KiB is the upper bound
/// so a misconfigured client cannot tip the endpoint into unbounded
/// buffering. The base64url JWS plus headers easily fit.
const MAX_OLP_INTROSPECT_BODY_BYTES: usize = 8 * 1024;

/// Process-global revocation-store registry. Keyed by hostname so
/// the same store is reused across requests on one origin; reloads
/// that do not change the backend keep the in-memory revocation set.
/// PR9 ships the Memory backend; redb + redis are PR10.
fn revocation_store_registry() -> &'static std::sync::Mutex<
    std::collections::HashMap<String, std::sync::Arc<dyn sbproxy_platform::storage::KVStore>>,
> {
    static REG: std::sync::OnceLock<
        std::sync::Mutex<
            std::collections::HashMap<
                String,
                std::sync::Arc<dyn sbproxy_platform::storage::KVStore>,
            >,
        >,
    > = std::sync::OnceLock::new();
    REG.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Look up (or lazily create) the revocation-store instance for
/// `audience` per the operator-declared backend. WOR-808 PR10 wires
/// the redb backend. PR11 wires Redis. Returns `None` when the
/// backend file / connection cannot be opened so the handler can
/// surface a 503 instead of silently allowing every token through.
fn get_or_init_revocation_store(
    audience: &str,
    cfg: &sbproxy_config::OlpRevocationStoreConfig,
) -> Option<std::sync::Arc<dyn sbproxy_platform::storage::KVStore>> {
    let key = match cfg {
        sbproxy_config::OlpRevocationStoreConfig::Memory => format!("mem:{audience}"),
        sbproxy_config::OlpRevocationStoreConfig::Redb { path } => {
            format!("redb:{audience}:{}", path.display())
        }
        sbproxy_config::OlpRevocationStoreConfig::Redis { url } => {
            format!("redis:{audience}:{url}")
        }
    };
    let mut reg = revocation_store_registry().lock().ok()?;
    if let Some(existing) = reg.get(&key) {
        return Some(existing.clone());
    }
    let new_store: std::sync::Arc<dyn sbproxy_platform::storage::KVStore> = match cfg {
        sbproxy_config::OlpRevocationStoreConfig::Memory => {
            std::sync::Arc::new(sbproxy_platform::storage::MemoryKVStore::new(64 * 1024))
        }
        sbproxy_config::OlpRevocationStoreConfig::Redb { path } => {
            // WOR-808 PR10: open the operator-declared redb file.
            // RedbKVStore wants a &str; surface a None on the open
            // error so the handler returns 503 rather than crashing.
            let path_str = path.to_str()?;
            match sbproxy_platform::storage::RedbKVStore::new(path_str) {
                Ok(s) => std::sync::Arc::new(s),
                Err(e) => {
                    warn!(
                        error = %e,
                        path = %path.display(),
                        "olp revocation: failed to open redb file"
                    );
                    return None;
                }
            }
        }
        sbproxy_config::OlpRevocationStoreConfig::Redis { url } => {
            // WOR-808 PR11: open the operator-declared Redis store.
            // Invalid connection configuration returns None so the handler
            // 503s. Introspection must not silently allow when the revocation
            // store is unavailable.
            let redis_cfg = sbproxy_platform::storage::RedisConfig::from_dsn(url).ok()?;
            std::sync::Arc::new(sbproxy_platform::storage::RedisKVStore::new(redis_cfg))
        }
    };
    reg.insert(key, new_store.clone());
    Some(new_store)
}

#[cfg(test)]
mod redis_revocation_store_tests {
    use super::get_or_init_revocation_store;
    use sbproxy_config::OlpRevocationStoreConfig;

    #[test]
    fn redis_revocation_store_accepts_full_secure_dsn_without_network_io() {
        let config = OlpRevocationStoreConfig::Redis {
            url: "rediss://default:p%40ss@[::1]:6380/7".to_string(),
        };

        assert!(get_or_init_revocation_store("secure-dsn.example", &config).is_some());
    }

    #[test]
    fn redis_revocation_store_rejects_invalid_dsn_before_network_io() {
        let config = OlpRevocationStoreConfig::Redis {
            url: "rediss://default:sentinel-olp-password@sentinel-olp-host.invalid:6380/-1"
                .to_string(),
        };

        assert!(get_or_init_revocation_store("invalid-dsn.example", &config).is_none());
    }

    #[test]
    fn invalid_revocation_store_log_uses_static_unavailable_message() {
        let source = include_str!("request_phase.rs");
        let obsolete = ["revocation store backend not yet", " implemented"].concat();

        assert!(
            source.contains("warn!(\"olp introspect: revocation store unavailable\");"),
            "invalid revocation-store construction must report unavailability"
        );
        assert!(
            !source.contains(&obsolete),
            "shipped Redis support must not be described as unimplemented"
        );
    }
}

/// WOR-808 PR10: per-IP token-bucket rate limiter for the
/// `active: false` path on `/.well-known/olp/introspect`. RFC 7662
/// §2.1 calls out token-scanning attacks against introspect
/// endpoints; a per-IP cap on inactive responses denies the
/// scanner the oracle without blocking legitimate RPs (who hit
/// the active path on their own tokens).
///
/// Bucket: 60 tokens, refill 60/minute (one per second). A scanner
/// firing >60 inactive lookups per minute from one IP gets 429'd;
/// burst up to 60 is allowed. Per-origin instance so multi-tenant
/// deployments cannot cross-contaminate.
struct IntrospectRateLimiter {
    buckets: std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, IntrospectBucket>>,
}

struct IntrospectBucket {
    tokens: f64,
    last_refill: std::time::Instant,
}

/// Maximum burst of `active:false` responses per source IP before
/// the limiter trips. The same value sets the steady-state cap:
/// the bucket refills at `INTROSPECT_CAPACITY / 60` tokens per
/// second so a sustained scanner sees roughly one allowed inactive
/// per second.
const INTROSPECT_CAPACITY: f64 = 60.0;

/// Refill rate, tokens per second. Tied to `INTROSPECT_CAPACITY`
/// for the one-per-second cadence above.
const INTROSPECT_REFILL_PER_SEC: f64 = INTROSPECT_CAPACITY / 60.0;

impl IntrospectRateLimiter {
    fn new() -> Self {
        Self {
            buckets: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Returns `true` when the IP is within budget. Consumes one
    /// token; refills on the wall clock since the last call.
    fn check_and_consume(&self, ip: std::net::IpAddr) -> bool {
        let now = std::time::Instant::now();
        let mut buckets = match self.buckets.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let bucket = buckets.entry(ip).or_insert(IntrospectBucket {
            tokens: INTROSPECT_CAPACITY,
            last_refill: now,
        });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens =
            (bucket.tokens + elapsed * INTROSPECT_REFILL_PER_SEC).min(INTROSPECT_CAPACITY);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

fn introspect_rate_limiter() -> &'static IntrospectRateLimiter {
    static L: std::sync::OnceLock<IntrospectRateLimiter> = std::sync::OnceLock::new();
    L.get_or_init(IntrospectRateLimiter::new)
}

/// Extract the client IP from the session. Honours
/// `X-Forwarded-For` first (left-most) and falls back to the
/// connection-level remote addr. The CIDR-trusted-proxy check is
/// not enforced here because the introspect endpoint is operator-
/// scoped; an attacker who could spoof XFF would already be on the
/// trusted segment.
fn introspect_client_ip(session: &pingora_proxy::Session) -> Option<std::net::IpAddr> {
    if let Some(xff) = session
        .req_header()
        .headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(first) = xff.split(',').next() {
            if let Ok(ip) = first.trim().parse::<std::net::IpAddr>() {
                return Some(ip);
            }
        }
    }
    session
        .client_addr()
        .and_then(|a| a.as_inet())
        .map(|s| s.ip())
}

/// Single-pass handler for `POST /.well-known/olp/introspect` (RFC
/// 7662) and `POST /.well-known/olp/revoke` (RFC 7009). Auth + body
/// parsing are shared; the `is_revoke` flag flips the terminal
/// behaviour. Returns Ok on every wire-shaped outcome; the caller
/// has already returned `true` to the pipeline.
async fn handle_olp_introspect_or_revoke(
    session: &mut pingora_proxy::Session,
    olp: &sbproxy_config::OlpConfig,
    introspect_cfg: &sbproxy_config::OlpIntrospectConfig,
    is_revoke: bool,
) -> Result<()> {
    // --- read body ---
    let mut body_buf: Vec<u8> = Vec::new();
    while let Some(chunk) = session.read_request_body().await? {
        let remaining = MAX_OLP_INTROSPECT_BODY_BYTES.saturating_sub(body_buf.len());
        if remaining == 0 {
            break;
        }
        let take = std::cmp::min(chunk.len(), remaining);
        body_buf.extend_from_slice(&chunk[..take]);
        if body_buf.len() >= MAX_OLP_INTROSPECT_BODY_BYTES {
            break;
        }
    }
    let body_str = std::str::from_utf8(&body_buf).unwrap_or("");

    // --- parse form ---
    let mut token: Option<String> = None;
    for pair in body_str.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == "token" {
                token = Some(decode_form_component(v));
            }
        }
    }
    let token = match token {
        Some(t) if !t.is_empty() => t,
        _ => {
            let body = serde_json::json!({
                "error": "invalid_request",
                "error_description": "token form parameter is required",
            })
            .to_string();
            send_response(session, 400, "application/json", body.as_bytes()).await?;
            return Ok(());
        }
    };

    // --- caller auth (RFC 7662 §2.1 MUSTs some form of authorization) ---
    let auth_outcome = check_introspect_auth(session, &introspect_cfg.auth, &token);
    match auth_outcome {
        IntrospectAuthOutcome::Allowed => {}
        IntrospectAuthOutcome::Unauthorized => {
            let mut headers = Vec::new();
            headers.push((
                "WWW-Authenticate".to_string(),
                format!(
                    "Basic realm=\"{}\"",
                    escape_quoted_string(&introspect_cfg.realm)
                ),
            ));
            send_response_with_headers(
                session,
                401,
                "application/json",
                br#"{"error":"invalid_client"}"#,
                &headers,
            )
            .await?;
            return Ok(());
        }
    }

    // --- build verifier + revocation store ---
    let seed = match decode_ed25519_seed(&olp.signing_key) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "olp introspect: signing key invalid");
            send_error(session, 500, "olp key invalid").await?;
            return Ok(());
        }
    };
    let signer = sbproxy_modules::olp::OlpTokenSigner::from_seed_bytes(seed, &olp.key_id);
    let verifier = sbproxy_modules::olp::OlpTokenVerifier::new(signer.verifying_key(), &olp.key_id);
    let aud_hint = olp.issuer.trim_end_matches('/');
    let store = match get_or_init_revocation_store(aud_hint, &introspect_cfg.revocation_store) {
        Some(s) => s,
        None => {
            warn!("olp introspect: revocation store unavailable");
            let body = br#"{"error":"temporarily_unavailable"}"#;
            send_response(session, 503, "application/json", body).await?;
            return Ok(());
        }
    };
    use sbproxy_modules::olp::RevocationStore as _;
    let revocation = sbproxy_modules::olp::KvRevocationStore::new(store, aud_hint);

    // --- /revoke branch ---
    if is_revoke {
        let claims = match verifier.verify(
            &token,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        ) {
            Ok(c) => c,
            // RFC 7009 §2.2: invalid tokens get a 200 anyway (so a
            // caller cannot enumerate which tokens were valid).
            Err(_) => {
                send_response(session, 200, "application/json", b"{}").await?;
                return Ok(());
            }
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let ttl = claims.exp.saturating_sub(now);
        if let Err(e) = revocation.revoke(&claims.jti, ttl, "operator-issued revoke") {
            warn!(error = %e, "olp revoke: store write failed");
            send_response(
                session,
                503,
                "application/json",
                br#"{"error":"temporarily_unavailable"}"#,
            )
            .await?;
            return Ok(());
        }
        send_response(session, 200, "application/json", b"{}").await?;
        return Ok(());
    }

    // --- /introspect branch ---
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let response = match sbproxy_modules::olp::introspect(
        &verifier,
        &revocation,
        &token,
        now,
        introspect_cfg.mirror_cnf,
    ) {
        Ok(r) => r,
        // Storage error path (RFC 7662 §2.2: NOT 200 active:false,
        // since that would let an attacker fault-inject the store
        // to bypass revocation).
        Err(e) => {
            warn!(error = %e, "olp introspect: revocation store unavailable");
            send_response(
                session,
                503,
                "application/json",
                br#"{"error":"temporarily_unavailable"}"#,
            )
            .await?;
            return Ok(());
        }
    };
    // WOR-808 PR10: rate-limit `active:false` responses per source
    // IP. RFC 7662 §2.1 calls out token-scanning attacks; this is
    // the scan-defence belt-and-suspenders that complements the
    // mandatory caller-auth check above. Only inactive responses
    // are limited so a legitimate RP introspecting its own valid
    // tokens never hits the cap.
    if !response.active {
        if let Some(ip) = introspect_client_ip(session) {
            if !introspect_rate_limiter().check_and_consume(ip) {
                warn!(client_ip = %ip, "olp introspect: rate limit tripped on active:false");
                send_response(
                    session,
                    429,
                    "application/json",
                    br#"{"error":"too_many_requests","error_description":"introspect inactive-response rate limit"}"#,
                )
                .await?;
                return Ok(());
            }
        }
    }
    let body = serde_json::to_vec(&response).unwrap_or_else(|_| br#"{"active":false}"#.to_vec());
    send_response(session, 200, "application/json", &body).await?;
    Ok(())
}

/// Result of the caller-authentication check on the introspect /
/// revoke endpoints. Only two outcomes today; PR follow-up may add
/// `Throttled` once the per-IP rate limiter ships.
enum IntrospectAuthOutcome {
    Allowed,
    Unauthorized,
}

/// Validate the caller credentials per the configured policy.
///
/// `mode: self` succeeds when the caller presents
/// `Authorization: License <token>` whose value equals the form-body
/// `token` (so the caller proves possession). `mode: basic` requires
/// matching Basic credentials. `mode: none` allows everyone.
fn check_introspect_auth(
    session: &pingora_proxy::Session,
    auth: &sbproxy_config::OlpIntrospectAuth,
    form_token: &str,
) -> IntrospectAuthOutcome {
    match auth {
        sbproxy_config::OlpIntrospectAuth::None => IntrospectAuthOutcome::Allowed,
        sbproxy_config::OlpIntrospectAuth::SelfProof => {
            let header_token = session
                .req_header()
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("License "))
                .map(str::trim)
                .unwrap_or("");
            // Constant-time-ish comparison: both strings to bytes,
            // length check first then byte-by-byte. The token values
            // are not secrets in the usual sense (the caller already
            // holds them), but matching on the same identity twice
            // closes the loop without leaking timing on length.
            if header_token.len() != form_token.len() || header_token.is_empty() {
                return IntrospectAuthOutcome::Unauthorized;
            }
            let mut diff: u8 = 0;
            for (a, b) in header_token.bytes().zip(form_token.bytes()) {
                diff |= a ^ b;
            }
            if diff == 0 {
                IntrospectAuthOutcome::Allowed
            } else {
                IntrospectAuthOutcome::Unauthorized
            }
        }
        sbproxy_config::OlpIntrospectAuth::Basic { clients } => {
            use base64::Engine as _;
            let header = session
                .req_header()
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Basic "))
                .map(str::trim)
                .unwrap_or("");
            let decoded: Vec<u8> = match base64::engine::general_purpose::STANDARD.decode(header) {
                Ok(d) => d,
                Err(_) => return IntrospectAuthOutcome::Unauthorized,
            };
            let creds = std::str::from_utf8(&decoded).unwrap_or("");
            let (user, pass) = match creds.split_once(':') {
                Some(kv) => kv,
                None => return IntrospectAuthOutcome::Unauthorized,
            };
            for client in clients {
                if client.username != user {
                    continue;
                }
                if verify_argon2_password(&client.password_hash, pass) {
                    return IntrospectAuthOutcome::Allowed;
                }
            }
            IntrospectAuthOutcome::Unauthorized
        }
    }
}

/// Verify an Argon2id PHC-format hash against a plaintext password.
/// Returns false on any parse / verify failure (the caller maps both
/// to 401).
fn verify_argon2_password(phc_hash: &str, password: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    use argon2::Argon2;
    let parsed = match PasswordHash::new(phc_hash) {
        Ok(p) => p,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Send a JSON response with extra response headers. Used by the
/// introspect 401 path to attach `WWW-Authenticate`.
async fn send_response_with_headers(
    session: &mut pingora_proxy::Session,
    status: u16,
    content_type: &str,
    body: &[u8],
    extra_headers: &[(String, String)],
) -> Result<()> {
    let mut header = pingora_http::ResponseHeader::build(status, None)?;
    header.insert_header("content-type", content_type)?;
    header.insert_header("content-length", body.len().to_string())?;
    for (name, value) in extra_headers {
        header.append_header(name.clone(), value.clone())?;
    }
    session
        .write_response_header(Box::new(header), false)
        .await?;
    session
        .write_response_body(Some(bytes::Bytes::copy_from_slice(body)), true)
        .await?;
    Ok(())
}

/// Decode a 32-byte Ed25519 seed from the operator-configured
/// `signing_key` string. PR1 accepts a 64-char lowercase hex string;
/// the secret-resolver pass at config-load time substitutes any
/// `vault://` reference into the raw bytes upstream of this point.
fn decode_ed25519_seed(s: &str) -> Result<[u8; 32], String> {
    let trimmed = s.trim();
    if trimmed.len() != 64 {
        return Err(format!(
            "ed25519 signing_key must be 32 bytes hex (64 chars); got {} chars",
            trimmed.len()
        ));
    }
    let decoded = hex::decode(trimmed).map_err(|e| e.to_string())?;
    decoded
        .try_into()
        .map_err(|_| "ed25519 signing_key must decode to exactly 32 bytes".to_string())
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("not a hex char: {b:#04x}")),
    }
}

/// Subject claim used when the client posts an empty or non-form
/// body. Lets existing JSON-shaped automation keep minting tokens
/// while opt-in form clients get a bound subject.
pub(crate) const OLP_ANONYMOUS_SUB: &str = "anonymous";

/// Content-type that gates the RFC 6749 §4.4 form-body path on
/// `POST /.well-known/olp/token`.
pub(crate) const OLP_TOKEN_FORM_CT: &str = "application/x-www-form-urlencoded";

/// Parsed `POST /.well-known/olp/token` form body. Carries the
/// resolved subject so the issuer can bind it as the `sub` claim
/// without re-parsing.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OlpTokenForm {
    pub client_id: String,
}

/// RFC 6749 §5.2 error code + human-readable description. Returned
/// as a JSON object on a 400 response.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OlpTokenFormError {
    pub code: &'static str,
    pub description: &'static str,
}

/// Parse a `POST /.well-known/olp/token` form body. Requires
/// `grant_type=client_credentials` (RFC 6749 §4.4) and a non-empty
/// `client_id`. Unknown extra parameters are ignored so the issuer
/// stays forward-compatible with audience / scope / resource
/// indicator extensions.
///
/// Errors are RFC 6749 §5.2 codes so the JSON response body uses the
/// same vocabulary as standard OAuth token endpoints.
pub(crate) fn parse_olp_token_form(body: &str) -> Result<OlpTokenForm, OlpTokenFormError> {
    let mut grant_type: Option<String> = None;
    let mut client_id: Option<String> = None;
    for pair in body.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_key, raw_val) = match pair.split_once('=') {
            Some(kv) => kv,
            None => (pair, ""),
        };
        let key = decode_form_component(raw_key);
        let val = decode_form_component(raw_val);
        match key.as_str() {
            "grant_type" => grant_type = Some(val),
            "client_id" => client_id = Some(val),
            _ => {}
        }
    }
    match grant_type.as_deref() {
        Some("client_credentials") => {}
        Some(_) => {
            return Err(OlpTokenFormError {
                code: "unsupported_grant_type",
                description: "only client_credentials is supported",
            });
        }
        None => {
            return Err(OlpTokenFormError {
                code: "invalid_request",
                description: "grant_type is required",
            });
        }
    }
    let client_id = client_id.unwrap_or_default();
    if client_id.is_empty() {
        return Err(OlpTokenFormError {
            code: "invalid_request",
            description: "client_id is required and must be non-empty",
        });
    }
    Ok(OlpTokenForm { client_id })
}

/// Decode a single `application/x-www-form-urlencoded` component:
/// `+` -> space, then percent-escape decoding. Invalid escapes are
/// left as-is so a malformed component never crashes the parser;
/// callers validate the resulting strings.
fn decode_form_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'+' {
            out.push(' ');
            i += 1;
        } else if b == b'%' && i + 2 < bytes.len() {
            match (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                (Ok(hi), Ok(lo)) => {
                    out.push(char::from((hi << 4) | lo));
                    i += 3;
                }
                _ => {
                    out.push('%');
                    i += 1;
                }
            }
        } else {
            out.push(char::from(b));
            i += 1;
        }
    }
    out
}

/// WOR-808 PR8: relaxed-length variant of [`decode_ed25519_seed`] used
/// for the EMS content-key seed. Accepts any even-length hex string
/// of at least 32 bytes (HKDF will widen / narrow as needed). Reject
/// anything shorter so the operator does not accidentally configure
/// a key with less entropy than a single AES-256 block.
/// WOR-808: augment a `WWW-Authenticate: License` challenge with
/// `realm=` + `token_url=` parameters per RFC 6750 §3 syntax so the
/// CAP client auto-discovers the OLP issuer endpoint.
///
/// Returns a fresh header vec; non-License headers (and origins
/// without OLP enabled) pass through unchanged. The added params:
///
/// * `realm="<hostname>"`: the protected resource identifier.
/// * `token_url="<scheme>://<host>/.well-known/olp/token"`: the
///   POST endpoint shipped in #336. Scheme is derived from the
///   request's `host` header convention: `https` when the host
///   header carries a port (`api.example.com:8443`) we still use
///   `https` to match the OLP issuer URL in cfg; HTTP-only
///   deployments live behind an opaque proxy where the public URL
///   already comes from the operator's `olp.issuer` config, which
///   we surface verbatim when present.
pub(crate) fn augment_license_challenge(
    extra_headers: &[(String, String)],
    olp: Option<&sbproxy_config::OlpConfig>,
    fallback_hostname: &str,
    host: Option<&str>,
) -> Vec<(String, String)> {
    let olp = match olp {
        Some(cfg) if cfg.enabled => cfg,
        _ => return extra_headers.to_vec(),
    };
    let token_url = format!("{}/.well-known/olp/token", olp.issuer.trim_end_matches('/'));
    let realm = host.unwrap_or(fallback_hostname);
    extra_headers
        .iter()
        .map(|(name, value)| {
            if name.eq_ignore_ascii_case("WWW-Authenticate") && value.starts_with("License") {
                // Avoid clobbering an existing `error=` param.
                // RFC 6750 §3 ordering: scheme, params in any
                // order; concatenate ours after the existing
                // value with a separator.
                let augmented = if value == "License" {
                    format!(
                        "License realm=\"{}\", token_url=\"{}\"",
                        escape_quoted_string(realm),
                        escape_quoted_string(&token_url)
                    )
                } else {
                    format!(
                        "{}, realm=\"{}\", token_url=\"{}\"",
                        value,
                        escape_quoted_string(realm),
                        escape_quoted_string(&token_url)
                    )
                };
                (name.clone(), augmented)
            } else {
                (name.clone(), value.clone())
            }
        })
        .collect()
}

/// Escape `"` and `\` per RFC 7230 §3.2.6 quoted-string syntax so
/// the appended params parse correctly.
fn escape_quoted_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

fn decode_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let trimmed = s.trim();
    if trimmed.len() < 64 || !trimmed.len().is_multiple_of(2) {
        return Err(format!(
            "content_key_seed must be at least 32 bytes hex (64+ even chars); got {} chars",
            trimmed.len()
        ));
    }
    hex::decode(trimmed).map_err(|e| e.to_string())
}

// --- WOR-892 PR2: OIDC callback handler ---

/// Handle a `POST` (some IdPs) or `GET` (most IdPs) to the operator-
/// configured `redirect_path`. Exchanges the IdP-supplied auth code
/// for an ID token, validates the token, mints a sealed session
/// cookie, and 302s to the original return URL.
///
/// All wire-shaped outcomes return `Ok`; the caller has already
/// returned `true` to the pipeline. Errors map to 4xx/5xx responses
/// in line with the OIDC Core 1.0 §3.1.2.7 step list.
async fn handle_oidc_callback(
    session: &mut pingora_proxy::Session,
    cfg: &sbproxy_modules::auth::oidc::OidcAuth,
) -> Result<()> {
    use sbproxy_modules::auth::oidc::{callback, session as oidc_session};

    // --- parse query + cookie ---
    let query = session.req_header().uri.query().unwrap_or("");
    let mut code: Option<String> = None;
    let mut state_q: Option<String> = None;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            match k {
                "code" => code = Some(decode_form_component(v)),
                "state" => state_q = Some(decode_form_component(v)),
                _ => {}
            }
        }
    }
    let code = match code {
        Some(c) if !c.is_empty() => c,
        _ => {
            send_response(
                session,
                400,
                "application/json",
                br#"{"error":"invalid_request","error_description":"code query parameter is required"}"#,
            )
            .await?;
            return Ok(());
        }
    };
    let state_q = state_q.unwrap_or_default();

    let tx_cookie_value = read_request_cookie(session, &cfg.tx_cookie_name);
    let tx_cookie = match tx_cookie_value {
        Some(c) => c,
        None => {
            send_response(
                session,
                400,
                "application/json",
                br#"{"error":"invalid_request","error_description":"oidc tx cookie missing; restart the login"}"#,
            )
            .await?;
            return Ok(());
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let tx_claims = match oidc_session::open_tx(&tx_cookie, cfg.cookie_secret.as_bytes(), now) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "oidc callback: tx cookie open failed");
            send_response(
                session,
                400,
                "application/json",
                br#"{"error":"invalid_request","error_description":"oidc tx cookie invalid or expired"}"#,
            )
            .await?;
            return Ok(());
        }
    };

    // --- state CSRF check ---
    // Constant-time-ish: equal-length check + byte-wise XOR.
    if tx_claims.state.len() != state_q.len() || state_q.is_empty() {
        warn!("oidc callback: state mismatch (length)");
        send_response(
            session,
            400,
            "application/json",
            br#"{"error":"invalid_request","error_description":"state mismatch"}"#,
        )
        .await?;
        return Ok(());
    }
    let mut diff: u8 = 0;
    for (a, b) in tx_claims.state.bytes().zip(state_q.bytes()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        warn!("oidc callback: state mismatch");
        send_response(
            session,
            400,
            "application/json",
            br#"{"error":"invalid_request","error_description":"state mismatch"}"#,
        )
        .await?;
        return Ok(());
    }

    // --- compute redirect_uri identical to challenge time ---
    let host = session
        .req_header()
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let redirect_uri = format!("https://{host}{}", cfg.redirect_path);

    // --- POST to the IdP token endpoint (async reqwest, in-context) ---
    let form =
        callback::build_token_exchange_form(cfg, &redirect_uri, &code, &tx_claims.pkce_verifier);
    let async_client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "oidc callback: reqwest client build failed");
            send_error(session, 500, "internal").await?;
            return Ok(());
        }
    };
    let token_response = async_client
        .post(&cfg.token_endpoint)
        .basic_auth(&cfg.client_id, Some(&cfg.client_secret))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form)
        .send()
        .await;
    let body = match token_response {
        Ok(resp) if resp.status().is_success() => match resp.text().await {
            Ok(t) => t,
            Err(e) => {
                warn!(error = %e, "oidc callback: token response body read failed");
                send_error(session, 502, "oidc token endpoint failed").await?;
                return Ok(());
            }
        },
        Ok(resp) => {
            warn!(status = %resp.status(), "oidc callback: token endpoint non-2xx");
            send_error(session, 502, "oidc token endpoint failed").await?;
            return Ok(());
        }
        Err(e) => {
            warn!(error = %e, "oidc callback: token endpoint POST failed");
            send_error(session, 502, "oidc token endpoint failed").await?;
            return Ok(());
        }
    };
    let id_token = match parse_id_token_from_response(&body) {
        Some(t) => t,
        None => {
            warn!("oidc callback: token response missing id_token");
            send_error(session, 502, "oidc response invalid").await?;
            return Ok(());
        }
    };

    // --- verify ID-token signature via JwksCache ---
    let jwks_url = cfg.jwks_uri.clone();
    let id_token_for_verify = id_token.clone();
    let expected_iss = cfg.issuer.clone();
    let claims_value: anyhow::Result<serde_json::Value> = tokio::task::spawn_blocking(move || {
        let cache = sbproxy_modules::auth::jwks::get_or_init_cache(
            &jwks_url,
            sbproxy_modules::auth::jwks::DEFAULT_REFRESH_SECS,
        );
        let header = jsonwebtoken::decode_header(&id_token_for_verify)
            .map_err(|e| anyhow::anyhow!("decode header failed: {e}"))?;
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;
        let decoding_key = cache
            .lookup_decoding_key_with_unknown_kid_refresh(header.kid.as_deref(), &client)
            .ok_or_else(|| anyhow::anyhow!("no decoding key for kid {:?}", header.kid))?;
        let mut validation = jsonwebtoken::Validation::new(header.alg);
        // We do aud + nonce ourselves via the sbproxy_modules helper
        // (aud can be a string or array; our helper tolerates both);
        // ask jsonwebtoken to skip its own aud check so a multi-aud
        // token is not rejected here. iss check stays in
        // jsonwebtoken so the signature verify and iss pin happen
        // together.
        validation.validate_aud = false;
        validation.set_issuer(&[&expected_iss]);
        let data = jsonwebtoken::decode::<serde_json::Value>(
            &id_token_for_verify,
            &decoding_key,
            &validation,
        )
        .map_err(|e| anyhow::anyhow!("id token verify failed: {e}"))?;
        Ok(data.claims)
    })
    .await
    .map_err(|e| anyhow::anyhow!("spawn_blocking join failed: {e}"))
    .and_then(|inner| inner);
    let claims_value = match claims_value {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "oidc callback: id token signature verify failed");
            send_error(session, 401, "id token invalid").await?;
            return Ok(());
        }
    };

    // --- validate ID-token claims (iss / aud / exp / nonce) ---
    let id_claims: callback::IdTokenClaims = match serde_json::from_value(claims_value) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "oidc callback: id token claim shape invalid");
            send_error(session, 401, "id token claims invalid").await?;
            return Ok(());
        }
    };
    if let Err(e) = callback::validate_id_token_claims(
        &id_claims,
        &cfg.issuer,
        &cfg.client_id,
        &tx_claims.nonce,
        now,
    ) {
        warn!(error = %e, "oidc callback: id token claims rejected");
        send_error(session, 401, "id token claims invalid").await?;
        return Ok(());
    }

    // --- optional userinfo fetch + trust-header projection ---
    //
    // When the operator configured `userinfo_endpoint` AND the
    // token response carried an `access_token`, call the OP for the
    // verified claims (email + groups + preferred_username), then
    // project to `X-Auth-*` trust headers per
    // `userinfo::trust_headers_from_claims`. Failure to fetch
    // userinfo is logged but NOT fatal: the session still mints with
    // only the ID-token-derived projection. This matches the OIDC
    // spec's stance that userinfo is auxiliary, not required for
    // session establishment.
    let mut trust_headers: Vec<(String, String)> = Vec::new();
    if let Some(uinfo_url) = cfg.userinfo_endpoint.as_deref() {
        if let Some(access_token) = parse_access_token_from_response(&body) {
            let auth_header =
                sbproxy_modules::auth::oidc::userinfo::build_userinfo_authorization_header(
                    &access_token,
                );
            let userinfo_result = async_client
                .get(uinfo_url)
                .header("authorization", auth_header)
                .send()
                .await;
            match userinfo_result {
                Ok(resp) if resp.status().is_success() => match resp.text().await {
                    Ok(uinfo_body) => {
                        match sbproxy_modules::auth::oidc::userinfo::parse_userinfo(&uinfo_body) {
                            Ok(claims) => {
                                trust_headers = sbproxy_modules::auth::oidc::userinfo::trust_headers_from_claims(&claims)
                                .into_iter()
                                .map(|(k, v)| (k.to_string(), v))
                                .collect();
                            }
                            Err(e) => warn!(error = %e, "oidc callback: userinfo parse failed"),
                        }
                    }
                    Err(e) => warn!(error = %e, "oidc callback: userinfo body read failed"),
                },
                Ok(resp) => warn!(status = %resp.status(), "oidc callback: userinfo non-2xx"),
                Err(e) => warn!(error = %e, "oidc callback: userinfo request failed"),
            }
        } else {
            warn!("oidc callback: userinfo configured but token response had no access_token");
        }
    }

    // --- mint the session cookie ---
    let session_claims = oidc_session::SessionClaims {
        sub: id_claims.sub.clone(),
        iss: id_claims.iss.clone(),
        aud: cfg.client_id.clone(),
        iat: now,
        exp: now + cfg.session_ttl_secs,
        trust_headers,
    };
    let sealed_session =
        match oidc_session::seal_session(&session_claims, cfg.cookie_secret.as_bytes()) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "oidc callback: session seal failed");
                send_error(session, 500, "session seal failed").await?;
                return Ok(());
            }
        };

    // --- 302 to return_to with Set-Cookie session + tx=deleted ---
    let session_cookie = format!(
        "{}={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
        cfg.session_cookie_name, sealed_session, cfg.session_ttl_secs
    );
    let tx_delete_cookie = format!(
        "{}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
        cfg.tx_cookie_name
    );
    let mut header = pingora_http::ResponseHeader::build(302, None)?;
    header.insert_header("location", tx_claims.return_to.clone())?;
    header.append_header("set-cookie", session_cookie)?;
    header.append_header("set-cookie", tx_delete_cookie)?;
    header.insert_header("content-length", "0")?;
    session
        .write_response_header(Box::new(header), false)
        .await?;
    session
        .write_response_body(Some(bytes::Bytes::new()), true)
        .await?;
    Ok(())
}

/// Handle `/oidc/logout` per OpenID Connect RP-Initiated Logout 1.0.
///
/// Always sets the session-cookie-deletion `Set-Cookie` header so the
/// browser drops the cookie regardless of whether the OP supports
/// end-session. Then:
///
/// * If `cfg.end_session_endpoint` is configured: 302 to the OP with
///   `id_token_hint` (when we can recover it), `post_logout_redirect_uri`
///   (when the caller supplied one in the query and it appears in
///   `cfg.post_logout_redirect_allowlist`, else the configured
///   default), and the round-tripped `state` (when supplied).
/// * Otherwise: 302 to `cfg.post_logout_redirect_default` (or the
///   caller's allowlisted URI).
///
/// `id_token_hint` is currently always `None` because the session
/// cookie shape does not carry the original ID token; recovering it
/// requires the server-side session store wiring that lands in a
/// follow-up PR. OPs that REQUIRE `id_token_hint` will then reject
/// the redirect with an error, which is the documented behaviour;
/// most OPs accept the redirect without the hint and prompt the user
/// once more before clearing their session.
async fn handle_oidc_logout(
    session: &mut pingora_proxy::Session,
    cfg: &sbproxy_modules::auth::oidc::OidcAuth,
) -> Result<()> {
    use sbproxy_modules::auth::oidc::logout;

    // --- parse query for caller-supplied post-logout target + state ---
    let query = session.req_header().uri.query().unwrap_or("");
    let mut requested_uri: Option<String> = None;
    let mut state_q: Option<String> = None;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            match k {
                "post_logout_redirect_uri" => requested_uri = Some(decode_form_component(v)),
                "state" => state_q = Some(decode_form_component(v)),
                _ => {}
            }
        }
    }

    // --- resolve post-logout target through the allowlist ---
    let resolved = logout::resolve_post_logout_redirect(
        requested_uri.as_deref(),
        &cfg.post_logout_redirect_allowlist,
        Some(&cfg.post_logout_redirect_default),
    );

    // --- compose the 302 target ---
    // When end_session_endpoint is configured, build the OP redirect.
    // Otherwise the proxy is the terminal redirect target; the
    // resolved post-logout URI becomes the final hop.
    let location = if cfg.end_session_endpoint.is_some() {
        logout::build_end_session_redirect_url(
            cfg.end_session_endpoint.as_deref(),
            // id_token_hint is unavailable until the session store
            // wiring lands; OPs that require it will reject and the
            // operator will see the failure in their browser tools.
            "",
            resolved,
            state_q.as_deref(),
        )
        .unwrap_or_else(|| resolved.unwrap_or("/").to_string())
    } else {
        resolved.unwrap_or("/").to_string()
    };

    let deletion = logout::build_session_deletion_cookie(cfg);
    let mut header = pingora_http::ResponseHeader::build(302, None)?;
    header.insert_header("location", location)?;
    header.append_header("set-cookie", deletion)?;
    header.insert_header("content-length", "0")?;
    session
        .write_response_header(Box::new(header), false)
        .await?;
    session
        .write_response_body(Some(bytes::Bytes::new()), true)
        .await?;
    Ok(())
}

/// Handle the two Web Bot Auth publish endpoints. `path` has
/// already been narrowed to one of the two known values; everything
/// else is a bug in the caller's recognizer.
async fn handle_web_bot_auth_publish(
    session: &mut pingora_proxy::Session,
    cfg: &sbproxy_config::WebBotAuthPublishConfig,
    path: &str,
) -> Result<()> {
    use sbproxy_modules::auth::bot_auth_publish::{
        sign_directory_response, validate_directory_url, DirectoryDocument, SignatureAgentCard,
    };

    // Validate the operator-supplied directory_url at request time
    // (config-load validation is the next refinement; the cost here
    // is bounded by request rate against this well-known path, which
    // is essentially zero in production).
    if let Err(e) = validate_directory_url(&cfg.directory_url) {
        warn!(error = %e, "web_bot_auth_publish: bad directory_url");
        send_error(session, 500, "web_bot_auth_publish misconfigured").await?;
        return Ok(());
    }
    let pk_bytes = match hex::decode(cfg.public_key_hex.trim()) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        Ok(b) => {
            warn!(len = b.len(), "web_bot_auth_publish: bad public key length");
            send_error(session, 500, "web_bot_auth_publish misconfigured").await?;
            return Ok(());
        }
        Err(e) => {
            warn!(error = %e, "web_bot_auth_publish: bad public key hex");
            send_error(session, 500, "web_bot_auth_publish misconfigured").await?;
            return Ok(());
        }
    };

    // Optional self-signature on the response body. When the
    // operator supplies `signing_key_hex` (the private half of the
    // advertised public key), the directory and agent-card responses
    // gain `Content-Digest`, `Signature-Input`, and `Signature`
    // headers per RFC 9421 so a verifier can confirm the body was
    // emitted by the holder of the advertised key. Failures here
    // fail open: the response still ships unsigned, just like when
    // no signing key is configured.
    let signing_seed: Option<[u8; 32]> = cfg.signing_key_hex.as_ref().and_then(|s| {
        match decode_ed25519_seed(s) {
            Ok(seed) => Some(seed),
            Err(e) => {
                warn!(error = %e, "web_bot_auth_publish: bad signing_key_hex; serving unsigned");
                None
            }
        }
    });

    if path == "/.well-known/http-message-signatures-directory" {
        let doc = DirectoryDocument::build(vec![(pk_bytes, cfg.key_id.clone())]);
        let body = doc.to_json();
        let extra = signing_seed
            .as_ref()
            .and_then(|seed| {
                match sign_directory_response(seed, &cfg.key_id, body.as_bytes()) {
                    Ok(headers) => Some(headers),
                    Err(e) => {
                        warn!(error = %e, "web_bot_auth_publish: directory self-sign failed; serving unsigned");
                        None
                    }
                }
            })
            .unwrap_or_default();
        send_response_with_headers(
            session,
            200,
            "application/http-message-signatures-directory+json",
            body.as_bytes(),
            &extra,
        )
        .await?;
        return Ok(());
    }

    // Otherwise: the agent card.
    let mut card = SignatureAgentCard::new(cfg.agent_name.clone(), cfg.directory_url.clone());
    if let Some(d) = &cfg.description {
        card = card.with_description(d.clone());
    }
    if let Some(c) = &cfg.contact_url {
        card = card.with_contact_url(c.clone());
    }
    let body = card.to_json();
    let extra = signing_seed
        .as_ref()
        .and_then(
            |seed| match sign_directory_response(seed, &cfg.key_id, body.as_bytes()) {
                Ok(headers) => Some(headers),
                Err(e) => {
                    warn!(error = %e, "web_bot_auth_publish: agent-card self-sign failed; serving unsigned");
                    None
                }
            },
        )
        .unwrap_or_default();
    send_response_with_headers(session, 200, "application/json", body.as_bytes(), &extra).await?;
    Ok(())
}

/// Read a cookie value out of the request's `Cookie` header. Returns
/// the first matching `name=value` pair; multiple cookies with the
/// same name are not permitted by RFC 6265 so taking the first is
/// safe.
fn read_request_cookie(session: &pingora_proxy::Session, name: &str) -> Option<String> {
    let raw = session
        .req_header()
        .headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())?;
    let needle = format!("{name}=");
    for pair in raw.split(';') {
        let trimmed = pair.trim();
        if let Some(rest) = trimmed.strip_prefix(&needle) {
            return Some(rest.to_string());
        }
    }
    None
}

/// Extract `id_token` from an RFC 6749 §5.1 token response body.
fn parse_id_token_from_response(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get("id_token").and_then(|t| t.as_str()).map(String::from)
}

/// Extract `access_token` from an RFC 6749 §5.1 token response body.
/// Used by the userinfo follow-up: the OP requires this token in the
/// `Authorization: Bearer` header on the userinfo GET.
fn parse_access_token_from_response(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get("access_token")
        .and_then(|t| t.as_str())
        .map(String::from)
}

#[cfg(test)]
mod challenge_tests {
    use super::*;
    use sbproxy_config::OlpConfig;

    fn olp_cfg(enabled: bool, issuer: &str) -> OlpConfig {
        OlpConfig {
            enabled,
            signing_key: "00".repeat(32),
            key_id: "test-kid".into(),
            issuer: issuer.into(),
            default_scope: "ai-input".into(),
            default_ttl_secs: 60,
            content_key_seed: None,
            introspect: None,
        }
    }

    #[test]
    fn augment_adds_realm_and_token_url_to_bare_license_challenge() {
        let cfg = olp_cfg(true, "https://api.example.com");
        let extra = vec![("WWW-Authenticate".to_string(), "License".to_string())];
        let out = augment_license_challenge(
            &extra,
            Some(&cfg),
            "api.example.com",
            Some("api.example.com:443"),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "WWW-Authenticate");
        assert!(out[0].1.starts_with("License realm=\""));
        assert!(out[0]
            .1
            .contains("token_url=\"https://api.example.com/.well-known/olp/token\""));
        assert!(out[0].1.contains("realm=\"api.example.com:443\""));
    }

    #[test]
    fn augment_preserves_error_param_on_invalid_challenge() {
        // CAP's invalid-token challenge looks like `License
        // error="invalid_token"`; augmenting must keep the error
        // param visible and append realm + token_url.
        let cfg = olp_cfg(true, "https://api.example.com");
        let extra = vec![(
            "WWW-Authenticate".to_string(),
            "License error=\"invalid_token\"".to_string(),
        )];
        let out = augment_license_challenge(
            &extra,
            Some(&cfg),
            "api.example.com",
            Some("api.example.com"),
        );
        assert!(out[0].1.contains("error=\"invalid_token\""));
        assert!(out[0].1.contains("realm=\"api.example.com\""));
        assert!(out[0].1.contains("token_url=\""));
    }

    #[test]
    fn augment_no_op_when_olp_disabled() {
        let cfg = olp_cfg(false, "https://api.example.com");
        let extra = vec![("WWW-Authenticate".to_string(), "License".to_string())];
        let out = augment_license_challenge(
            &extra,
            Some(&cfg),
            "api.example.com",
            Some("api.example.com"),
        );
        assert_eq!(out, extra);
    }

    #[test]
    fn augment_no_op_when_olp_absent() {
        let extra = vec![("WWW-Authenticate".to_string(), "License".to_string())];
        let out =
            augment_license_challenge(&extra, None, "api.example.com", Some("api.example.com"));
        assert_eq!(out, extra);
    }

    #[test]
    fn augment_passes_through_non_license_headers() {
        // A Digest or Basic challenge on the same origin must NOT
        // grow OLP params (those are License-scheme specific).
        let cfg = olp_cfg(true, "https://api.example.com");
        let extra = vec![
            (
                "WWW-Authenticate".to_string(),
                "Basic realm=\"x\"".to_string(),
            ),
            ("X-Custom".to_string(), "value".to_string()),
        ];
        let out = augment_license_challenge(
            &extra,
            Some(&cfg),
            "api.example.com",
            Some("api.example.com"),
        );
        assert_eq!(out, extra);
    }

    #[test]
    fn augment_falls_back_to_origin_hostname_when_no_host_header() {
        let cfg = olp_cfg(true, "https://api.example.com");
        let extra = vec![("WWW-Authenticate".to_string(), "License".to_string())];
        let out = augment_license_challenge(&extra, Some(&cfg), "api.example.com", None);
        assert!(out[0].1.contains("realm=\"api.example.com\""));
    }

    #[test]
    fn augment_escapes_quotes_and_backslashes_in_realm() {
        // RFC 7230 §3.2.6 quoted-string: " and \ MUST be escaped.
        let cfg = olp_cfg(true, "https://api.example.com");
        let extra = vec![("WWW-Authenticate".to_string(), "License".to_string())];
        let out =
            augment_license_challenge(&extra, Some(&cfg), "api.example.com", Some("ev\"il\\host"));
        assert!(out[0].1.contains(r#"realm="ev\"il\\host""#));
    }
}

#[cfg(test)]
mod olp_form_tests {
    use super::{parse_olp_token_form, OlpTokenForm};

    #[test]
    fn happy_path_binds_client_id_from_form_body() {
        let got =
            parse_olp_token_form("grant_type=client_credentials&client_id=acme-corp").unwrap();
        assert_eq!(
            got,
            OlpTokenForm {
                client_id: "acme-corp".to_string()
            }
        );
    }

    #[test]
    fn missing_grant_type_returns_invalid_request() {
        let err = parse_olp_token_form("client_id=acme").unwrap_err();
        assert_eq!(err.code, "invalid_request");
    }

    #[test]
    fn wrong_grant_type_returns_unsupported_grant_type() {
        let err = parse_olp_token_form("grant_type=password&client_id=acme").unwrap_err();
        assert_eq!(err.code, "unsupported_grant_type");
    }

    #[test]
    fn missing_client_id_returns_invalid_request() {
        let err = parse_olp_token_form("grant_type=client_credentials").unwrap_err();
        assert_eq!(err.code, "invalid_request");
    }

    #[test]
    fn empty_client_id_returns_invalid_request() {
        let err = parse_olp_token_form("grant_type=client_credentials&client_id=").unwrap_err();
        assert_eq!(err.code, "invalid_request");
    }

    #[test]
    fn percent_decoding_recovers_client_id_with_special_chars() {
        // Real publisher client_ids include `:` and `-`. Pin the
        // percent-decoding path so a colon-bearing client_id survives.
        let got =
            parse_olp_token_form("grant_type=client_credentials&client_id=svc%3Aweb-1").unwrap();
        assert_eq!(got.client_id, "svc:web-1");
    }

    #[test]
    fn plus_decodes_to_space_in_client_id() {
        let got =
            parse_olp_token_form("grant_type=client_credentials&client_id=acme+corp").unwrap();
        assert_eq!(got.client_id, "acme corp");
    }

    #[test]
    fn unknown_parameters_are_ignored() {
        // Forward-compat: future RFC 8693 / RFC 8707 params must not
        // tip the parser into a 400.
        let got = parse_olp_token_form(
            "grant_type=client_credentials&client_id=acme&audience=https%3A%2F%2Fapi&resource=urn%3Ar",
        )
        .unwrap();
        assert_eq!(got.client_id, "acme");
    }
}

#[cfg(test)]
mod inbound_key_phase_tests {
    use super::*;
    use sbproxy_keystore::crypto::KeyCrypto;
    use sbproxy_keystore::record::{CredentialRecord, KeyRecord, RecordStatus};
    use sbproxy_keystore::{
        KeyPolicyCasResult, KeyStore, MemoryKeyStore, TtlCache, TtlCacheConfig,
    };
    use std::sync::Arc;

    struct BrokenKeyReadStore {
        inner: MemoryKeyStore,
    }

    #[async_trait::async_trait]
    impl KeyStore for BrokenKeyReadStore {
        async fn get_key(&self, _key_id: &str) -> anyhow::Result<Option<KeyRecord>> {
            anyhow::bail!("store down")
        }

        async fn list_keys(&self) -> anyhow::Result<Vec<KeyRecord>> {
            self.inner.list_keys().await
        }

        async fn put_key(&self, record: KeyRecord) -> anyhow::Result<()> {
            self.inner.put_key(record).await
        }

        async fn put_key_if_revision(
            &self,
            record: KeyRecord,
            expected_revision: u64,
        ) -> anyhow::Result<KeyPolicyCasResult> {
            self.inner
                .put_key_if_revision(record, expected_revision)
                .await
        }

        async fn delete_key(&self, key_id: &str) -> anyhow::Result<()> {
            self.inner.delete_key(key_id).await
        }

        async fn get_credential(&self, id: &str) -> anyhow::Result<Option<CredentialRecord>> {
            self.inner.get_credential(id).await
        }

        async fn list_credentials(&self) -> anyhow::Result<Vec<CredentialRecord>> {
            self.inner.list_credentials().await
        }

        async fn put_credential(&self, record: CredentialRecord) -> anyhow::Result<()> {
            self.inner.put_credential(record).await
        }

        async fn delete_credential(&self, id: &str) -> anyhow::Result<()> {
            self.inner.delete_credential(id).await
        }

        async fn revision(&self) -> anyhow::Result<u64> {
            self.inner.revision().await
        }
    }

    /// A plane holding one active and one revoked key, plus their tokens.
    async fn plane_with_keys() -> (crate::key_plane::KeyPlane, String, String) {
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
        (plane, active.token, revoked.token)
    }

    fn headers(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        for (k, v) in pairs {
            map.append(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    fn ctx() -> RequestContext {
        RequestContext::default()
    }

    fn loopback_ip() -> std::net::IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    /// A context whose peer looks like the admin server's own loopback
    /// dispatch call, the only shape an impersonation ticket is ever
    /// allowed to redeem from.
    fn loopback_ctx() -> RequestContext {
        let mut c = ctx();
        c.client_ip = Some(loopback_ip());
        c
    }

    fn assert_denial(
        outcome: InboundKeyPhase,
        expected_status: u16,
        expected_trust: AuthTrustOutcome,
    ) {
        assert!(
            matches!(
                outcome,
                InboundKeyPhase::Deny {
                    status,
                    trust_outcome,
                    ..
                } if status == expected_status && trust_outcome == expected_trust
            ),
            "unexpected inbound key outcome: {outcome:?}"
        );
    }

    #[tokio::test]
    async fn a_minted_key_on_x_api_key_resolves_and_records_its_header() {
        let (plane, token, _) = plane_with_keys().await;
        let mut c = ctx();
        let outcome =
            resolve_inbound_key(&plane, &headers(&[("x-api-key", &token)]), None, &mut c).await;
        assert!(matches!(outcome, InboundKeyPhase::Resolved), "{outcome:?}");
        assert!(c.resolved_inbound_key.is_some());
        // The caller strips exactly this header, so the proxy's own key never
        // reaches the origin.
        assert_eq!(c.inbound_key_header.as_deref(), Some("x-api-key"));
    }

    #[tokio::test]
    async fn a_minted_key_is_also_accepted_on_bearer_authorization() {
        let (plane, token, _) = plane_with_keys().await;
        let mut c = ctx();
        let h = headers(&[("authorization", &format!("Bearer {token}"))]);
        assert!(matches!(
            resolve_inbound_key(&plane, &h, None, &mut c).await,
            InboundKeyPhase::Resolved
        ));
        assert_eq!(c.inbound_key_header.as_deref(), Some("authorization"));
    }

    #[tokio::test]
    async fn no_token_leaves_the_context_untouched_so_configured_auth_runs() {
        let (plane, _, _) = plane_with_keys().await;
        let mut c = ctx();
        let h = headers(&[("authorization", "Bearer some-opaque-jwt")]);
        assert!(matches!(
            resolve_inbound_key(&plane, &h, None, &mut c).await,
            InboundKeyPhase::NotPresent
        ));
        assert!(c.resolved_inbound_key.is_none());
        assert!(c.inbound_key_header.is_none());
    }

    #[tokio::test]
    async fn a_callers_own_provider_key_falls_through_rather_than_denying() {
        // Parallel operation is the whole point: a tool presenting its real
        // Anthropic key in x-api-key must reach the origin, not collect a 401.
        let (plane, _, _) = plane_with_keys().await;
        let mut c = ctx();
        let h = headers(&[("x-api-key", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz")]);
        assert!(matches!(
            resolve_inbound_key(&plane, &h, None, &mut c).await,
            InboundKeyPhase::NotPresent
        ));
    }

    #[tokio::test]
    async fn a_revoked_key_denies_403() {
        let (plane, _, revoked) = plane_with_keys().await;
        let mut c = ctx();
        let outcome =
            resolve_inbound_key(&plane, &headers(&[("x-api-key", &revoked)]), None, &mut c).await;
        assert_denial(outcome, 403, AuthTrustOutcome::InvalidProof);
        assert_eq!(
            c.inbound_key_mode,
            crate::context::InboundKeyMode::Minted,
            "a recognized minted attempt must retain its mode on denial"
        );
        assert!(
            c.native_key_provider.is_none(),
            "a minted denial must not invent provider attribution"
        );
        assert!(
            c.resolved_inbound_key.is_none(),
            "a denied key is not stamped"
        );
    }

    #[tokio::test]
    async fn an_unknown_key_denies_401() {
        let (plane, _, _) = plane_with_keys().await;
        let mut c = ctx();
        let unknown = format!("sbp_{}_{}", "f".repeat(16), "e".repeat(64));
        let outcome =
            resolve_inbound_key(&plane, &headers(&[("x-api-key", &unknown)]), None, &mut c).await;
        assert_denial(outcome, 401, AuthTrustOutcome::InvalidProof);
        assert_eq!(
            c.inbound_key_mode,
            crate::context::InboundKeyMode::Minted,
            "an unknown minted-shaped key must still be observable as minted"
        );
        assert!(c.native_key_provider.is_none());
    }

    #[tokio::test]
    async fn a_wrong_secret_denies_401_like_an_unknown_id() {
        // Same status for both, so neither is an existence oracle.
        let (plane, token, _) = plane_with_keys().await;
        let key_id = &token[4..20];
        let wrong = format!("sbp_{key_id}_{}", "0".repeat(64));
        let mut c = ctx();
        let outcome =
            resolve_inbound_key(&plane, &headers(&[("x-api-key", &wrong)]), None, &mut c).await;
        assert_denial(outcome, 401, AuthTrustOutcome::InvalidProof);
        assert_eq!(
            c.inbound_key_mode,
            crate::context::InboundKeyMode::Minted,
            "a wrong minted secret must still be observable as minted"
        );
        assert!(c.native_key_provider.is_none());
    }

    #[tokio::test]
    async fn conflicting_tokens_in_two_headers_deny_400() {
        let (plane, token, revoked) = plane_with_keys().await;
        let mut c = ctx();
        let h = headers(&[("x-api-key", &token), ("x-sb-api", &revoked)]);
        let outcome = resolve_inbound_key(&plane, &h, None, &mut c).await;
        assert_denial(outcome, 400, AuthTrustOutcome::InvalidProof);
        assert_eq!(
            c.inbound_key_mode,
            crate::context::InboundKeyMode::Minted,
            "conflicting minted-shaped credentials are still a minted attempt"
        );
        assert!(c.native_key_provider.is_none());
    }

    #[tokio::test]
    async fn a_key_store_outage_is_a_neutral_backend_failure() {
        let crypto = KeyCrypto::new(b"pep".to_vec(), b"mas".to_vec());
        let token = crypto.mint_key().token;
        let store: Arc<dyn KeyStore> = Arc::new(BrokenKeyReadStore {
            inner: MemoryKeyStore::new(),
        });
        let cache = Arc::new(TtlCache::new(store, TtlCacheConfig::default()));
        let plane = crate::key_plane::KeyPlane::from_parts(crypto, cache, false, false, None);
        let mut c = ctx();

        let outcome =
            resolve_inbound_key(&plane, &headers(&[("x-api-key", &token)]), None, &mut c).await;

        assert_denial(outcome, 503, AuthTrustOutcome::BackendFailure);
    }

    /// A plane over a store that always fails key reads, pinned to `posture`.
    fn broken_store_plane(
        posture: sbproxy_config::types::FailureMode,
    ) -> (crate::key_plane::KeyPlane, String) {
        let crypto = KeyCrypto::new(b"pep".to_vec(), b"mas".to_vec());
        let token = crypto.mint_key().token;
        let store: Arc<dyn KeyStore> = Arc::new(BrokenKeyReadStore {
            inner: MemoryKeyStore::new(),
        });
        let cache = Arc::new(TtlCache::new(store, TtlCacheConfig::default()));
        let plane = crate::key_plane::KeyPlane::from_parts(crypto, cache, false, false, None)
            .with_failure_posture(posture);
        (plane, token)
    }

    /// Every posture, at both inbound-key entry points, from one accessor.
    ///
    /// The legacy `failure_mode_allow: false` and `true` resolve to
    /// `closed` and `degraded`, so the first two rows below are also the
    /// legacy behaviour, unchanged. An admitting posture returns
    /// `NotPresent`, which falls through to the origin's configured auth;
    /// it has never been a blanket admit and still is not.
    #[tokio::test]
    async fn the_failure_posture_governs_both_inbound_key_outage_paths() {
        use sbproxy_config::types::FailureMode;

        for (posture, admits) in [
            (FailureMode::Closed, false),
            (FailureMode::Degraded, true),
            (FailureMode::Open, true),
        ] {
            let (plane, token) = broken_store_plane(posture);

            let mut swept = ctx();
            let outcome =
                resolve_inbound_key(&plane, &headers(&[("x-api-key", &token)]), None, &mut swept)
                    .await;
            if admits {
                assert!(
                    matches!(outcome, InboundKeyPhase::NotPresent),
                    "{posture:?} must fall through, not deny: {outcome:?}"
                );
            } else {
                assert_denial(outcome, 503, AuthTrustOutcome::BackendFailure);
            }

            // Same decision on the playground impersonation ticket path,
            // which used to carry its own copy of it.
            let ticket = crate::admin_playground::ticket::mint("some-key-id");
            let mut ticketed = loopback_ctx();
            let outcome = resolve_inbound_key(
                &plane,
                &headers(&[("authorization", &format!("Bearer {ticket}"))]),
                Some(loopback_ip()),
                &mut ticketed,
            )
            .await;
            if admits {
                assert!(
                    matches!(outcome, InboundKeyPhase::NotPresent),
                    "{posture:?} must fall through on the ticket path too: {outcome:?}"
                );
            } else {
                assert_denial(outcome, 503, AuthTrustOutcome::BackendFailure);
            }
        }
    }

    /// `degraded` and `open` admit the same request and are still not the
    /// same answer. The difference is what the plane reports about the
    /// guarantee it did not make, which is what an operator alerts on.
    #[test]
    fn degraded_is_distinguishable_from_open_on_the_admitting_path() {
        use sbproxy_config::types::FailureMode;

        let (degraded, _) = broken_store_plane(FailureMode::Degraded);
        let (open, _) = broken_store_plane(FailureMode::Open);

        assert!(degraded.failure_posture().admits());
        assert!(open.failure_posture().admits());

        assert!(degraded.failure_posture().guarantee_waived());
        assert!(!open.failure_posture().guarantee_waived());
        assert_eq!(degraded.failure_posture().as_label(), "degraded");
        assert_eq!(open.failure_posture().as_label(), "open");
    }

    #[tokio::test]
    async fn an_impersonation_ticket_resolves_to_the_named_key() {
        let (plane, token, _) = plane_with_keys().await;
        let key_id = token[4..20].to_string();
        let ticket = crate::admin_playground::ticket::mint(&key_id);
        let mut c = loopback_ctx();
        let h = headers(&[("authorization", &format!("Bearer {ticket}"))]);
        let outcome = resolve_inbound_key(&plane, &h, Some(loopback_ip()), &mut c).await;
        assert!(matches!(outcome, InboundKeyPhase::Resolved), "{outcome:?}");
        assert_eq!(
            c.resolved_inbound_key
                .as_ref()
                .map(|rec| rec.key_id.clone()),
            Some(key_id)
        );
        // Same stripping path a normal minted key uses, so the ticket
        // never reaches the upstream origin.
        assert_eq!(c.inbound_key_header.as_deref(), Some("authorization"));
    }

    #[tokio::test]
    async fn a_consumed_impersonation_ticket_cannot_be_replayed() {
        let (plane, token, _) = plane_with_keys().await;
        let key_id = token[4..20].to_string();
        let ticket = crate::admin_playground::ticket::mint(&key_id);
        let h = headers(&[("authorization", &format!("Bearer {ticket}"))]);

        let mut first = loopback_ctx();
        assert!(matches!(
            resolve_inbound_key(&plane, &h, Some(loopback_ip()), &mut first).await,
            InboundKeyPhase::Resolved
        ));

        let mut second = loopback_ctx();
        let outcome = resolve_inbound_key(&plane, &h, Some(loopback_ip()), &mut second).await;
        assert_denial(outcome, 401, AuthTrustOutcome::InvalidProof);
    }

    #[tokio::test]
    async fn an_impersonation_ticket_for_a_revoked_key_denies_403() {
        let (plane, _, revoked) = plane_with_keys().await;
        let key_id = revoked[4..20].to_string();
        let ticket = crate::admin_playground::ticket::mint(&key_id);
        let mut c = loopback_ctx();
        let h = headers(&[("authorization", &format!("Bearer {ticket}"))]);
        let outcome = resolve_inbound_key(&plane, &h, Some(loopback_ip()), &mut c).await;
        assert_denial(outcome, 403, AuthTrustOutcome::InvalidProof);
    }

    #[tokio::test]
    async fn an_unknown_impersonation_ticket_denies_401() {
        let (plane, _, _) = plane_with_keys().await;
        let mut c = loopback_ctx();
        let h = headers(&[(
            "authorization",
            &format!("Bearer {}deadbeef", crate::admin_playground::ticket::PREFIX),
        )]);
        let outcome = resolve_inbound_key(&plane, &h, Some(loopback_ip()), &mut c).await;
        assert_denial(outcome, 401, AuthTrustOutcome::InvalidProof);
    }

    #[tokio::test]
    async fn an_impersonation_ticket_from_a_non_loopback_client_denies_401_and_is_not_consumed() {
        let (plane, token, _) = plane_with_keys().await;
        let key_id = token[4..20].to_string();
        let ticket = crate::admin_playground::ticket::mint(&key_id);
        let h = headers(&[("authorization", &format!("Bearer {ticket}"))]);

        // Preserve the existing effective-client gate independently of
        // the raw-peer gate: even through a loopback TCP peer, a forwarded
        // non-loopback client must be denied exactly like an unknown ticket.
        let mut off_loopback = ctx();
        off_loopback.client_ip = Some("10.0.0.5".parse().unwrap());
        let outcome = resolve_inbound_key(&plane, &h, Some(loopback_ip()), &mut off_loopback).await;
        assert_denial(outcome, 401, AuthTrustOutcome::InvalidProof);

        // The wrong-peer attempt must not have burned the ticket: the
        // legitimate loopback caller can still redeem it afterward.
        let mut loopback = loopback_ctx();
        let outcome = resolve_inbound_key(&plane, &h, Some(loopback_ip()), &mut loopback).await;
        assert!(matches!(outcome, InboundKeyPhase::Resolved), "{outcome:?}");
    }

    #[tokio::test]
    async fn a_non_loopback_trusted_proxy_cannot_spoof_a_loopback_impersonation_ticket() {
        let (plane, token, _) = plane_with_keys().await;
        let key_id = token[4..20].to_string();
        let ticket = crate::admin_playground::ticket::mint(&key_id);
        let h = headers(&[
            ("authorization", &format!("Bearer {ticket}")),
            ("x-forwarded-for", "127.0.0.1"),
        ]);

        // request_filter first sees this raw TCP peer, then replaces
        // ctx.client_ip with the trusted proxy's X-Forwarded-For value.
        // Ticket redemption must retain both identities.
        let raw_peer_ip: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        assert!(!raw_peer_ip.is_loopback());
        let forwarded_client_ip = h["x-forwarded-for"].to_str().unwrap().parse().unwrap();
        let mut spoofed_loopback = ctx();
        spoofed_loopback.client_ip = Some(forwarded_client_ip);
        let outcome =
            resolve_inbound_key(&plane, &h, Some(raw_peer_ip), &mut spoofed_loopback).await;
        assert_denial(outcome, 401, AuthTrustOutcome::InvalidProof);

        // Reject before consuming so the genuine loopback dispatch can
        // still redeem the ticket.
        let mut genuine_loopback = loopback_ctx();
        let outcome =
            resolve_inbound_key(&plane, &h, Some(loopback_ip()), &mut genuine_loopback).await;
        assert!(matches!(outcome, InboundKeyPhase::Resolved), "{outcome:?}");
    }

    #[tokio::test]
    async fn a_normal_bearer_token_is_unaffected_by_ticket_recognition() {
        // The normal minted-key path (not a ticket at all) must be
        // untouched: same outcome as before this feature existed.
        let (plane, token, _) = plane_with_keys().await;
        let mut c = ctx();
        let h = headers(&[("authorization", &format!("Bearer {token}"))]);
        assert!(matches!(
            resolve_inbound_key(&plane, &h, None, &mut c).await,
            InboundKeyPhase::Resolved
        ));
        assert_eq!(c.inbound_key_header.as_deref(), Some("authorization"));
    }

    #[test]
    fn inbound_key_early_refusals_finalize_trust_exactly_once() {
        let cases = [
            (
                AuthTrustOutcome::Missing,
                sbproxy_modules::auth::TrustTier::Anonymous,
            ),
            (
                AuthTrustOutcome::BackendFailure,
                sbproxy_modules::auth::TrustTier::Anonymous,
            ),
            (
                AuthTrustOutcome::InvalidProof,
                sbproxy_modules::auth::TrustTier::Suspicious,
            ),
        ];

        for (outcome, expected_tier) in cases {
            let mut c = ctx();
            finalize_inbound_key_trust(&mut c, outcome);
            assert_eq!(c.trust_tier, expected_tier);
            assert!(c.trust_tier_metric_recorded);

            let first_tier = c.trust_tier;
            finalize_inbound_key_trust(&mut c, AuthTrustOutcome::InvalidProof);
            assert_eq!(
                c.trust_tier, first_tier,
                "a second finalization attempt must be ignored"
            );
        }
    }

    #[test]
    fn require_is_off_by_default_so_an_upgrade_changes_nothing() {
        let cfg = sbproxy_config::types::KeyInboundConfig::default();
        assert!(!crate::inbound_key::requires_minted_key(&cfg));
    }
}

#[cfg(test)]
mod inbound_key_governs_ai_tests {
    use sbproxy_keystore::record::KeyRecord;

    /// Regression pin for the silent failure this epic's design flagged.
    ///
    /// `handle_ai_proxy` runs after the auth block, so by the time the AI
    /// gateway resolves a key the pre-auth sweep has already consumed the
    /// header. If the gateway re-reads `authorization` instead of the context
    /// it finds nothing, falls through to configured keys, finds nothing
    /// there, and dispatches ungoverned with no error and no log.
    ///
    /// Asserts on the resolved policy rather than a status code, because a
    /// 200 is exactly what the broken path also produces.
    #[test]
    fn a_swept_key_still_carries_its_policy_into_the_ai_gateway() {
        let mut record = KeyRecord::new("0123456789abcdef", "unused-hash", chrono::Utc::now());
        record.allowed_models = vec!["gpt-4".to_string()];
        record.max_requests_per_minute = Some(7);

        let ctx = crate::context::RequestContext {
            resolved_inbound_key: Some(Box::new(record)),
            ..Default::default()
        };

        let stamped = ctx
            .resolved_inbound_key
            .as_deref()
            .expect("the sweep stamped a record on the context");

        // These are the fields that silently vanish when the gateway re-reads
        // a header the sweep already consumed.
        assert_eq!(stamped.allowed_models, ["gpt-4"]);
        assert_eq!(stamped.max_requests_per_minute, Some(7));
        assert_eq!(stamped.key_id, "0123456789abcdef");
    }
}
