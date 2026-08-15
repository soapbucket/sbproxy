//! The Pingora `ProxyHttp` trait implementation for `SbProxy`:
//! per-request context construction and the request/upstream/response/
//! body phase handlers.
//!
//! Extracted from `server.rs`. A trait impl may live in any
//! module of the crate; `use super::*` brings `SbProxy`, the trait, and
//! every helper into scope. Behavior-preserving move, no logic changes.

use super::*;
use crate::context::{LoadBalancerActionKey, LoadBalancerAttemptToken};
use anyhow::Context as _;
use sbproxy_config::types::FailureMode;

fn active_action<'a>(pipeline: &'a CompiledPipeline, ctx: &RequestContext) -> Option<&'a Action> {
    let origin_idx = ctx.origin_idx?;
    if let Some(fwd_idx) = ctx.forward_rule_idx {
        pipeline
            .forward_rules
            .get(origin_idx)
            .and_then(|rules| rules.get(fwd_idx))
            .map(|rule| &rule.action)
    } else {
        pipeline.actions.get(origin_idx)
    }
}

fn request_modifiers_for_route(
    pipeline: &CompiledPipeline,
    origin_idx: usize,
    forward_rule_idx: Option<usize>,
) -> Vec<sbproxy_config::RequestModifierConfig> {
    let mut modifiers = pipeline
        .config
        .origins
        .get(origin_idx)
        .map(|origin| origin.request_modifiers.to_vec())
        .unwrap_or_default();
    if let Some(forward_rule_idx) = forward_rule_idx {
        if let Some(rule) = pipeline
            .forward_rules
            .get(origin_idx)
            .and_then(|rules| rules.get(forward_rule_idx))
        {
            modifiers.extend(rule.request_modifiers.iter().cloned());
        }
    }
    modifiers
}

fn downstream_half_closed(session: &Session) -> bool {
    match session.as_downstream() {
        pingora_core::protocols::http::ServerSession::H1(session) => session.is_half_closed(),
        _ => false,
    }
}

fn client_disconnected(
    error_source: Option<pingora_error::ErrorSource>,
    downstream_half_closed: bool,
) -> bool {
    // Half-close alone must not count. RFC 9112 §9.6 lets a client
    // shut down its write side and keep reading, our Pingora fork
    // tolerates that and finishes delivering the response, and at the
    // TCP layer a polite half-close and a full abandonment both arrive
    // as one FIN. Counting the FIN by itself turned every fully
    // delivered response into `client_disconnected` at the client's
    // option, which on a metering origin is a self-serve discount and
    // wrong dispute evidence. The half-close signal only means
    // "client went away" when delivery also failed to complete, so it
    // needs an error beside it; a downstream-sourced error keeps
    // counting on its own, as it always has.
    let delivery_failed = error_source.is_some();
    error_source.is_some_and(|source| source == pingora_error::ErrorSource::Downstream)
        || (downstream_half_closed && delivery_failed)
}

fn should_record_proxy_request_metrics(path: &str) -> bool {
    path != "/metrics"
}

fn record_inbound_key_request_for_path(
    path: &str,
    provider: Option<&str>,
    key_mode: &str,
    tenant_id: &str,
    api_key_id: Option<&str>,
) -> bool {
    if !should_record_proxy_request_metrics(path) {
        return false;
    }
    sbproxy_observe::metrics::record_inbound_key_request(provider, key_mode, tenant_id, api_key_id);
    true
}

/// Make the GraphQL-validated POST body authoritative at the request-body
/// boundary.
///
/// Hold every discarded inbound chunk and replace the end-of-stream chunk
/// before any downstream body policy, idempotency state, accounting, or
/// upstream emission can observe it.
fn emit_graphql_validated_request_body(
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut RequestContext,
) {
    if ctx.graphql_validated_request_body.is_none() {
        return;
    }

    if end_of_stream {
        *body = ctx.graphql_validated_request_body.take();
        // The authoritative slot supersedes the ordinary modifier slot.
        ctx.replacement_request_body = None;
    } else {
        *body = None;
    }
}

/// Hold a consumed request-body chunk back from the upstream without
/// ending the stream.
///
/// This is the one place the `Some(Bytes::new())`-vs-`None` rule lives:
/// Pingora treats `None` from `request_body_filter` as end-of-body on
/// both HTTP/1.1 and HTTP/2, so a branch that moved a mid-stream chunk
/// into a local buffer must leave an empty chunk in the slot. Leaving
/// `None` ends the upstream body at whatever bytes were already
/// forwarded and the upstream sees a silently truncated request
/// (WOR-2138; the gRPC transcode and gRPC-Web branches had the same
/// fault, fixed in WOR-2163). Every buffering branch that consumes a
/// chunk before end-of-stream goes through this function rather than
/// writing the slot directly.
///
/// Both upstream legs drop the empty chunk rather than writing it, so
/// holding costs nothing on the wire: `proxy_h1::send_body_to_upstream`
/// and `proxy_h2::send_body_to2` each return early when the slot holds
/// an empty chunk and the stream has not ended.
fn hold_request_body_chunk(body: &mut Option<Bytes>) {
    *body = Some(Bytes::new());
}

/// The transform that forbids skipping when the body outgrows the
/// buffer, if any.
///
/// A `closed` posture promises the untransformed body never reaches the
/// client, and body size is influenceable from either side of the
/// proxy, so an oversized body must fail the response rather than
/// bypass the transform. Returns the first closed transform's type
/// name for attribution; `None` means every transform that would apply
/// is `open` and the documented pass-through stands.
///
/// Filtered by content type with the same predicate apply-time uses: a
/// closed transform that would never have touched this response cannot
/// forbid delivering it, or every large download on an origin whose
/// HTML redactor is scoped to `text/html` would abort mid-stream.
fn oversized_body_refusal<'t>(
    transforms: &'t [sbproxy_modules::transform::CompiledTransform],
    content_type: Option<&str>,
) -> Option<&'t str> {
    transforms
        .iter()
        .filter(|t| t.matches_content_type(content_type))
        .find(|t| t.failure_posture == FailureMode::Closed)
        .map(|t| t.transform.transform_type())
}

/// The whole first-position guard for WOR-2411, taking the real request
/// context so every condition is testable against the type production
/// uses.
///
/// Returns the closed transform's type name when this chunk must be
/// refused before the capture blocks see it. Deliberately not gated on
/// `buffering_body`: buffering starts in the transform section, so a
/// body whose first chunk alone crosses the cap arrives before
/// buffering exists, and an earlier version gated on it missed exactly
/// the single-chunk delivery that small caps see most.
///
/// Exempt states: a pending fallback or replacement body discards the
/// upstream body entirely, so nothing oversized remains to refuse; and
/// a response the all-open pass-through already committed to raw
/// delivery must not be aborted after its raw prefix reached the
/// client.
fn closed_refusal_before_capture(ctx: &RequestContext, chunk_len: usize) -> Option<String> {
    if ctx.transform_passthrough_committed
        || ctx.fallback_body.is_some()
        || ctx.response_body_replacement.is_some()
    {
        return None;
    }
    let idx = ctx.origin_idx?;
    let pipeline = ctx.pipeline.clone();
    let transforms = pipeline.transforms.get(idx).map_or(&[][..], Vec::as_slice);
    if transforms.is_empty() {
        return None;
    }
    let buffered: usize = ctx.response_body_buf.as_ref().map_or(0, |b| b.len());
    let max_size = transforms
        .iter()
        .map(|t| t.max_body_size)
        .max()
        .unwrap_or(10 * 1024 * 1024);
    if buffered.saturating_add(chunk_len) <= max_size {
        return None;
    }
    oversized_body_refusal(transforms, ctx.upstream_content_type.as_deref()).map(str::to_owned)
}

/// Stop a buffered response whose transform failed after Pingora committed the
/// upstream headers. The status line cannot be rewritten safely at this phase,
/// so closing the stream is the only way to avoid completing a false success.
fn abort_committed_transform_response(
    body: &mut Option<Bytes>,
    ctx: &mut RequestContext,
    transform_name: &str,
) -> Result<Option<std::time::Duration>> {
    *body = None;
    ctx.response_body_buf = None;
    ctx.buffering_body = false;
    ctx.response_status = Some(500);
    ctx.response_status_override = Some(500);
    ctx.response_reason_override = None;
    ctx.transform_error_attribution = Some(transform_name.to_string());
    Err(pingora_error::Error::explain(
        ErrorType::InternalError,
        "response transform failed after response headers were committed",
    ))
}

/// Complete a deferred body-bound authentication proof against the bytes the
/// client actually sent.
///
/// GraphQL request modifiers may replace those bytes before body policies and
/// idempotency run. A signature over `content-digest` still authenticates the
/// inbound representation, so finish that proof before a late cache hit can
/// short-circuit and mark the deferred check as consumed.
fn verify_graphql_inbound_body_binding(
    headers: &http::HeaderMap,
    inbound_body: &[u8],
    ctx: &mut RequestContext,
) -> bool {
    if !ctx.bot_auth_digest_check_required {
        return true;
    }

    let verified = headers
        .get("content-digest")
        .or_else(|| headers.get("repr-digest"))
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            sbproxy_middleware::digest::verify_content_digest(value, inbound_body)
        });
    if verified {
        ctx.content_digest_verified = true;
        ctx.bot_auth_digest_check_required = false;
    }
    verified
}

/// Engage idempotency only after GraphQL validation has established the final
/// authoritative request body.
///
/// The ordinary path probes in `request_filter` so cache hits avoid policies
/// and upstream selection. Validated GraphQL requests cannot safely do that:
/// request modifiers do not produce the final method, headers, and body until
/// `upstream_request_filter`. This late path preserves the cached response
/// payload and conflict semantics while ensuring an older entry never bypasses
/// the current validation rules.
fn engage_validated_graphql_idempotency(
    request_headers: &http::HeaderMap,
    method: &http::Method,
    authoritative_body: &[u8],
    ctx: &mut RequestContext,
) -> bool {
    let pipeline = ctx.pipeline.clone();
    let Some(origin_idx) = ctx.origin_idx else {
        return false;
    };
    let Some(idem) = pipeline
        .idempotencies
        .get(origin_idx)
        .and_then(|entry| entry.as_ref())
        .cloned()
    else {
        return false;
    };
    if !idem.methods.contains(method) {
        return false;
    }
    let Some(key) = request_headers
        .get(idem.header_name.as_str())
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
    else {
        return false;
    };
    if authoritative_body.len() > idem.max_request_body_bytes {
        ctx.idempotency_skip_reason = Some("SKIPPED-OVERSIZE-REQUEST");
        return false;
    }
    let Ok(permit) = idem.permits.clone().try_acquire_owned() else {
        ctx.idempotency_skip_reason = Some("SKIPPED-POOL-FULL");
        return false;
    };
    let workspace = pipeline.config.origins[origin_idx].workspace_id.to_string();
    ctx.idempotency_workspace = Some(workspace.clone());
    ctx.idempotency_permit = Some(permit);

    let body_hash = sbproxy_middleware::idempotency::hash_body(authoritative_body);
    if let Some(cached) = idem.cache.get(&workspace, &key) {
        ctx.idempotency_permit = None;
        if cached.request_body_hash == body_hash {
            ctx.idempotency_deferred_hit = Some(cached);
        } else {
            let (status, content_type, body) = sbproxy_middleware::idempotency::conflict_response();
            ctx.validator_failed = Some((
                status.as_u16(),
                String::from_utf8_lossy(&body).into_owned(),
                content_type.to_string(),
            ));
        }
        return true;
    }

    ctx.idempotency_miss = Some((key, body_hash));
    ctx.idempotency_response_body_buf = Some(bytes::BytesMut::with_capacity(8192));
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoadBalancerAttemptOutcome {
    Success,
    Failure,
    Neutral,
}

fn load_balancer_for_action_key(
    pipeline: &CompiledPipeline,
    action_key: LoadBalancerActionKey,
) -> Option<&sbproxy_modules::LoadBalancerAction> {
    let action = if let Some(forward_rule_index) = action_key.forward_rule_index {
        pipeline
            .forward_rules
            .get(action_key.origin_index)
            .and_then(|rules| rules.get(forward_rule_index))
            .map(|rule| &rule.action)
    } else {
        pipeline.actions.get(action_key.origin_index)
    }?;
    match action {
        Action::LoadBalancer(load_balancer) => Some(load_balancer.as_ref()),
        _ => None,
    }
}

fn finish_load_balancer_attempt(ctx: &mut RequestContext, outcome: LoadBalancerAttemptOutcome) {
    let Some(attempt) = ctx.lb_attempt.take() else {
        return;
    };

    let pipeline = ctx.pipeline.clone();
    let Some(load_balancer) = load_balancer_for_action_key(&pipeline, attempt.action) else {
        warn!(
            origin_index = attempt.action.origin_index,
            forward_rule_index = ?attempt.action.forward_rule_index,
            target_index = attempt.target_index,
            "load balancer attempt owner disappeared from its pinned pipeline"
        );
        return;
    };

    let success = match outcome {
        LoadBalancerAttemptOutcome::Success => Some(true),
        LoadBalancerAttemptOutcome::Failure => Some(false),
        LoadBalancerAttemptOutcome::Neutral => None,
    };
    if let Some(success) = success {
        load_balancer.record_strategy_outcome(
            attempt.target_index,
            sbproxy_modules::RoutingOutcome {
                success,
                latency: attempt.started_at.elapsed(),
            },
        );
        if success {
            load_balancer.record_target_success(attempt.target_index);
            load_balancer.record_breaker_success(attempt.target_index);
        } else {
            load_balancer.record_target_failure(attempt.target_index);
            load_balancer.record_breaker_failure(attempt.target_index);
        }
    }
    load_balancer.record_disconnect(attempt.target_index);
}

fn begin_load_balancer_attempt(
    ctx: &mut RequestContext,
    action: LoadBalancerActionKey,
    selection: &sbproxy_modules::action::TargetSelection,
) {
    // Defensive replacement cleanup. Normal retry/error paths finish the old
    // token before Pingora asks for another peer, but this guard keeps a
    // surprise second selection from leaking or underflowing connection state.
    finish_load_balancer_attempt(ctx, LoadBalancerAttemptOutcome::Neutral);

    let pipeline = ctx.pipeline.clone();
    let Some(load_balancer) = load_balancer_for_action_key(&pipeline, action) else {
        warn!(
            origin_index = action.origin_index,
            forward_rule_index = ?action.forward_rule_index,
            target_index = selection.target_index,
            "cannot start load balancer attempt without its owning action"
        );
        return;
    };
    load_balancer.record_connect(selection.target_index);
    ctx.lb_attempt = Some(LoadBalancerAttemptToken {
        action,
        target_index: selection.target_index,
        started_at: std::time::Instant::now(),
        observed_upstream_status: None,
    });
    ctx.admin_load_balancer_strategy = Some(selection.selection_method.clone());
    ctx.admin_load_balancer_target = Some(format!("{}:{}", selection.host, selection.port));
}

fn capture_load_balancer_upstream_response(
    ctx: &mut RequestContext,
    upstream_response: &pingora_http::ResponseHeader,
) {
    if let Some(attempt) = ctx.lb_attempt.as_mut() {
        attempt.observed_upstream_status = Some(upstream_response.status.as_u16());
    }
}

fn active_load_balancer_target_index(ctx: &RequestContext) -> Option<usize> {
    ctx.lb_attempt.as_ref().map(|attempt| attempt.target_index)
}

fn terminal_load_balancer_attempt_outcome(
    status: u16,
    error_source: Option<&pingora_error::ErrorSource>,
) -> LoadBalancerAttemptOutcome {
    if status >= 500 || matches!(error_source, Some(pingora_error::ErrorSource::Upstream)) {
        LoadBalancerAttemptOutcome::Failure
    } else if error_source.is_some() {
        // Downstream, internal, and unclassified failures are not evidence
        // against the selected upstream.
        LoadBalancerAttemptOutcome::Neutral
    } else {
        LoadBalancerAttemptOutcome::Success
    }
}

fn finish_terminal_load_balancer_attempt(
    ctx: &mut RequestContext,
    error_source: Option<&pingora_error::ErrorSource>,
) {
    let observed_upstream_status = ctx
        .lb_attempt
        .as_ref()
        .and_then(|attempt| attempt.observed_upstream_status)
        .unwrap_or(0);
    let outcome = terminal_load_balancer_attempt_outcome(observed_upstream_status, error_source);
    finish_load_balancer_attempt(ctx, outcome);
}

/// Scheme-agnostic host + path of an upstream URL (WOR-1698).
struct ParsedUpstreamUrl {
    /// `Url::host_str()` of the upstream.
    host: Option<String>,
    /// Configured transport scheme.
    scheme: Option<String>,
    /// `Url::path()` of the upstream (empty string when the URL does not
    /// parse), used to derive the base-path prefix for the Proxy action.
    path: String,
}

/// Memoized parse of an upstream URL's host and path (WOR-1698).
///
/// `upstream_request_filter` re-derived the upstream host (for the
/// rewritten `Host` header, every action arm) and the Proxy base path by
/// calling `url::Url::parse` on the fixed config URL on every request.
/// The result is deterministic per URL, so cache it. The cache is keyed
/// by the raw URL string and reproduces exactly the
/// `url::Url::parse(url).host_str()` / `.path()` the call sites used, so
/// behavior is unchanged (a URL that fails to parse yields `host: None`
/// and an empty path, the same as the old `.ok()` handling).
fn parsed_upstream_url(url: &str) -> std::sync::Arc<ParsedUpstreamUrl> {
    #[allow(clippy::type_complexity)]
    static CACHE: std::sync::LazyLock<
        parking_lot::Mutex<std::collections::HashMap<String, std::sync::Arc<ParsedUpstreamUrl>>>,
    > = std::sync::LazyLock::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));
    // Upstream URLs come from config and are few; bound the memo so a
    // long-lived process that reloads many distinct configs cannot grow
    // it without limit (the WOR-1693 discipline).
    const CACHE_CAP: usize = 8192;

    let mut cache = CACHE.lock();
    if let Some(hit) = cache.get(url) {
        return hit.clone();
    }
    let parsed = url::Url::parse(url).ok();
    let info = std::sync::Arc::new(ParsedUpstreamUrl {
        host: parsed
            .as_ref()
            .and_then(|url| url.host_str().map(str::to_string)),
        scheme: parsed.as_ref().map(|u| u.scheme().to_string()),
        path: parsed
            .as_ref()
            .map(|u| u.path().to_string())
            .unwrap_or_default(),
    });
    if cache.len() >= CACHE_CAP {
        cache.clear();
    }
    cache.insert(url.to_string(), info.clone());
    info
}

fn final_response_status(
    ctx: &RequestContext,
    written: Option<&pingora_http::ResponseHeader>,
) -> u16 {
    ctx.response_status
        .or_else(|| written.map(|header| header.status.as_u16()))
        .unwrap_or(0)
}

fn is_billable_provider_success(status: u16, provider: Option<&str>) -> bool {
    (200..300).contains(&status) && provider.is_some_and(|value| !value.is_empty())
}

fn take_realized_compression_value(
    ctx: &mut RequestContext,
    status: u16,
    terminal_error: bool,
) -> Option<sbproxy_ai::PendingCompressionValue> {
    let pending = ctx.pending_compression_value.take();
    (!terminal_error && is_billable_provider_success(status, ctx.ai_provider.as_deref()))
        .then_some(pending)
        .flatten()
}

fn retry_config_for_action(action: &Action) -> Option<&sbproxy_modules::action::RetryConfig> {
    match action {
        Action::Proxy(proxy) => proxy.retry.as_ref(),
        Action::LoadBalancer(lb) => lb.retry.as_ref(),
        _ => None,
    }
}

fn is_status_retry_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "OPTIONS" | "TRACE" | "PUT" | "DELETE"
    )
}

fn status_retry_skip_reason(session: &mut Session) -> Option<&'static str> {
    let method = session.req_header().method.as_str();
    if !is_status_retry_method(method) {
        return Some("non_idempotent_method");
    }

    if session.as_mut().is_body_empty() {
        return None;
    }

    if !session.as_mut().is_body_done() {
        return Some("streaming_body");
    }

    if session.as_ref().retry_buffer_truncated() {
        return Some("body_too_large");
    }

    if session.as_ref().get_retry_buffer().is_none() {
        return Some("body_unavailable");
    }

    None
}

fn dpop_retry_skip_reason(session: &mut Session) -> Option<&'static str> {
    if session.as_mut().is_body_empty() {
        return None;
    }
    if !session.as_mut().is_body_done() {
        return Some("streaming_body");
    }
    if session.as_ref().retry_buffer_truncated() {
        return Some("body_too_large");
    }
    if session.as_ref().get_retry_buffer().is_none() {
        return Some("body_unavailable");
    }
    None
}

fn dpop_resource_htu(scheme: &str, request: &RequestHeader) -> anyhow::Result<String> {
    let scheme = match scheme {
        "http" | "ws" | "grpc" => "http",
        "https" | "wss" | "grpcs" => "https",
        _ => anyhow::bail!("outbound DPoP requires an HTTP or HTTPS upstream scheme"),
    };
    let authority = request
        .headers
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .or_else(|| request.uri.authority().map(http::uri::Authority::as_str))
        .filter(|value| !value.is_empty())
        .context("outbound DPoP request has no final authority")?;
    let path = if request.uri.path().is_empty() {
        "/"
    } else {
        request.uri.path()
    };
    let mut target = url::Url::parse(&format!("{scheme}://{authority}{path}"))
        .context("outbound DPoP request target is not a valid absolute URI")?;
    target.set_query(None);
    target.set_fragment(None);
    Ok(target.to_string())
}

fn response_dpop_nonce(response: &ResponseHeader) -> Option<String> {
    let values: Vec<_> = response.headers.get_all("dpop-nonce").iter().collect();
    if values.len() != 1 {
        return None;
    }
    let nonce = values[0].to_str().ok()?;
    sbproxy_modules::auth::dpop_outbound::validate_nonce(nonce).ok()?;
    Some(nonce.to_string())
}

/// Return whether one `WWW-Authenticate` field contains a DPoP challenge with
/// the exact `error=use_dpop_nonce` auth parameter.
///
/// Commas are ambiguous in RFC 9110 authentication fields: they delimit both
/// challenges and auth parameters. Track the current challenge while scanning
/// comma-separated segments outside quoted strings so a combined
/// `Bearer ..., DPoP ...` field is handled without letting near-name
/// parameters such as `fooerror` match.
fn dpop_authenticate_value_requests_nonce(header: &str) -> bool {
    let bytes = header.as_bytes();
    let mut segment_start = 0;
    let mut quoted = false;
    let mut escaped = false;
    let mut current_challenge_is_dpop = false;

    for segment_end in (0..=bytes.len()).filter(|&index| {
        if index == bytes.len() {
            return true;
        }
        let byte = bytes[index];
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            false
        } else if byte == b'"' {
            quoted = true;
            false
        } else {
            byte == b','
        }
    }) {
        let segment = header[segment_start..segment_end].trim();
        segment_start = segment_end.saturating_add(1);
        if segment.is_empty() {
            continue;
        }

        let segment_bytes = segment.as_bytes();
        let token_end = segment_bytes
            .iter()
            .position(|byte| !is_auth_token_byte(*byte))
            .unwrap_or(segment_bytes.len());
        if token_end == 0 {
            current_challenge_is_dpop = false;
            continue;
        }
        let mut after_token = token_end;
        while segment_bytes
            .get(after_token)
            .is_some_and(u8::is_ascii_whitespace)
        {
            after_token += 1;
        }

        if segment_bytes.get(after_token) == Some(&b'=') {
            if current_challenge_is_dpop
                && auth_challenge_has_parameter(segment, "error", "use_dpop_nonce")
            {
                return true;
            }
            continue;
        }

        current_challenge_is_dpop = segment[..token_end].eq_ignore_ascii_case("DPoP");
        if current_challenge_is_dpop
            && auth_challenge_has_parameter(&segment[token_end..], "error", "use_dpop_nonce")
        {
            return true;
        }
    }

    false
}

fn dpop_resource_nonce_challenge_present(response: &ResponseHeader) -> bool {
    if response.status != http::StatusCode::UNAUTHORIZED {
        return false;
    }
    response
        .headers
        .get_all(http::header::WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(dpop_authenticate_value_requests_nonce)
}

fn dpop_resource_nonce_challenge(response: &ResponseHeader) -> Option<String> {
    dpop_resource_nonce_challenge_present(response)
        .then(|| response_dpop_nonce(response))
        .flatten()
}

fn maybe_retry_dpop_nonce(
    session: &mut Session,
    upstream_response: &ResponseHeader,
    ctx: &mut RequestContext,
) -> Option<Box<Error>> {
    if !ctx.outbound_dpop_active {
        return None;
    }
    let challenged = dpop_resource_nonce_challenge_present(upstream_response);
    let nonce = if challenged {
        dpop_resource_nonce_challenge(upstream_response)?
    } else {
        response_dpop_nonce(upstream_response)?
    };
    let pipeline = ctx.pipeline.clone();
    let runtime = pipeline
        .outbound_creds
        .get(ctx.origin_idx?)
        .and_then(Option::as_ref)
        .and_then(|credential| credential.dpop_runtime().ok().flatten())?;
    let htu = ctx.outbound_dpop_htu.as_deref()?;

    if !challenged || ctx.dpop_nonce_retry_used || dpop_retry_skip_reason(session).is_some() {
        let _ = runtime.set_resource_nonce(htu, &nonce);
        return None;
    }

    if runtime.set_resource_nonce(htu, &nonce).is_err() {
        return None;
    }
    ctx.dpop_nonce_retry_used = true;
    finish_load_balancer_attempt(ctx, LoadBalancerAttemptOutcome::Failure);
    let mut error = Error::explain(
        ErrorType::HTTPStatus(http::StatusCode::UNAUTHORIZED.as_u16()),
        "protected resource requested a DPoP nonce",
    );
    error.set_retry(true);
    Some(error)
}

fn insert_outbound_credential_header(
    request: &mut RequestHeader,
    header_name: String,
    header_value: &str,
) -> Result<()> {
    request
        .insert_header(header_name, header_value)
        .map_err(|_| {
            pingora_error::Error::explain(
                pingora_error::ErrorType::HTTPStatus(503),
                "outbound credential header rejected",
            )
        })
}

/// A realtime credential kept only on the request stack.
///
/// Deliberately does not implement `Debug`: the value is an upstream secret
/// and must never become loggable through request context diagnostics.
struct RealtimeCredential {
    header: String,
    value: String,
}

fn realtime_provider_credential(
    provider: &sbproxy_ai::ProviderConfig,
) -> Option<RealtimeCredential> {
    provider
        .api_key
        .as_deref()
        .filter(|api_key| !api_key.trim().is_empty())?;
    let (header, value) = provider.auth_header();
    Some(RealtimeCredential { header, value })
}

fn realtime_native_provider_credential(
    provider: &sbproxy_ai::ProviderConfig,
    headers: &http::HeaderMap,
    hints: &[sbproxy_config::types::ProviderHintConfig],
    native_provider: &str,
) -> Option<RealtimeCredential> {
    if !provider.accepts_native_credential_for(native_provider) {
        return None;
    }
    let api_key =
        crate::inbound_key::resolve_native_provider_credential(headers, hints, native_provider)?;
    let mut resolved_provider = provider.clone();
    resolved_provider.api_key = Some(api_key.to_string());
    realtime_provider_credential(&resolved_provider)
}

fn realtime_native_provider_credential_for_pipeline(
    provider: &sbproxy_ai::ProviderConfig,
    headers: &http::HeaderMap,
    pipeline: &CompiledPipeline,
    native_provider: &str,
) -> Option<RealtimeCredential> {
    let inbound = pipeline.inbound_key_config()?;
    realtime_native_provider_credential(provider, headers, &inbound.provider_hints, native_provider)
}

fn realtime_inbound_carrier_names(ctx: &RequestContext) -> Vec<String> {
    let mut headers = Vec::new();
    if let Some(header) = ctx.inbound_key_header.as_ref() {
        headers.push(header.clone());
    }
    if let Some(inbound) = ctx.pipeline.inbound_key_config() {
        headers.extend(inbound.credential_carrier_names());
    }
    headers
}

fn choose_realtime_credential(
    bound: Option<RealtimeCredential>,
    provider: Option<RealtimeCredential>,
) -> anyhow::Result<RealtimeCredential> {
    bound
        .or(provider)
        .context("realtime credential unavailable")
}

fn realtime_credential_headers(
    bound: Option<&RealtimeCredential>,
    provider: Option<&RealtimeCredential>,
    origin: Option<&sbproxy_modules::auth::outbound_credential::OutboundCredentialConfig>,
) -> Vec<String> {
    use sbproxy_modules::auth::outbound_credential::OutboundCredentialConfig;

    let mut headers = Vec::with_capacity(3);
    for header in bound
        .into_iter()
        .chain(provider)
        .map(|credential| credential.header.as_str())
        .chain(origin.map(|credential| match credential {
            OutboundCredentialConfig::TokenExchange(_)
            | OutboundCredentialConfig::ClientCredentials(_) => "authorization",
            OutboundCredentialConfig::VaultSecret(config) => config.header.as_str(),
        }))
    {
        let canonical = header.trim().to_ascii_lowercase();
        if !headers.contains(&canonical) {
            headers.push(canonical);
        }
    }
    headers
}

fn scrub_realtime_credentials(
    request: &mut RequestHeader,
    inbound_key_headers: &[String],
    credential_headers: &[String],
    authoritative_header: &str,
) {
    for header in [
        "authorization",
        "proxy-authorization",
        "dpop",
        "x-api-key",
        "api-key",
        "x-goog-api-key",
        "x-sb-api",
    ] {
        request.remove_header(header);
    }
    for header in inbound_key_headers.iter().chain(credential_headers) {
        let canonical = header.trim().to_ascii_lowercase();
        request.remove_header(&canonical);
    }
    let authoritative = authoritative_header.trim().to_ascii_lowercase();
    request.remove_header(&authoritative);
}

fn apply_realtime_credential(
    request: &mut RequestHeader,
    credential: &RealtimeCredential,
    inbound_key_headers: &[String],
    credential_headers: &[String],
) -> Result<()> {
    for header in credential_headers
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(credential.header.as_str()))
    {
        if sbproxy_config::types::credential_header_is_reserved(header) {
            return Err(pingora_error::Error::explain(
                pingora_error::ErrorType::HTTPStatus(503),
                "realtime credential header is reserved",
            ));
        }
    }
    scrub_realtime_credentials(
        request,
        inbound_key_headers,
        credential_headers,
        &credential.header,
    );
    insert_outbound_credential_header(request, credential.header.clone(), &credential.value)
}

async fn commit_realtime_quota_attempt(ctx: &mut RequestContext) -> Result<()> {
    let Some(attempt) = ctx.ai_realtime_quota_attempt.take() else {
        ctx.ai_realtime_quota_config.take();
        return Ok(());
    };

    match attempt.commit().await {
        Ok(()) => {
            ctx.ai_realtime_quota_config.take();
            Ok(())
        }
        Err(error) => {
            let config = ctx.ai_realtime_quota_config.take();
            let Some(failure) =
                crate::context::RealtimeQuotaFailure::from_pool_error(config.as_ref(), &error)
            else {
                // The guard normally handles this branch itself. Retain a
                // defensive fail-open path if a future store returns backend
                // unavailability after settlement semantics evolve.
                if let Some(config) = config.as_ref() {
                    sbproxy_ai::ai_metrics::record_quota_pool_fail_open(&config.name);
                }
                return Ok(());
            };
            ctx.ai_realtime_quota_failure = Some(failure);
            Err(pingora_error::Error::explain(
                pingora_error::ErrorType::HTTPStatus(failure.status),
                failure.message,
            ))
        }
    }
}

fn realtime_response_accepts_session(status: u16) -> bool {
    status == http::StatusCode::SWITCHING_PROTOCOLS.as_u16()
}

fn take_accepted_realtime_dispatch(
    dispatch: &mut Option<crate::context::RealtimeDispatchCtx>,
    response_status: u16,
) -> Option<crate::context::RealtimeDispatchCtx> {
    let dispatch = dispatch.take();
    realtime_response_accepts_session(response_status)
        .then_some(dispatch)
        .flatten()
}

fn ensure_dpop_credential_source(
    bound_credential_id: Option<&str>,
    origin_dpop_enabled: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !(origin_dpop_enabled && bound_credential_id.is_some()),
        "bound credential cannot satisfy origin DPoP"
    );
    Ok(())
}

fn final_dpop_access_token<'a>(
    request: &'a RequestHeader,
    expected_token: &str,
) -> anyhow::Result<&'a str> {
    let mut values = request.headers.get_all(http::header::AUTHORIZATION).iter();
    let value = values
        .next()
        .context("outbound DPoP authorization header is missing")?;
    anyhow::ensure!(
        values.next().is_none(),
        "outbound DPoP authorization header is duplicated"
    );
    let value = value
        .to_str()
        .context("outbound DPoP authorization header is invalid")?;
    let token = value
        .strip_prefix("DPoP ")
        .filter(|token| !token.is_empty())
        .context("outbound DPoP authorization scheme is invalid")?;
    anyhow::ensure!(
        token == expected_token,
        "outbound DPoP authorization token was modified"
    );
    Ok(token)
}

/// Decide whether the upstream response status triggers a retry.
///
/// `Some(retryable error)` means the status matched the action's
/// `retry.retry_on`, attempts remain under `max_attempts`, and the
/// request can be replayed from Pingora's retry buffer; the caller
/// (`upstream_response_decision`) returns it so Pingora discards the
/// response before any bytes reach the downstream, drops the upstream
/// connection, and re-runs `upstream_peer`. `None` lets the response
/// flow through untouched; a skipped-but-matching status stamps
/// `ctx.status_retry_skip_reason` so `response_filter` can surface
/// `x-sbproxy-retry-skip-reason` on the passed-through response.
async fn maybe_retry_upstream_status(
    session: &mut Session,
    upstream_response: &ResponseHeader,
    ctx: &mut RequestContext,
) -> Option<Box<Error>> {
    let status = upstream_response.status.as_u16();
    let pipeline = ctx.pipeline.clone();
    let action = active_action(&pipeline, ctx)?;
    let cfg = retry_config_for_action(action)?;
    if !cfg.enabled() || !cfg.allows_status(status) {
        return None;
    }

    // Status and connect-error retries share `ctx.retry_count`, so a
    // mixed failure sequence stays under one `max_attempts` cap.
    if !cfg.attempts_remaining(ctx.retry_count) {
        ctx.status_retry_skip_reason = Some("max_attempts_exhausted");
        debug!(
            hostname = %ctx.hostname,
            upstream_status = %status,
            attempts = %cfg.max_attempts,
            "upstream status matched retry_on but max attempts were exhausted"
        );
        return None;
    }

    if let Some(reason) = status_retry_skip_reason(session) {
        ctx.status_retry_skip_reason = Some(reason);
        debug!(
            hostname = %ctx.hostname,
            upstream_status = %status,
            reason = %reason,
            "upstream status matched retry_on but request is not replayable"
        );
        return None;
    }

    let backoff_ms = cfg.backoff_for_attempt(ctx.retry_count);
    finish_load_balancer_attempt(ctx, LoadBalancerAttemptOutcome::Failure);

    ctx.status_retry_skip_reason = None;
    ctx.retry_count += 1;
    ctx.retry_backoff_ms = Some(backoff_ms);
    sbproxy_observe::metrics::record_upstream_status_retry(ctx.hostname.as_str(), status);
    debug!(
        hostname = %ctx.hostname,
        upstream_status = %status,
        attempt = %ctx.retry_count,
        max = %cfg.max_attempts,
        backoff_ms = %backoff_ms,
        "upstream status matched retry_on, retrying"
    );

    let mut error = Error::explain(
        ErrorType::HTTPStatus(status),
        "upstream status matched retry_on",
    );
    error.set_retry(true);
    Some(error)
}

/// Metric phase label for a timeout-classed Pingora error, or `None`
/// when the error type is not honestly a timeout. `connect` covers
/// deadlines hit while establishing the upstream connection (TCP
/// connect, TLS handshake); `upstream` covers read and write
/// deadlines on the established connection. This is the closed label
/// set for `sbproxy_upstream_timeout_retries_total{phase}`.
fn timeout_error_phase(etype: &ErrorType) -> Option<&'static str> {
    match etype {
        ErrorType::ConnectTimedout | ErrorType::TLSHandshakeTimedout => Some("connect"),
        ErrorType::ReadTimedout | ErrorType::WriteTimedout => Some("upstream"),
        _ => None,
    }
}

/// Decide whether an error surfaced by `error_while_proxy` schedules
/// a timeout retry.
///
/// Mirrors `maybe_retry_upstream_status` for the mid-proxy leg:
/// `Some(phase)` means the error is a timeout class on the upstream
/// side, the action's `retry.retry_on` lists `timeout`, attempts
/// remain under the shared `max_attempts` cap, no response bytes have
/// been written downstream, and the request is replayable; the caller
/// then increments `ctx.retry_count` and marks the error retryable.
/// `None` leaves the error exactly as Pingora produced it.
///
/// Both safety gates live here because Pingora's proxy loop retries
/// blindly on `e.retry()`: `response_started` guards bytes that can
/// never be recalled from the client, and `replay_skip` (from
/// `status_retry_skip_reason`) guards requests whose method or body
/// must not be replayed after they already reached the upstream.
fn maybe_retry_upstream_timeout(
    cfg: &sbproxy_modules::action::RetryConfig,
    etype: &ErrorType,
    esource: &pingora_error::ErrorSource,
    retries_used: u32,
    response_started: bool,
    replay_skip: Option<&'static str>,
) -> Option<&'static str> {
    let phase = timeout_error_phase(etype)?;
    if *esource != pingora_error::ErrorSource::Upstream {
        return None;
    }
    if !cfg.allows("timeout") || !cfg.attempts_remaining(retries_used) {
        return None;
    }
    if response_started || replay_skip.is_some() {
        return None;
    }
    Some(phase)
}

/// Combine the origin's configured upstream idle timeout with the
/// service-discovery idle cap.
///
/// The cap (half the DNS refresh window, at most 10s) is a correctness
/// bound, not a default: a pooled connection pinned to a rotated-away IP
/// must age out before the next refresh. The configured idle can therefore
/// only shrink the result, never extend past the cap, so the two combine
/// via `min()`. Either side passes through unchanged when the other is
/// absent.
fn cap_idle_for_service_discovery(
    configured: Option<std::time::Duration>,
    sd_cap: Option<std::time::Duration>,
) -> Option<std::time::Duration> {
    match (configured, sd_cap) {
        (Some(configured), Some(cap)) => Some(configured.min(cap)),
        (None, Some(cap)) => Some(cap),
        (configured, None) => configured,
    }
}

/// Dispatch the response-cache store for a completed body.
///
/// `final_body` is what a later hit will replay: the raw upstream
/// bytes on an origin without transforms, or the transform chain's
/// output on an origin with them (ingest semantics: the entry holds
/// what this miss ships, so hits and misses answer alike). Consumes
/// the capture state off the context; safe to call once per request.
fn dispatch_response_cache_store(ctx: &mut RequestContext, final_body: &[u8]) {
    let key = ctx.cache_key.take();
    let status = ctx.cache_status.take();
    let headers = ctx.cache_headers.take();
    let (Some(key), Some(status), Some(headers)) = (key, status, headers) else {
        return;
    };
    // WOR-2367: `cache.admit`. This is the earliest point where the
    // question the event answers is answerable: whether a response is
    // worth storing depends on its status, size, and content, and the
    // body is only complete here. On a transformed origin the length
    // it sees is the transformed one, because that is what would be
    // stored.
    //
    // Declining leaves `ttl_secs` and the static `cacheable_status`
    // gate in charge, which is what a deployment without the event
    // already does.
    let static_ttl = {
        let pipeline_guard = ctx.pipeline.clone();
        ctx.origin_idx
            .and_then(|idx| pipeline_guard.config.origins.get(idx))
            .and_then(|o| o.response_cache.as_ref())
            .map(|c| c.ttl_secs)
            .unwrap_or(300)
    };
    let admit = evaluate_cache_admit(ctx, status, &headers, final_body.len());
    let ttl = admit.ttl_secs.unwrap_or(static_ttl);
    let pipeline_for_write = ctx.pipeline.clone();
    // The write-back must seal under the same origin the lookup opened
    // under, so resolve the per-origin handle rather than the shared
    // one.
    let write_origin_id = ctx
        .origin_idx
        .and_then(|idx| pipeline_for_write.config.origins.get(idx))
        .map(|o| o.origin_id.to_string())
        .unwrap_or_default();
    // WOR-2407: stamp the config this entry belongs to. Redundant
    // against the key on an exact-keyed backend, load bearing on
    // memcached, which matches a digest of the key rather than the
    // key.
    let write_config_fp = ctx
        .origin_idx
        .and_then(|idx| pipeline_for_write.config.origins.get(idx))
        .map(|o| o.cache_config_fingerprint.to_string())
        .unwrap_or_default();
    // `admit.store` gates the write and nothing else. Returning early
    // here would skip work the caller still owes, so the event refuses
    // to *store* without refusing to serve.
    if let Some(cache_store) = pipeline_for_write
        .cache_store_for(&write_origin_id)
        .cloned()
        .filter(|_| admit.store)
    {
        let entry = sbproxy_cache::CachedResponse {
            generation: sbproxy_cache::new_cache_generation(),
            status,
            headers,
            body: final_body.to_vec(),
            cached_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            ttl_secs: ttl,
            config_fp: write_config_fp,
        };
        // --- Cache Reserve admission ---
        // Mirror into the cold tier subject to the configured admission
        // filter. The reserve write fires before the hot-cache write
        // moves `entry` so we don't have to round-trip through serde to
        // clone it.
        if let (Some(reserve), Some(admission)) = (
            pipeline_for_write.cache_reserve.clone(),
            pipeline_for_write.cache_reserve_admission,
        ) {
            let origin_id_for_reserve = write_origin_id.clone();
            maybe_admit_to_reserve(
                reserve,
                admission,
                key.clone(),
                &entry,
                origin_id_for_reserve,
            );
        }
        // Dispatch the actual write in a blocking task so the Redis TCP
        // I/O doesn't run on the reactor thread.
        tokio::task::spawn_blocking(move || {
            if let Err(e) = cache_store.put(&key, &entry) {
                tracing::warn!(error = %e, "cache write failed");
            }
        });
    }
}

/// Whether this pipeline publishes audit records for `event`.
///
/// One reader for the compiled block so no emitting site re-derives the
/// precedence: an absent block publishes nothing, and the per-event
/// versus master-switch order lives on the config type itself
/// (WOR-2405).
///
/// `route` is the origin's **config key**, the same value the origin
/// id carries, not the request `Host`. Under a wildcard origin those
/// differ, and passing the `Host` would silently skip the origin-scope
/// block the operator wrote.
pub(super) fn audit_publishes(
    pipeline: &crate::pipeline::CompiledPipeline,
    event: sbproxy_observe::decision::DecisionEvent,
    tenant: Option<&str>,
    route: Option<&str>,
) -> bool {
    let scopes = &pipeline.config.decision_audit;
    if scopes.is_empty() {
        return false;
    }
    scopes.publishes(event.as_label(), tenant, route)
}

/// Run the origin's `cache.admit` event, or return the static default.
///
/// The returned plan is always usable: a declined event, an absent one,
/// and a faulted one all yield `store: true` with no TTL override, which
/// is exactly what a deployment without the event does. The three are
/// distinguished on the metric rather than in the return value, because
/// the caller's behavior is identical and only the operator's
/// interpretation differs.
fn evaluate_cache_admit(
    ctx: &crate::context::RequestContext,
    status: u16,
    headers: &[(String, String)],
    body_len: usize,
) -> sbproxy_cache::cache_event::CacheAdmitPlan {
    use sbproxy_cache::cache_event::{CacheAdmitPlan, CacheDecision};
    use sbproxy_observe::decision::{
        record_decision, record_decision_fail_open, DecisionEvent, DecisionOutcome,
    };

    let default = CacheAdmitPlan::default();

    let pipeline = ctx.pipeline.clone();
    let Some(script) = ctx
        .origin_idx
        .and_then(|idx| pipeline.config.origins.get(idx))
        .and_then(|origin| origin.response_cache.as_ref())
        .and_then(|cache| cache.admit_event.as_ref())
    else {
        return default;
    };

    let origin = ctx
        .origin_idx
        .and_then(|idx| pipeline.config.origins.get(idx))
        .map_or("", |origin| origin.origin_id.as_str());
    let engine = crate::decision_script::engine_label(script);
    let started = std::time::Instant::now();

    // The event's input context. Everything it needs is assembled
    // before it runs, so the event does no I/O and every engine stays
    // eligible.
    let context = serde_json::json!({
        "response": {
            "status": status,
            "body_bytes": body_len,
            "headers": headers
                .iter()
                .map(|(name, value)| (name.clone(), serde_json::Value::String(value.clone())))
                .collect::<serde_json::Map<_, _>>(),
        },
        "request": {
            "path": ctx.request_path.as_str(),
            "host": ctx.hostname.as_str(),
        },
        "tenant": ctx.tenant_id.as_str(),
        "origin": origin,
    });

    let plan = match crate::decision_script::evaluate(script, &context) {
        Err(fault) => {
            // The engine faulted. The request proceeded and the response
            // is still stored, so this is a fail-open rather than an
            // error outcome: the decision was never made.
            // This event genuinely fails open: the response is stored
            // even though the decision was never made. So the outcome
            // records what happened, `Allow`, and the separate counter
            // records that it was not earned. Folding the fault into
            // `outcome="error"` as well would page an operator on the
            // error rate for traffic that behaved as configured, which
            // the sibling policy site rejected for the same reason.
            //
            // `fault` still selects the log detail, so a budget overrun
            // is distinguishable from a broken script.
            tracing::debug!(
                target: "sbproxy::decision",
                event = "cache.admit",
                ?fault,
                "cache.admit failed open"
            );
            record_decision_fail_open(DecisionEvent::CacheAdmit, engine, origin, &ctx.tenant_id);
            record_decision(
                DecisionEvent::CacheAdmit,
                engine,
                DecisionOutcome::Allow,
                origin,
                &ctx.tenant_id,
            );
            default
        }
        Ok(document) => match sbproxy_cache::cache_event::decode_cache_admit(&document) {
            Ok(CacheDecision::Decline) => {
                record_decision(
                    DecisionEvent::CacheAdmit,
                    engine,
                    DecisionOutcome::Decline,
                    origin,
                    &ctx.tenant_id,
                );
                default
            }
            Ok(CacheDecision::Plan(plan)) => {
                let outcome = if plan.store {
                    DecisionOutcome::Allow
                } else {
                    DecisionOutcome::Deny
                };
                record_decision(
                    DecisionEvent::CacheAdmit,
                    engine,
                    outcome,
                    origin,
                    &ctx.tenant_id,
                );
                // WOR-2405: the reason the script gave is the payload. A
                // record saying a response was not cached is nearly
                // useless; one naming the rule and why is an
                // investigation. Publishing is opt-in per event, so this
                // costs a config read on a path that already did an
                // engine evaluation.
                if audit_publishes(
                    &pipeline,
                    DecisionEvent::CacheAdmit,
                    (!ctx.tenant_id.is_empty()).then(|| ctx.tenant_id.as_str()),
                    (!origin.is_empty()).then_some(origin),
                ) {
                    crate::policy_bus::emit_decision_audit(
                        DecisionEvent::CacheAdmit,
                        engine,
                        outcome,
                        &ctx.request_id,
                        origin,
                        &ctx.hostname,
                        &ctx.tenant_id,
                        &plan.reason,
                    );
                }
                plan
            }
            Err(error) => {
                // A malformed document is the script's bug, not the
                // engine's. Same fallback, different signal, because the
                // fixes are different: one is a broken runtime and the
                // other is a broken rule.
                tracing::warn!(
                    target: "sbproxy::decision",
                    event = "cache.admit",
                    error = %error,
                    "cache.admit returned a document that could not be decoded"
                );
                record_decision_fail_open(
                    DecisionEvent::CacheAdmit,
                    engine,
                    origin,
                    &ctx.tenant_id,
                );
                record_decision(
                    DecisionEvent::CacheAdmit,
                    engine,
                    DecisionOutcome::Allow,
                    origin,
                    &ctx.tenant_id,
                );
                default
            }
        },
    };
    sbproxy_observe::decision::record_decision_duration(
        DecisionEvent::CacheAdmit,
        engine,
        origin,
        started.elapsed().as_secs_f64(),
    );
    plan
}

#[async_trait]
impl ProxyHttp for SbProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext::new()
    }

    /// Handle incoming request before proxying.
    ///
    /// This phase:
    /// 1. Extracts hostname and resolves the origin
    /// 2. Handles the unrouted-host /health compatibility probe
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
        // WOR-2318: the root span of a proxied request. Wrapping the whole
        // filter rather than opening the span inside it is what makes it a
        // parent: `Instrument` re-enters the span around every poll, so the
        // auth span, every policy span, and the AI request span all nest
        // under it without a single one of them being handed a parent
        // explicitly.
        //
        // `method.as_str()` is borrowed straight from the request header,
        // so the field costs no allocation, and `tracing` does not even
        // evaluate it unless the callsite is enabled.
        //
        // The span cannot be parented on the caller's trace here: the
        // inbound `traceparent` has not been parsed yet at this point, and
        // parsing it twice to get an earlier answer would allocate per
        // request for a value the filter is about to compute anyway.
        // `request_phase::request_filter` calls
        // `parent_span_on_remote_trace_context` against `Span::current()`
        // the moment it has the context, which is this span.
        let span =
            sbproxy_observe::telemetry::intake_accept_span(session.req_header().method.as_str());
        tracing::Instrument::instrument(request_phase::request_filter(session, ctx), span).await
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
        // `upstream_peer` starts a new attempt. Every ordinary retry path
        // already finishes the prior token, while this neutral guard handles
        // Pingora replacement paths that bypass those callbacks.
        finish_load_balancer_attempt(ctx, LoadBalancerAttemptOutcome::Neutral);

        if let Some(backoff_ms) = ctx.retry_backoff_ms.take() {
            if backoff_ms > 0 {
                debug!(
                    attempt = %ctx.retry_count,
                    backoff_ms = %backoff_ms,
                    "sleeping before upstream retry"
                );
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
            }
        }

        let pipeline = ctx.pipeline.clone();
        let origin_idx = ctx.origin_idx.ok_or_else(|| {
            warn!("upstream_peer called without origin_idx");
            Error::new(ErrorType::HTTPStatus(500))
        })?;
        let load_balancer_action_key = LoadBalancerActionKey::new(origin_idx, ctx.forward_rule_idx);

        // tune_peer applies the origin's upstream transport settings to every
        // peer we return. Pingora 0.8 ships with very conservative defaults
        // (HTTP/1.1 only, max_h2_streams=1, no idle_timeout, no tcp_keepalive,
        // no connect/read/write deadlines). See sbproxy-bench/docs/TUNING.md
        // for the rationale. The deadlines come from the compiled origin's
        // resolved `timeouts` block (config `origins.*.timeouts`); the
        // defaults match the Go engine's http.Transport settings so benchmark
        // comparisons measure the engine, not the defaults. `config.origins`
        // is indexed by `origin_idx` exactly like `pipeline.actions`, so a
        // forward-rule inline origin inherits its parent origin's timeouts.
        let upstream_timeouts = pipeline.config.origins[origin_idx].timeouts;
        let tune_peer = |mut peer: HttpPeer| -> HttpPeer {
            use std::time::Duration;
            peer.options.connection_timeout = Some(upstream_timeouts.connect);
            peer.options.total_connection_timeout = Some(upstream_timeouts.total_connect);
            peer.options.read_timeout = Some(upstream_timeouts.read);
            peer.options.write_timeout = Some(upstream_timeouts.write);
            peer.options.idle_timeout = Some(upstream_timeouts.idle);
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
        };

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
                    guard_upstream(&host, port, tls, allow_private).await?;
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
                            // quickly instead of lingering for the full
                            // configured idle timeout (90s by default).
                            // This is a workaround for the missing
                            // pool-eviction primitive in Pingora 0.8; it
                            // trades a small amount of pool churn for much
                            // fresher routing. Combined with the origin's
                            // configured idle via min() at the peer below.
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
                // The service-discovery cap (half the DNS refresh window) is
                // a correctness bound: a pooled connection must not outlive
                // an IP rotation. The configured idle can therefore only
                // shrink the result further; take the min of the two rather
                // than letting either win outright.
                peer.options.idle_timeout =
                    cap_idle_for_service_discovery(peer.options.idle_timeout, sd_idle_timeout);
                Ok(Box::new(peer))
            }
            Action::LoadBalancer(lb) => {
                let request_header = _session.req_header();
                let path = request_header.uri.path_and_query().map_or_else(
                    || request_header.uri.path().to_string(),
                    |value| value.to_string(),
                );
                let mut routing_request = sbproxy_modules::RoutingRequest::new(
                    request_header.method.as_str(),
                    path,
                    ctx.hostname.as_str(),
                );
                routing_request.headers = request_header.headers.clone();
                routing_request.client_ip = ctx.client_ip.map(|ip| ip.to_string());
                let selection = lb.select_target_for_request(routing_request).map_err(|e| {
                    warn!(error = %e, "load balancer target selection failed");
                    Error::because(ErrorType::ConnectError, "lb target selection failed", e)
                })?;

                guard_upstream(
                    &selection.host,
                    selection.port,
                    selection.tls,
                    allow_private,
                )
                .await?;

                begin_load_balancer_attempt(ctx, load_balancer_action_key, &selection);

                debug!(
                    hostname = %ctx.hostname,
                    upstream_host = %selection.host,
                    upstream_port = %selection.port,
                    tls = %selection.tls,
                    target_idx = %selection.target_index,
                    selection_method = %selection.selection_method,
                    "load balancer routing request to upstream"
                );

                let addr = format!("{}:{}", selection.host, selection.port);
                let peer = tune_peer(HttpPeer::new(&*addr, selection.tls, selection.host));
                Ok(Box::new(peer))
            }
            Action::A2a(a2a) => {
                let (host, port, tls) = a2a.parse_upstream().map_err(|e| {
                    warn!(error = %e, "failed to parse A2A upstream URL");
                    Error::because(ErrorType::ConnectError, "bad A2A upstream URL", e)
                })?;

                guard_upstream(&host, port, tls, allow_private).await?;

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

                guard_upstream(&host, port, tls, allow_private).await?;

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
                )
                .await?;
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

                guard_upstream(&host, port, tls, allow_private).await?;

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

                guard_upstream(&host, port, tls, allow_private).await?;

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
        let is_realtime = ctx.ai_realtime_dispatch.is_some();
        let realtime_inbound_key_headers = if is_realtime {
            realtime_inbound_carrier_names(ctx)
        } else {
            Vec::new()
        };

        // Collect header modifications into owned Vecs, then drop the pipeline
        // guard before calling Pingora's insert_header (requires 'static borrows).
        let mut req_to_set: Vec<(String, String)> = Vec::new();
        let mut req_to_remove: Vec<String> = Vec::new();
        let mut req_to_append: Vec<(String, String)> = Vec::new();
        let mut lua_scripts: Vec<String> = Vec::new();
        let mut js_scripts: Vec<String> = Vec::new();
        let mut advanced_modifiers: Vec<sbproxy_config::RequestModifierConfig> = Vec::new();
        let mut upstream_url_path: Option<String> = None;
        let mut upstream_host_header: Option<String> = None;
        let mut upstream_scheme: Option<String> = None;
        let mut disable_forwarded_host: bool = false;
        let mut forwarding = ForwardingHeaderControls::default();
        // WOR-802: outbound credential resolver config for this origin,
        // cloned out of the pipeline so it can be used (and awaited on)
        // after the pipeline guard is dropped below.
        let mut outbound_cred: Option<
            sbproxy_modules::auth::outbound_credential::OutboundCredentialConfig,
        > = None;
        let mut dpop_resource: Option<(
            std::sync::Arc<sbproxy_modules::auth::dpop_outbound::DpopRuntime>,
            String,
        )> = None;
        let mut realtime_provider_auth: Option<RealtimeCredential> = None;
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
            let pipeline = ctx.pipeline.clone();
            if let Some(idx) = ctx.origin_idx {
                let origin = &pipeline.config.origins[idx];
                outbound_cred = pipeline.outbound_creds.get(idx).and_then(|o| o.clone());
                // WOR-805: capture the shared outbound signer when this
                // origin opts into Web Bot Auth signing.
                if pipeline.outbound_wba.get(idx).copied().unwrap_or(false) {
                    wba_signer = pipeline.web_bot_auth_signer.clone();
                    wba_signature_agent = pipeline.web_bot_auth_signature_agent.clone();
                }

                // WOR-1132: forward the resolved agent-class verdict to the
                // upstream when an `agent_class` policy on this origin has
                // `forward_to_upstream: true`. The resolver already ran in
                // `request_filter` and stamped `ctx.agent_id` / `agent_vendor`
                // / `agent_id_source`; the policy's `enforce` is a no-op
                // marker, so the actual header stamping happens here where the
                // outgoing request is in hand. Without a captured verdict
                // (resolver disabled, or no signal) nothing is stamped.
                #[cfg(feature = "agent-class")]
                if let Some(policies) = pipeline.policies.get(idx) {
                    for policy in policies {
                        let sbproxy_modules::Policy::AgentClass(ac) = policy else {
                            continue;
                        };
                        if !ac.forward_to_upstream() {
                            continue;
                        }
                        if let Some(agent_id) = ctx.agent_id.as_ref() {
                            req_to_set.push((
                                ac.header_name().to_string(),
                                agent_id.as_str().to_string(),
                            ));
                        }
                        let vendor_header = ac.vendor_header_name();
                        if !vendor_header.is_empty() {
                            if let Some(vendor) = ctx.agent_vendor.as_ref() {
                                req_to_set.push((vendor_header.to_string(), vendor.clone()));
                            }
                        }
                        let verified_header = ac.verified_header_name();
                        if !verified_header.is_empty() {
                            // A verdict is "verified" only when it came from a
                            // cryptographic or forward-confirmed signal (Web
                            // Bot Auth keyid or forward-confirmed reverse DNS),
                            // not from a spoofable user-agent match.
                            let verified = matches!(
                                ctx.agent_id_source,
                                Some(
                                    sbproxy_classifiers::AgentIdSource::BotAuth
                                        | sbproxy_classifiers::AgentIdSource::Rdns
                                )
                            );
                            req_to_set.push((
                                verified_header.to_string(),
                                if verified { "true" } else { "false" }.to_string(),
                            ));
                        }
                        // One agent_class policy per origin is the contract;
                        // stop after the first that forwards.
                        break;
                    }
                }

                // Extract the URL path from the proxy action so we can prepend it
                // to the upstream request path. This ensures that configs like
                // `url: http://backend:8080/api` proxy to /api/... not just /...
                let effective_action: &Action = if let Some(fwd_idx) = ctx.forward_rule_idx {
                    &pipeline.forward_rules[idx][fwd_idx].action
                } else {
                    &pipeline.actions[idx]
                };
                if let (Some(dispatch), Action::AiProxy(ai)) =
                    (ctx.ai_realtime_dispatch.as_ref(), effective_action)
                {
                    realtime_provider_auth = ai
                        .config
                        .providers
                        .iter()
                        .find(|provider| provider.name.as_str() == dispatch.provider_name)
                        .and_then(|provider| {
                            if ctx.inbound_key_mode != crate::context::InboundKeyMode::Native {
                                return realtime_provider_credential(provider);
                            }
                            let native_provider = ctx.native_key_provider.as_deref()?;
                            realtime_native_provider_credential_for_pipeline(
                                provider,
                                &session.req_header().headers,
                                &pipeline,
                                native_provider,
                            )
                        });
                }

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
                let selected_upstream_url = match effective_action {
                    Action::Proxy(action) => Some(action.url.as_str()),
                    Action::LoadBalancer(action) => active_load_balancer_target_index(ctx)
                        .and_then(|index| action.targets.get(index))
                        .map(|target| target.url.as_str()),
                    Action::WebSocket(action) => Some(action.url.as_str()),
                    Action::Grpc(action) => Some(action.url.as_str()),
                    Action::A2a(action) => Some(action.url.as_str()),
                    Action::GraphQL(action) => Some(action.url.as_str()),
                    _ => None,
                };
                upstream_scheme =
                    selected_upstream_url.and_then(|url| parsed_upstream_url(url).scheme.clone());
                let mut fc = ForwardingHeaderControls::default();
                upstream_host_header = match effective_action {
                    Action::Proxy(p) => {
                        fc = p.forwarding;
                        p.host_override
                            .clone()
                            .or_else(|| parsed_upstream_url(&p.url).host.clone())
                    }
                    Action::LoadBalancer(lb) => active_load_balancer_target_index(ctx)
                        .and_then(|i| lb.targets.get(i))
                        .and_then(|t| {
                            fc = t.forwarding;
                            t.host_override
                                .clone()
                                .or_else(|| parsed_upstream_url(&t.url).host.clone())
                        }),
                    Action::WebSocket(ws) => {
                        fc = ws.forwarding;
                        ws.host_override
                            .clone()
                            .or_else(|| parsed_upstream_url(&ws.url).host.clone())
                    }
                    Action::Grpc(g) => {
                        fc = g.forwarding;
                        g.authority
                            .clone()
                            .or_else(|| parsed_upstream_url(&g.url).host.clone())
                    }
                    Action::A2a(a) => {
                        fc = a.forwarding;
                        a.host_override
                            .clone()
                            .or_else(|| parsed_upstream_url(&a.url).host.clone())
                    }
                    Action::GraphQL(gq) => {
                        fc = gq.forwarding;
                        gq.host_override
                            .clone()
                            .or_else(|| parsed_upstream_url(&gq.url).host.clone())
                    }
                    _ => None,
                };
                forwarding = fc;
                disable_forwarded_host = forwarding.disable_forwarded_host_header;

                if let Action::Proxy(proxy) = effective_action {
                    // WOR-1698: read the memoized path instead of
                    // re-parsing the fixed upstream URL. A URL that does
                    // not parse yields an empty path, so the guard below
                    // skips it, matching the old `if let Ok(..)` behavior.
                    let p = &parsed_upstream_url(&proxy.url).path;
                    if p != "/" && !p.is_empty() {
                        upstream_url_path = Some(p.clone());
                    }
                }

                advanced_modifiers =
                    request_modifiers_for_route(&pipeline, idx, ctx.forward_rule_idx);

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
                        if let Some(script) = &modifier.js_script {
                            js_scripts.push(script.clone());
                        }
                    }
                }

                // Collect forward-rule request modifiers (OUTSIDE the origin modifier block
                // because forward rules have their own modifiers even if the origin has none)
                if let Some(fwd_idx) = ctx.forward_rule_idx {
                    if let Some(fwd_rules) = pipeline.forward_rules.get(idx) {
                        if let Some(fwd_rule) = fwd_rules.get(fwd_idx) {
                            let tmpl = build_request_template_context(session, ctx, origin);
                            for modifier in &fwd_rule.request_modifiers {
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
                                // This loop read `headers` and nothing else, so a
                                // script on a forward rule was collected by the
                                // compiler and never run, for both engines. They
                                // join the same vectors the origin-level scripts
                                // use and execute at the one call site below.
                                if let Some(script) = &modifier.lua_script {
                                    lua_scripts.push(script.clone());
                                }
                                if let Some(script) = &modifier.js_script {
                                    js_scripts.push(script.clone());
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
        apply_forwarding_headers(
            &forwarding,
            session,
            upstream_request,
            ctx.client_ip,
            client_host.as_deref(),
        );

        // Propagate the correlation ID to the upstream under the
        // configured header name. The same value is echoed on the
        // downstream response in `response_filter`.
        {
            let pipeline = ctx.pipeline.clone();
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
        // The header a minted virtual key arrived in is consumed here. The
        // proxy's own key is not an upstream credential, and forwarding it
        // would hand a governed secret to every origin the proxy talks to.
        // Same reasoning as the X-Client-Cert-* strip below.
        if let Some(header) = ctx.inbound_key_header.as_deref() {
            upstream_request.remove_header(header);
        }

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
            } else {
                // WOR-1159: TLS connection but the peer presented no client
                // certificate (e.g. optional mTLS with `require: false`).
                // Emit an explicit `x-client-cert-verified: 0` so the
                // upstream receives an unambiguous "no verified client cert"
                // signal, rather than the header simply being absent (which
                // an upstream cannot distinguish from a proxy that never
                // sets it). The inbound copies were already stripped above.
                let _ = upstream_request.insert_header("x-client-cert-verified".to_string(), "0");
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
        // resolver failure for a legacy non-DPoP credential fails open:
        // the request goes upstream without the minted credential (the
        // upstream rejects it). DPoP failures and rejected credential
        // headers fail closed because continuing could forward the caller's
        // identity without the configured sender constraint.
        // A credential bound to the resolved minted key wins, and SUPPRESSES
        // the origin-level resolver rather than running it and overwriting the
        // result. Two concrete reasons: the origin's `token_exchange` mode
        // makes a network round-trip per request, and it reads the inbound
        // bearer as the RFC 8693 subject token, which the inbound-key phase
        // may have just stripped. Running it here would burn a call and
        // exchange against a subject that is no longer present.
        let bound_credential_id = ctx
            .resolved_inbound_key
            .as_deref()
            .and_then(|record| record.credential_id.clone());
        let origin_dpop_enabled = !is_realtime
            && outbound_cred
                .as_ref()
                .is_some_and(|credential| credential.is_dpop_enabled());
        if origin_dpop_enabled {
            // Never forward a caller-supplied proof as the proxy's proof.
            upstream_request.remove_header("dpop");
        }
        if let Err(error) =
            ensure_dpop_credential_source(bound_credential_id.as_deref(), origin_dpop_enabled)
        {
            warn!(
                origin = %ctx.hostname,
                error = %error,
                "bound credential conflicts with origin DPoP; refusing the request"
            );
            return Err(pingora_error::Error::explain(
                pingora_error::ErrorType::HTTPStatus(503),
                "bound credential cannot satisfy origin DPoP",
            ));
        }

        let mut realtime_bound_auth: Option<RealtimeCredential> = None;
        if let Some(credential_id) = bound_credential_id {
            let Some(plane) = ctx.pipeline.key_plane().cloned() else {
                warn!(
                    credential_id = %credential_id,
                    "a key binds a credential but no key plane is installed"
                );
                return Err(pingora_error::Error::explain(
                    pingora_error::ErrorType::HTTPStatus(503),
                    "credential resolution unavailable",
                ));
            };
            let tenant = ctx
                .resolved_inbound_key
                .as_deref()
                .and_then(|record| record.tenant_id.clone());
            match plane
                .resolve_credential_secret(&credential_id, tenant.as_deref())
                .await
            {
                Ok(resolved) => {
                    if is_realtime {
                        realtime_bound_auth = Some(RealtimeCredential {
                            header: resolved.header,
                            value: resolved.value,
                        });
                    } else {
                        insert_outbound_credential_header(
                            upstream_request,
                            resolved.header,
                            &resolved.value,
                        )?;
                    }
                }
                Err(e) => {
                    // Fail CLOSED, unlike the origin-level resolver below.
                    // That one fails open because a failed mint there just
                    // means the upstream rejects the request. Here a
                    // wrong-credential path is available, and taking it would
                    // hand this key an upstream identity it was never bound
                    // to.
                    warn!(
                        origin = %ctx.hostname,
                        credential_id = %credential_id,
                        error = %e,
                        "bound credential could not be resolved; refusing the request"
                    );
                    return Err(pingora_error::Error::explain(
                        pingora_error::ErrorType::HTTPStatus(503),
                        "bound credential unavailable",
                    ));
                }
            }
        } else if let Some(cred_cfg) = outbound_cred.as_ref().filter(|_| {
            !is_realtime && ctx.inbound_key_mode != crate::context::InboundKeyMode::Native
        }) {
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
            // `upstream_request_filter` runs after the intake span has
            // closed, so the token exchange has no ambient span to read
            // and the request's context is handed over explicitly.
            let cred_trace_ctx = ctx.trace_ctx.clone();
            match sbproxy_modules::auth::outbound_credential::resolve_cached(
                &ctx.hostname,
                cred_cfg,
                forward_auth_client(),
                inbound_bearer.as_deref(),
                &lookup,
                cred_trace_ctx.as_ref(),
            )
            .await
            {
                Ok(minted) => {
                    let dpop_access_token = minted.dpop_access_token().map(str::to_string);
                    insert_outbound_credential_header(
                        upstream_request,
                        minted.header_name,
                        &minted.header_value,
                    )?;
                    if cred_cfg.is_dpop_enabled() {
                        let access_token = dpop_access_token.ok_or_else(|| {
                            pingora_error::Error::explain(
                                pingora_error::ErrorType::HTTPStatus(503),
                                "DPoP credential did not contain a DPoP access token",
                            )
                        })?;
                        let runtime = cred_cfg
                            .dpop_runtime()
                            .map_err(|_| {
                                pingora_error::Error::explain(
                                    pingora_error::ErrorType::HTTPStatus(503),
                                    "DPoP signer unavailable",
                                )
                            })?
                            .ok_or_else(|| {
                                pingora_error::Error::explain(
                                    pingora_error::ErrorType::HTTPStatus(503),
                                    "DPoP signer unavailable",
                                )
                            })?;
                        dpop_resource = Some((runtime, access_token));
                    }
                }
                Err(e) => {
                    if cred_cfg.is_dpop_enabled() {
                        warn!(
                            origin = %ctx.hostname,
                            error = %e,
                            "outbound DPoP credential resolution failed; refusing the request"
                        );
                        return Err(pingora_error::Error::explain(
                            pingora_error::ErrorType::HTTPStatus(503),
                            "outbound DPoP credential unavailable",
                        ));
                    }
                    warn!(
                        origin = %ctx.hostname,
                        error = %e,
                        "outbound credential resolution failed; sending upstream request without it (fail-open)"
                    );
                }
            }
        }
        let realtime_credential_headers = realtime_credential_headers(
            realtime_bound_auth.as_ref(),
            realtime_provider_auth.as_ref(),
            outbound_cred.as_ref(),
        );
        let realtime_auth = if is_realtime {
            Some(
                choose_realtime_credential(realtime_bound_auth, realtime_provider_auth).map_err(
                    |_| {
                        warn!(
                            origin = %ctx.hostname,
                            "AI realtime credential unavailable; refusing the request"
                        );
                        pingora_error::Error::explain(
                            pingora_error::ErrorType::HTTPStatus(503),
                            "realtime credential unavailable",
                        )
                    },
                )?,
            )
        } else {
            None
        };

        // Apply Lua script request modifiers
        for script in &lua_scripts {
            match lua_request_modifier(script, session.req_header(), ctx) {
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

        // Apply JavaScript request modifiers, after Lua so that a config
        // setting both on one modifier resolves the same way the response
        // side already does: the JavaScript result wins on a shared header.
        for script in &js_scripts {
            match js_request_modifier(script, session.req_header(), ctx) {
                Ok(headers_to_set) => {
                    for (key, value) in headers_to_set {
                        let _ = upstream_request.insert_header(key, &value);
                    }
                }
                Err(e) => {
                    warn!(error = %e, "JavaScript request modifier script error");
                }
            }
        }

        if let Some(model_override) = ctx
            .ai_realtime_dispatch
            .as_ref()
            .and_then(|dispatch| dispatch.model_override.as_deref())
        {
            let rewritten = replace_realtime_model_query(&upstream_request.uri, model_override)
                .map_err(|error| {
                    pingora_error::Error::because(
                        pingora_error::ErrorType::InternalError,
                        "failed to apply realtime model override",
                        error,
                    )
                })?;
            upstream_request.set_uri(rewritten);
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

        // Validate GraphQL only after every request modifier has produced the
        // outbound method, URI, headers, and replacement body. This closes the
        // gap where a benign client document could pass validation and then
        // be rewritten into a forbidden request before proxying.
        if ctx.graphql_validation_pending {
            ctx.graphql_validated_request_body = None;
            let pipeline = ctx.pipeline.clone();
            let (validation_result, validated_request_body) = if let Some(origin_idx) =
                ctx.origin_idx
            {
                let forwarded_action = ctx.forward_rule_idx.and_then(|forward_idx| {
                    pipeline
                        .forward_rules
                        .get(origin_idx)
                        .and_then(|rules| rules.get(forward_idx))
                        .map(|rule| &rule.action)
                });
                let effective_action =
                    forwarded_action.or_else(|| pipeline.actions.get(origin_idx));
                match effective_action {
                    Some(Action::GraphQL(graphql)) => match upstream_request.method {
                        http::Method::GET => {
                            let has_replacement_body = ctx
                                .replacement_request_body
                                .as_ref()
                                .is_some_and(|body| !body.is_empty());
                            let has_inbound_body = ctx
                                .graphql_request_body
                                .as_ref()
                                .is_some_and(|body| !body.is_empty());
                            if has_replacement_body || has_inbound_body {
                                (
                                    Err("validated GraphQL GET requests must not contain a body"
                                        .to_string()),
                                    None,
                                )
                            } else {
                                (
                                    graphql.validate_get_query(upstream_request.uri.query()),
                                    None,
                                )
                            }
                        }
                        http::Method::POST => {
                            let content_type = upstream_request
                                .headers
                                .get(http::header::CONTENT_TYPE)
                                .and_then(|value| value.to_str().ok());
                            let body = ctx
                                .replacement_request_body
                                .clone()
                                .or_else(|| ctx.graphql_request_body.clone())
                                .unwrap_or_default();
                            (graphql.validate_post_body(content_type, &body), Some(body))
                        }
                        _ => (
                            Err("validated GraphQL actions accept GET or POST only".to_string()),
                            None,
                        ),
                    },
                    _ => (
                        Err("validated GraphQL action is no longer available".to_string()),
                        None,
                    ),
                }
            } else {
                (
                    Err("validated GraphQL action has no resolved origin".to_string()),
                    None,
                )
            };

            if let Err(detail) = validation_result {
                debug!(detail = %detail, "GraphQL request validation failed");
                let body = serde_json::json!({
                    "error": "GraphQL request validation failed",
                    "detail": detail,
                })
                .to_string();
                ctx.validator_failed = Some((400, body, "application/json".to_string()));
                return Err(pingora_error::Error::explain(
                    pingora_error::ErrorType::HTTPStatus(400),
                    "GraphQL request validation failed",
                ));
            }
            ctx.graphql_validated_request_body = validated_request_body;

            // A body-bound inbound signature authenticates the bytes the
            // client sent, before a request modifier replaces them. Complete
            // that proof before an idempotency hit can short-circuit.
            let inbound_body = ctx.graphql_request_body.clone().unwrap_or_default();
            if !verify_graphql_inbound_body_binding(
                &session.req_header().headers,
                &inbound_body,
                ctx,
            ) {
                let body = serde_json::json!({
                    "error": "bot_auth: content-digest body mismatch",
                })
                .to_string();
                ctx.validator_failed = Some((401, body, "application/json".to_string()));
                return Err(pingora_error::Error::explain(
                    pingora_error::ErrorType::HTTPStatus(401),
                    "bot_auth: content-digest body binding failed",
                ));
            }

            let authoritative_body = ctx
                .graphql_validated_request_body
                .clone()
                .unwrap_or_default();
            if engage_validated_graphql_idempotency(
                &session.req_header().headers,
                &upstream_request.method,
                &authoritative_body,
                ctx,
            ) {
                return Err(pingora_error::Error::explain(
                    pingora_error::ErrorType::InternalError,
                    "validated GraphQL idempotency response",
                ));
            }
        }

        // Mint at the final outbound request seam. Every URI/method/header
        // rewrite and GraphQL validation has completed, and retries re-enter
        // this hook, so each attempt receives a fresh proof.
        ctx.outbound_dpop_active = false;
        ctx.outbound_dpop_htu = None;
        if let Some((runtime, access_token)) = dpop_resource {
            let final_access_token = final_dpop_access_token(upstream_request, &access_token)
                .map_err(|_| {
                    pingora_error::Error::explain(
                        pingora_error::ErrorType::HTTPStatus(503),
                        "outbound DPoP authorization header was modified",
                    )
                })?;
            let scheme = upstream_scheme.as_deref().ok_or_else(|| {
                pingora_error::Error::explain(
                    pingora_error::ErrorType::HTTPStatus(503),
                    "outbound DPoP upstream scheme unavailable",
                )
            })?;
            let htu = dpop_resource_htu(scheme, upstream_request).map_err(|_| {
                pingora_error::Error::explain(
                    pingora_error::ErrorType::HTTPStatus(503),
                    "outbound DPoP target unavailable",
                )
            })?;
            let proof = runtime
                .mint_resource_proof(upstream_request.method.as_str(), &htu, final_access_token)
                .map_err(|_| {
                    pingora_error::Error::explain(
                        pingora_error::ErrorType::HTTPStatus(503),
                        "outbound DPoP proof minting failed",
                    )
                })?;
            upstream_request
                .insert_header("dpop", &proof)
                .map_err(|_| {
                    pingora_error::Error::explain(
                        pingora_error::ErrorType::HTTPStatus(503),
                        "outbound DPoP proof header rejected",
                    )
                })?;
            ctx.outbound_dpop_active = true;
            ctx.outbound_dpop_htu = Some(htu);
        }

        // Credential authority is the final outbound-header seam. Caller,
        // configured modifier, Lua, tracing, and signature headers have all
        // been applied; scrub every known carrier before installing exactly
        // one selected provider credential.
        if let Some(credential) = realtime_auth.as_ref() {
            apply_realtime_credential(
                upstream_request,
                credential,
                &realtime_inbound_key_headers,
                &realtime_credential_headers,
            )?;
        }

        if is_realtime {
            commit_realtime_quota_attempt(ctx).await?;
        }

        // Body-transforming Proxy-Wasm filters own the outbound message
        // framing. Apply that only to Pingora's upstream copy so an HTTP/1.0
        // downstream request keeps its original protocol semantics.
        crate::proxy_wasm_http::filter_upstream_request_headers(upstream_request, ctx)?;

        Ok(())
    }

    /// Decide whether to discard the upstream response and retry.
    ///
    /// Runs once per upstream response, right after
    /// `upstream_response_filter` and before any bytes reach the
    /// downstream client. Status-code retries are decided here:
    /// returning an error with `set_retry(true)` makes Pingora drop
    /// the upstream connection and re-run `upstream_peer`, exactly
    /// like a connect-time retry. Request-body replay is gated by
    /// Pingora's retry buffer; a matching status the proxy cannot
    /// safely replay passes through with `x-sbproxy-retry-skip-reason`.
    async fn upstream_response_decision(
        &self,
        session: &mut Session,
        upstream_response: &ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Option<Box<Error>>
    where
        Self::CTX: Send + Sync,
    {
        capture_load_balancer_upstream_response(ctx, upstream_response);
        let dpop_nonce_challenge =
            ctx.outbound_dpop_active && dpop_resource_nonce_challenge_present(upstream_response);
        if let Some(error) = maybe_retry_dpop_nonce(session, upstream_response, ctx) {
            return Some(error);
        }
        if dpop_nonce_challenge {
            // The RFC 9449 retry has its own exact one-attempt budget.
            // Never let a generic status retry multiply it.
            return None;
        }
        maybe_retry_upstream_status(session, upstream_response, ctx).await
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

        // WOR-2145: snapshot the response headers the attestation config
        // meters, before this hook starts rewriting headers of its own.
        // The evidence on a receipt has to be what the origin actually
        // sent: a value read after the proxy edited it would be the
        // proxy quoting itself and calling it the upstream's claim.
        // A no-op unless this origin writes receipts and declares
        // origin-header rules.
        crate::meter_runtime::capture_origin_headers(ctx, upstream_response);

        crate::proxy_wasm_http::filter_response_headers(session, upstream_response, ctx)?;

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
        // closes that gap without changing the header behavior.
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
                let code_u32 = if status >= 0 { status as u32 } else { 2 };
                sbproxy_observe::metrics::record_grpc_status(
                    sbproxy_observe::metrics::grpc_status_label(code_u32),
                );
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
                let code_u32 = if status >= 0 { status as u32 } else { 2 };
                sbproxy_observe::metrics::record_grpc_status(
                    sbproxy_observe::metrics::grpc_status_label(code_u32),
                );
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
            let pipeline = ctx.pipeline.clone();
            let _ = upstream_response.insert_header(
                "x-sbproxy-debug-config-rev",
                pipeline.config_revision.as_str(),
            );
        }

        // --- WOR-2295: e2e harness identity marker ---
        //
        // Only set when `SBPROXY_E2E_HARNESS_TOKEN` is present in this
        // process's environment, which happens only under the e2e test
        // harness, never in production (see `e2e_harness_token` in
        // `server.rs`, reached here via `use super::*;`). Echoing the
        // harness's own token back lets its readiness probe confirm a
        // response came from the child it spawned, not a different,
        // concurrently-starting test's proxy that won a same-port race
        // during the harness's port-reservation window. This covers the
        // normal upstream-relay response; the short-circuit responses
        // `send_response` writes (e.g. the unmatched-Host 404 the probe
        // itself typically hits before any origin is configured to
        // match `127.0.0.1:<port>`) carry the same header from there.
        if let Some(token) = e2e_harness_token() {
            let _ = upstream_response.insert_header("x-sbproxy-e2e-harness-token", token);
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
                let pipeline = ctx.pipeline.clone();
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

        if let Some(reason) = ctx.status_retry_skip_reason {
            let _ = upstream_response.insert_header("x-sbproxy-retry-skip-reason", reason);
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
                let pipeline = ctx.pipeline.clone();
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
            let pipeline = ctx.pipeline.clone();
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
            // WOR-1697: only build the template context and JSON header
            // map when the origin actually configures response modifiers;
            // the common no-modifier origin skips both allocations.
            if !origin.response_modifiers.is_empty() {
                // Build template context for response modifier interpolation.
                let tmpl = build_request_template_context(session, ctx, origin);
                let mut response_headers =
                    response_headers_from_header_map(&upstream_response.headers);
                for modifier in &origin.response_modifiers {
                    if let Some(hm) = &modifier.headers {
                        for key in &hm.remove {
                            to_remove.push(key.clone());
                            response_headers.remove(key);
                        }
                        for (key, value) in &hm.set {
                            let resolved = tmpl.resolve(value);
                            insert_json_header(&mut response_headers, key, &resolved);
                            to_set.push((key.clone(), resolved));
                        }
                        for (key, value) in &hm.add {
                            let resolved = tmpl.resolve(value);
                            insert_json_header(&mut response_headers, key, &resolved);
                            to_append.push((key.clone(), resolved));
                        }
                    }
                    // Status code override. The reason phrase travels with
                    // its code: a later `status` block without a `text`
                    // clears any earlier custom phrase rather than pairing
                    // it with a code it was never written for.
                    if let Some(status_override) = &modifier.status {
                        ctx.response_status_override = Some(status_override.code);
                        ctx.response_reason_override = status_override.text.clone();
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
                        match lua_response_modifier(script, status, &response_headers, ctx) {
                            Ok(headers) => {
                                for (key, value) in headers {
                                    insert_json_header(&mut response_headers, &key, &value);
                                    to_set.push((key, value));
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "Lua response modifier script error");
                            }
                        }
                    }
                    if let Some(script) = &modifier.js_script {
                        let status = upstream_response.status.as_u16();
                        match js_response_modifier(script, status, &response_headers, ctx) {
                            Ok(headers) => {
                                for (key, value) in headers {
                                    insert_json_header(&mut response_headers, &key, &value);
                                    to_set.push((key, value));
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "JavaScript response modifier script error");
                            }
                        }
                    }
                }
            } // WOR-1697: end response_modifiers guard
        } // pipeline guard dropped here

        // 5. Forward rule request modifier headers echoed on response
        // (Go proxy includes forward rule set headers in the response too)
        {
            let pipeline = ctx.pipeline.clone();
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

        // 8. P0 session ID echo.
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
            let pipeline = ctx.pipeline.clone();
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
                            let request_view = cel_response_request_view(ctx);
                            let mutations = t.evaluate_headers_lossy_with_request(
                                b"",
                                upstream_response.status.as_u16(),
                                &upstream_response.headers,
                                request_view,
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
            apply_response_status_override(
                upstream_response,
                status_code,
                ctx.response_reason_override.as_deref(),
            );
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
            let pipeline_a = ctx.pipeline.clone();
            if let Some(idx) = ctx.origin_idx {
                if let Some(policies) = pipeline_a.policies.get(idx) {
                    // WOR-1697: the per-origin policy vec almost always
                    // exists but is usually empty of assertions; skip the
                    // two HeaderMap clones and the string snapshots unless
                    // at least one assertion is configured.
                    if policies.iter().any(|p| matches!(p, Policy::Assertion(_))) {
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
                                let passed = a.evaluate_with_trust_tier(
                                    &method,
                                    &path,
                                    &req_headers,
                                    query.as_deref(),
                                    client_ip.as_deref(),
                                    &hostname,
                                    resp_status,
                                    &resp_headers,
                                    None,
                                    Some(ctx.trust_tier.as_str()),
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
                    } // WOR-1697: end has-assertions guard
                }
            }
        }

        // 8. Session cookie: set sbproxy_sid if session_config is present and cookie is absent.
        {
            let pipeline3 = ctx.pipeline.clone();
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
                let pipeline4 = ctx.pipeline.clone();
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
                // Already advanced to the upstream hop's child by
                // `upstream_request_filter`, which is the right parent:
                // an on_response callback happens after that hop, not
                // beside the inbound one.
                let trace_ctx = ctx.trace_ctx.clone();
                let injected = fire_on_response_callbacks(
                    &callbacks,
                    status,
                    &hostname,
                    &path,
                    &request_id,
                    &config_revision,
                    duration_ms,
                    trace_ctx.as_ref(),
                )
                .await;
                for (key, value) in injected {
                    let _ = upstream_response.insert_header(key, &value);
                }
            }
        }

        // Capture response status for metrics in the logging phase. A
        // realtime dispatch becomes an active session only once the provider
        // accepts the WebSocket handshake.
        let response_status = upstream_response.status.as_u16();
        if ctx.ai_realtime_dispatch.is_some() && realtime_response_accepts_session(response_status)
        {
            sbproxy_ai::ai_metrics::inc_realtime_sessions_active();
        }
        ctx.response_status = Some(response_status);

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
            let pipeline_c = ctx.pipeline.clone();
            let cfg = &pipeline_c.config.server.correlation_id;
            if cfg.enabled && cfg.echo_response && !ctx.request_id.is_empty() {
                let _ =
                    upstream_response.insert_header(cfg.header.clone(), ctx.request_id.as_str());
            }
        }

        // 10. Prepare for body transforms: remove Content-Length so Pingora
        //    sends chunked encoding once we buffer and modify the body.
        let pipeline2 = ctx.pipeline.clone();
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
                if !comp_cfg.enabled {
                    sbproxy_observe::metrics::record_compression_decision("identity", "disabled");
                } else if !ct_ok || upstream_already_encoded {
                    // Already-compressed upstream or excluded media
                    // type. Treat as a skip; the codec label is
                    // identity because no codec was selected.
                    sbproxy_observe::metrics::record_compression_decision(
                        "identity",
                        "skipped_accept",
                    );
                } else if !size_ok {
                    sbproxy_observe::metrics::record_compression_decision(
                        "identity",
                        "skipped_size",
                    );
                }
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
                        ctx.compression_level = comp_cfg.level;
                        ctx.compression_buf = Some(bytes::BytesMut::with_capacity(8192));
                        let _ =
                            upstream_response.insert_header("content-encoding", encoding.as_str());
                        upstream_response.remove_header("content-length");
                        let _ = upstream_response.insert_header("transfer-encoding", "chunked");
                        let _ = upstream_response.append_header("vary", "Accept-Encoding");
                    } else if comp_cfg.enabled {
                        // Client did not advertise any supported codec.
                        sbproxy_observe::metrics::record_compression_decision(
                            "identity",
                            "skipped_accept",
                        );
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

        // --- WOR-2145: refuse rather than serve work we cannot bill ---
        //
        // This is the last point at which the meter can refuse anything.
        // The receipt itself is cut in `logging`, which runs after the
        // response has been written and cannot recall a single byte, so
        // `failure_mode: closed` has to make its decision here, on the
        // strength of whether the chain is writable at all.
        //
        // Rewriting the status is not enough on its own. The body is
        // suppressed in `response_body_filter` through `meter_refused`,
        // because a 503 delivered with the upstream's body attached
        // hands the buyer exactly the value the seller has just declared
        // itself unable to record.
        //
        // Only `closed` reaches this branch. `degraded`, `open`, and
        // `observe` all admit, and each leaves its own kind of trace
        // when the receipt is cut.
        //
        // WOR-2169 adds a second reason to be here, on the same terms.
        // A usage reporter under `failure_posture: closed` whose durable
        // queue has already refused a write shuts itself, and the next
        // response is refused rather than served unbilled. The two are
        // deliberately one branch: from the client's side there is no
        // difference between "we cannot record what you consumed" and
        // "we cannot bill you for what you consumed", and an operator
        // who asked for `closed` asked for the same answer to both.
        #[cfg(feature = "payments")]
        let billing_refuses = crate::usage_bridge::preflight_refuses(ctx);
        #[cfg(not(feature = "payments"))]
        let billing_refuses = false;
        if crate::meter_runtime::preflight_refuses(ctx) || billing_refuses {
            ctx.meter_refused = true;
            ctx.response_status = Some(503);
            upstream_response
                .set_status(http::StatusCode::SERVICE_UNAVAILABLE)
                .ok();
            // A suppressed body is an empty body, and it has to say so.
            // Leaving the upstream's framing in place would advertise
            // bytes that are never sent and hang the client waiting for
            // them.
            upstream_response.remove_header("content-encoding");
            upstream_response.remove_header("transfer-encoding");
            let _ = upstream_response.insert_header("content-length", "0");
            tracing::warn!(
                tenant_id = %ctx.tenant_id,
                host = %ctx.hostname,
                "attestation: refusing under failure_mode closed; the receipt chain is not writable"
            );
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
        crate::proxy_wasm_http::filter_request_body(body, end_of_stream, ctx)?;

        // For validated GraphQL POSTs, replace the inbound replay stream
        // before every downstream consumer. This is deliberately first:
        // request limits, body policies, idempotency, and byte accounting must
        // all agree with the exact bytes that can reach upstream.
        emit_graphql_validated_request_body(body, end_of_stream, ctx);

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

        // --- Origin-level JSON threat protection ---
        //
        // request_filter marks threat-protected requests but must not read
        // their bodies: doing so drains the downstream stream before Pingora
        // can send it upstream. Hold JSON candidates here, enforce a bounded
        // buffer while chunks arrive, scan the complete representation at
        // end-of-stream, then release the exact bytes on success. A clearly
        // non-JSON body is released as soon as its first non-whitespace byte
        // is available.
        if ctx.threat_scan_pending {
            const THREAT_SCAN_HARD_CAP: usize = 8 * 1024 * 1024;

            let pipeline = ctx.pipeline.clone();
            let threat = ctx
                .origin_idx
                .and_then(|idx| pipeline.threat_protections.get(idx))
                .and_then(Option::as_ref)
                .filter(|threat| threat.enabled);

            if let Some(threat) = threat {
                let declared_json = session
                    .req_header()
                    .headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value.contains("application/json"));
                let size_cap = threat
                    .json
                    .as_ref()
                    .and_then(|json| json.max_total_size)
                    .unwrap_or(THREAT_SCAN_HARD_CAP);
                let buf = ctx
                    .request_body_buf
                    .get_or_insert_with(bytes::BytesMut::new);
                let incoming_len = body.as_ref().map_or(0, Bytes::len);
                let first_non_whitespace = buf
                    .iter()
                    .chain(body.as_ref().into_iter().flat_map(|chunk| chunk.iter()))
                    .find(|byte| !byte.is_ascii_whitespace())
                    .copied();
                let looks_json = matches!(first_non_whitespace, Some(b'{' | b'['));
                let json_candidate = declared_json || looks_json || first_non_whitespace.is_none();

                if json_candidate && buf.len().saturating_add(incoming_len) > size_cap {
                    debug!("threat protection blocked request: body exceeds size cap");
                    ctx.validator_failed = Some((
                        413,
                        error_json_body("request entity too large"),
                        "application/json".to_string(),
                    ));
                    *body = None;
                    return Err(pingora_error::Error::explain(
                        pingora_error::ErrorType::HTTPStatus(413),
                        "threat protection body exceeded size cap",
                    ));
                }

                if let Some(chunk) = body.take() {
                    buf.extend_from_slice(&chunk);
                }

                if !json_candidate {
                    let collected = ctx.request_body_buf.take().unwrap_or_default();
                    ctx.threat_scan_pending = false;
                    if !collected.is_empty() {
                        *body = Some(collected.freeze());
                    }
                } else if end_of_stream {
                    let collected = ctx.request_body_buf.take().unwrap_or_default();
                    ctx.threat_scan_pending = false;
                    if !collected.is_empty() {
                        if let Err(detail) = threat.check_json_body(&collected) {
                            debug!(detail = %detail, "threat protection blocked request");
                            ctx.validator_failed = Some((
                                413,
                                error_json_body("request entity too large"),
                                "application/json".to_string(),
                            ));
                            return Err(pingora_error::Error::explain(
                                pingora_error::ErrorType::HTTPStatus(413),
                                "threat protection rejected request body",
                            ));
                        }
                        *body = Some(collected.freeze());
                    }
                } else {
                    // Hold JSON candidates until the complete body can be
                    // scanned; `hold_request_body_chunk` documents why the
                    // slot must not be left `None`. Other body consumers
                    // receive the released representation after this branch
                    // completes.
                    hold_request_body_chunk(body);
                    return Ok(());
                }
            } else {
                // A hot reload may remove threat protection after the
                // request phase. Do not strand the request body in that case.
                ctx.threat_scan_pending = false;
                if let Some(mut buffered) = ctx.request_body_buf.take() {
                    if let Some(chunk) = body.take() {
                        buffered.extend_from_slice(&chunk);
                    }
                    if !buffered.is_empty() {
                        *body = Some(buffered.freeze());
                    } else if !end_of_stream {
                        // Nothing accumulated to release, but the take
                        // above emptied the slot and `None` would end
                        // the upstream body here (WOR-2163). At
                        // end-of-stream `None` is the right answer and
                        // this arm is skipped.
                        hold_request_body_chunk(body);
                    }
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
        //
        // WOR-2163: this is a buffer-then-release branch like the two
        // above, so a mid-stream chunk consumed into the accumulator has
        // to leave an empty chunk behind (see `hold_request_body_chunk`).
        // A REST body large enough to arrive in several chunks otherwise
        // ended the upstream request body on the first one, and the
        // gRPC upstream received a request with no message frame at all.
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
                    let pipeline = ctx.pipeline.clone();
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
            } else {
                // The chunk above went into the accumulator; the slot
                // must carry an empty chunk rather than `None` so the
                // upstream body stays open for the framed message this
                // branch emits at end-of-stream.
                hold_request_body_chunk(body);
            }
            return Ok(());
        }

        // --- WOR-819: gRPC-Web -> native gRPC request de-framing ---
        //
        // Buffer the gRPC-Web request body and, at end_of_stream, decode
        // it into native gRPC message frames (base64-decoding the `-text`
        // variant). The upstream `:path`/method/content-type were already
        // set to the native gRPC shape in `upstream_request_filter`.
        //
        // WOR-2163: same buffer-then-release rule as the transcode branch
        // above. A gRPC-Web frame big enough to span several inbound
        // chunks must not leave the slot `None` mid-stream, or the native
        // gRPC upstream sees the request body end before the de-framed
        // message is written.
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
            } else {
                // The chunk above went into the accumulator; the slot
                // must carry an empty chunk rather than `None` so the
                // upstream body stays open for the de-framed message
                // this branch emits at end-of-stream.
                hold_request_body_chunk(body);
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
        // locally and emit an empty chunk to Pingora (see
        // `hold_request_body_chunk`), so the upstream does not see a
        // partial body until validation passes. On end-of-stream we
        // run all matching `RequestValidator` policies; on success we
        // release the buffered bytes as a single chunk to the
        // upstream. On failure we record a status + body for the
        // response phase, signal the validator failure via
        // `validator_failed`, and emit `None` so the upstream is not
        // contacted.
        'request_validation: {
            if !ctx.validate_request_body {
                break 'request_validation;
            }
            // Mirror of THREAT_SCAN_HARD_CAP above: the validator
            // accumulator is the other buffer-then-release dance in
            // this filter and gets the same bound, so a client that
            // streams an oversize or unterminated body cannot grow
            // proxy memory with it (WOR-2137). Overflow takes the same
            // exit as the threat-scan cap: reject with 413 before the
            // chunk is buffered, never run the validators, never
            // contact the upstream.
            const VALIDATE_BODY_HARD_CAP: usize = 8 * 1024 * 1024;

            let incoming_len = body.as_ref().map_or(0, Bytes::len);
            let buffered_len = ctx
                .request_body_buf
                .as_ref()
                .map_or(0, |buffer| buffer.len());
            let proposed_len = buffered_len.saturating_add(incoming_len);
            let skipped = match ctx
                .dynamic_request_body_plan
                .before_growth(proposed_len, None)
            {
                Ok(skipped) => skipped,
                Err(overflow) => {
                    let hook = overflow.metadata();
                    debug!(
                        bundle = hook.bundle_id(),
                        hook = hook.hook_type(),
                        policy_index = ?overflow.policy_index(),
                        received = proposed_len,
                        cap = overflow.cap(),
                        "buffered dynamic policy blocked request body before allocation"
                    );
                    ctx.validator_failed = Some((
                        413,
                        error_json_body("request entity too large"),
                        "application/json".to_string(),
                    ));
                    *body = None;
                    return Err(pingora_error::Error::explain(
                        pingora_error::ErrorType::HTTPStatus(413),
                        "dynamic policy request body exceeded buffering cap",
                    ));
                }
            };
            for skipped_hook in skipped {
                let hook = skipped_hook.metadata();
                let posture = hook.failure_posture();
                tracing::warn!(
                    target: "sbproxy::extension",
                    bundle = hook.bundle_id(),
                    hook = hook.hook_type(),
                    policy_index = skipped_hook.policy_index(),
                    received = proposed_len,
                    cap = skipped_hook.cap(),
                    failure_posture = posture.as_label(),
                    "skipping buffered dynamic policy whose request body exceeded its cap"
                );
                if posture.guarantee_waived() || posture.records_counterfactual() {
                    ctx.record_policy_decision(hook.hook_type(), posture.as_label());
                }
            }

            if !ctx.dynamic_request_body_plan.has_active_buffered_policies()
                && !ctx.dynamic_request_body_plan.other_buffering_required()
            {
                let mut collected = ctx.request_body_buf.take().unwrap_or_default();
                if let Some(chunk) = body.take() {
                    collected.extend_from_slice(&chunk);
                }
                ctx.validate_request_body = false;
                if !collected.is_empty() {
                    *body = Some(collected.freeze());
                } else if !end_of_stream {
                    hold_request_body_chunk(body);
                }
                break 'request_validation;
            }

            if proposed_len > VALIDATE_BODY_HARD_CAP {
                debug!(
                    received = proposed_len,
                    cap = VALIDATE_BODY_HARD_CAP,
                    "request body validation blocked request: body exceeds buffering cap"
                );
                ctx.validator_failed = Some((
                    413,
                    error_json_body("request entity too large"),
                    "application/json".to_string(),
                ));
                *body = None;
                return Err(pingora_error::Error::explain(
                    pingora_error::ErrorType::HTTPStatus(413),
                    "request body validation exceeded buffering cap",
                ));
            }
            let buf = ctx
                .request_body_buf
                .get_or_insert_with(bytes::BytesMut::new);
            if let Some(chunk) = body.take() {
                buf.extend_from_slice(&chunk);
            }
            if end_of_stream {
                let collected = ctx.request_body_buf.take().unwrap_or_default().freeze();
                // A verified header signature that covers content-digest is
                // provisional until the complete pre-transform body arrives.
                // Authenticate that body before any validator can short
                // circuit so a mismatch is always attributed to the failed
                // proof and never reaches the upstream.
                if !crate::trust_tier::verify_and_finalize_body_proof(
                    ctx,
                    &session.req_header().headers,
                    &collected,
                ) {
                    debug!("bot_auth content-digest body binding check failed; rejecting request");
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
                let pipeline = ctx.pipeline.clone();
                if let Some(origin_idx) = ctx.origin_idx {
                    let workspace_id = pipeline.config.origins[origin_idx].workspace_id.to_string();
                    let verdict_ctx = PolicyVerdictCtx {
                        request_id: ctx.request_id.to_string(),
                        workspace_id,
                        origin: pipeline.config.origins[origin_idx].origin_id.to_string(),
                        tenant: ctx.tenant_id.to_string(),
                    };
                    if let Some((status, message, policy_type)) = check_buffered_dynamic_policies(
                        &pipeline.enforcers[origin_idx],
                        session,
                        ctx,
                        collected.clone(),
                        &verdict_ctx,
                    )
                    .await
                    {
                        let policy_type = effective_policy_type(ctx, policy_type);
                        sbproxy_observe::metrics::record_policy(
                            ctx.hostname.as_str(),
                            policy_type,
                            "deny",
                        );
                        ctx.record_policy_decision(policy_type, "deny");
                        let body_str = error_json_body(&message);
                        ctx.validator_failed =
                            Some((status, body_str, "application/json".to_string()));
                        return Err(pingora_error::Error::explain(
                            pingora_error::ErrorType::HTTPStatus(status),
                            "request body failed dynamic policy",
                        ));
                    }
                }
                let content_type = session
                    .req_header()
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let mut failed: Option<(u16, String, String)> = None;
                let mut graphql_content_digest_body = None;
                let mut graphql_content_digest_body_taken = false;
                let content_digest_uses_graphql_original = ctx.graphql_validation_pending;
                // WOR-2118: parse the agent-to-agent envelope once,
                // before the policy loop, so the `a2a` arm and the
                // prompt-injection arm read one structure rather than
                // each re-parsing the body. `ctx.a2a` is the envelope
                // the A2A enforcer resolved, which is not the same as
                // the one header detection stamped: it also carries the
                // operator's `route_glob` match and the verified `act`
                // chain overlay.
                //
                // The identifiers are cloned rather than borrowed
                // because the loop below mutates `ctx`, and they are
                // cloned only when the body actually parsed as A2A so a
                // plain validated POST pays nothing for this.
                let a2a_ctx = ctx.a2a.clone();
                let a2a_v1 = a2a_ctx
                    .as_ref()
                    .filter(|c| c.spec == sbproxy_modules::A2ASpec::V1_0)
                    .and_then(|_| sbproxy_modules::a2a_v1::parse_request(&collected));
                let a2a_idents = a2a_v1.as_ref().map(|_| {
                    (
                        ctx.hostname.to_string(),
                        ctx.request_id.to_string(),
                        ctx.tenant_id.to_string(),
                    )
                });
                // WOR-2139: capture the run correlation id off the same
                // parse. `params.contextId` groups every hop of one
                // multi-agent run, and this is the first phase where it
                // exists: the request filter builds the A2A envelope
                // from headers, which do not carry it. Stamped on the
                // context so the terminal surfaces (access log, and any
                // span opened later in the request) all read one bounded
                // value. Nothing is added to the upstream request here,
                // because `upstream_request_filter` already ran.
                if let Some(context_id) = a2a_v1
                    .as_ref()
                    .and_then(crate::server::a2a_body_phase::run_context_id)
                {
                    ctx.a2a_context_id = Some(context_id);
                }
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
                                    // RFC 9530 digests bind the inbound
                                    // representation. A validated GraphQL
                                    // modifier makes `collected` authoritative
                                    // for every downstream consumer, but the
                                    // digest alone must inspect the saved
                                    // pre-transform bytes. Take that slot once
                                    // at EOS and reuse it if configuration
                                    // contains more than one digest policy.
                                    if !graphql_content_digest_body_taken {
                                        graphql_content_digest_body =
                                            ctx.graphql_request_body.take();
                                        graphql_content_digest_body_taken = true;
                                    }
                                    let representation_body =
                                        if content_digest_uses_graphql_original {
                                            graphql_content_digest_body
                                                .as_deref()
                                                .unwrap_or_default()
                                        } else {
                                            &collected
                                        };
                                    if representation_body.len() > cd.max_body_bytes {
                                        // Mirror the request_limit
                                        // pattern: reject 413 the
                                        // moment the cap is exceeded.
                                        let body_str = serde_json::json!({
                                            "error": "request body exceeds content_digest max_body_bytes",
                                            "detail": format!(
                                                "body length {} > cap {}",
                                                representation_body.len(),
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
                                    let outcome = cd.verify(header_value, representation_body);
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
                                Policy::A2A(p) => {
                                    // WOR-2118: the A2A 1.0
                                    // push-notification SSRF check. It
                                    // runs here rather than in the
                                    // request filter because the
                                    // enforcer's request snapshot always
                                    // carries an empty body, so the
                                    // check was gated on a condition
                                    // that could never hold and never
                                    // fired once. The buffered body is
                                    // the first place the registration
                                    // is actually visible.
                                    let (Some(a2a), Some(parsed), Some((route, _, _))) =
                                        (a2a_ctx.as_ref(), a2a_v1.as_ref(), a2a_idents.as_ref())
                                    else {
                                        continue;
                                    };
                                    if let Some(rejection) =
                                        crate::server::a2a_body_phase::check_push_notification(
                                            p,
                                            route,
                                            a2a.spec.as_label(),
                                            a2a.identity_verified,
                                            parsed,
                                        )
                                    {
                                        ctx.a2a_denial_body = Some(rejection.body.clone());
                                        ctx.deny_policy_type = Some(rejection.deny_policy_type);
                                        failed = Some((
                                            rejection.status,
                                            rejection.body,
                                            rejection.content_type,
                                        ));
                                        break;
                                    }
                                }
                                Policy::PromptInjectionV2(p) => {
                                    // WOR-2118: an agent-to-agent hop
                                    // goes through the structured seam,
                                    // which scores each message part on
                                    // its own and picks the action from
                                    // the hop's delegation depth. The
                                    // generic path below fuses the whole
                                    // JSON-RPC envelope into one string,
                                    // which is what that seam exists to
                                    // stop doing.
                                    if let (
                                        Some(a2a),
                                        Some(parsed),
                                        Some((route, request_id, tenant_id)),
                                    ) = (a2a_ctx.as_ref(), a2a_v1.as_ref(), a2a_idents.as_ref())
                                    {
                                        let audit = sbproxy_modules::BodyAwareAuditContext {
                                            hostname: route.as_str(),
                                            request_id: Some(request_id.as_str()),
                                            tenant_id: Some(tenant_id.as_str()),
                                            virtual_key_id: None,
                                            policy_version: None,
                                        };
                                        if let Some(rejection) =
                                            crate::server::a2a_body_phase::scan_message_parts(
                                                p, route, a2a, parsed, &collected, audit,
                                            )
                                        {
                                            ctx.deny_policy_type = Some(rejection.deny_policy_type);
                                            failed = Some((
                                                rejection.status,
                                                rejection.body,
                                                rejection.content_type,
                                            ));
                                            break;
                                        }
                                        continue;
                                    }
                                    // WOR-2137: the generic body scan is
                                    // opt-in. The enforcer only requests
                                    // buffering when `enable_body_aware`
                                    // is set, but the buffer may exist
                                    // because another policy asked for
                                    // it, and a body buffered for a
                                    // validator must not feed a scan the
                                    // operator switched off.
                                    if !p.body_aware_enabled() {
                                        continue;
                                    }
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
                                                // WOR-2159: honour the
                                                // configured content type,
                                                // as the ai_proxy and A2A
                                                // block paths already do.
                                                failed = Some((
                                                    403,
                                                    p.block_body().to_string(),
                                                    p.block_content_type().to_string(),
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
                if graphql_content_digest_body_taken {
                    // Preserve the captured original for a possible upstream
                    // retry. The representation slot is borrowed by digest
                    // verification exactly once per body-filter pass.
                    ctx.graphql_request_body = graphql_content_digest_body;
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
                // Body validation and idempotency share the same request
                // buffer. When both are active, the validator branch owns
                // the end-of-stream chunk and must also register the
                // idempotency miss; otherwise the response is never cached
                // and the key-only replay path cannot engage.
                if ctx.idempotency_buffering {
                    let body_hash = sbproxy_middleware::idempotency::hash_body(&collected);
                    let header_name = ctx
                        .origin_idx
                        .and_then(|i| pipeline.idempotencies.get(i))
                        .and_then(|opt| opt.as_ref())
                        .map(|i| i.header_name.clone())
                        .unwrap_or_else(|| "Idempotency-Key".to_string());
                    let key = session
                        .req_header()
                        .headers
                        .get(header_name.as_str())
                        .and_then(|value| value.to_str().ok())
                        .map(str::trim)
                        .unwrap_or_default()
                        .to_string();
                    ctx.idempotency_miss = Some((key, body_hash));
                    ctx.idempotency_response_body_buf = Some(bytes::BytesMut::with_capacity(8192));
                    ctx.idempotency_buffering = false;
                }
                // Validation passed - release the buffered body as one
                // chunk so the upstream sees the full payload.
                let frozen = if !collected.is_empty() {
                    let bytes = collected.clone();
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
                                params.trace_ctx,
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
            if !end_of_stream {
                // The chunk above was consumed into the accumulator;
                // `hold_request_body_chunk` documents why the slot must
                // carry an empty chunk here rather than `None`.
                hold_request_body_chunk(body);
            }
            emit_graphql_validated_request_body(body, end_of_stream, ctx);
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
                let pipeline = ctx.pipeline.clone();
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
                emit_graphql_validated_request_body(body, end_of_stream, ctx);
                return Ok(());
            }
            if let Some(chunk) = body.as_ref() {
                buf.extend_from_slice(chunk);
            }
            if end_of_stream {
                let collected = ctx.request_body_buf.take().unwrap_or_default();
                let body_hash = sbproxy_middleware::idempotency::hash_body(&collected);
                let header_name = {
                    let pipeline = ctx.pipeline.clone();
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
            emit_graphql_validated_request_body(body, end_of_stream, ctx);
            // Non-GraphQL requests pass the chunk through unchanged.
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
                            params.trace_ctx,
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

        if ctx.graphql_validated_request_body.is_some() {
            emit_graphql_validated_request_body(body, end_of_stream, ctx);
        } else if let Some(replacement) = ctx.replacement_request_body.take() {
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
        // WOR-2145: the meter refused this response in `response_filter`
        // under `failure_mode: closed`. Drop every chunk so the buyer
        // receives none of the work the proxy cannot record.
        //
        // Ahead of the byte accounting below on purpose. `bytes_out` is
        // the evidence behind a measured unit, so it has to be what
        // actually crossed the wire and not what the upstream offered.
        if ctx.meter_refused {
            *body = None;
            return Ok(None);
        }

        crate::proxy_wasm_http::filter_response_body(body, end_of_stream, ctx)?;

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

        // --- Closed-posture size refusal, ahead of every capture ---
        //
        // WOR-2411. This must run before the response cache and the
        // idempotency capture accumulate this chunk: both store the
        // *pre-transform* body, and on the chunk that crosses the cap
        // with end_of_stream set they would otherwise dispatch their
        // writes in this same call, so the bytes the closed posture is
        // about to refuse would be served verbatim from cache for the
        // entry's whole TTL. Aborting first means nothing captures them.
        //
        // Deliberately NOT gated on `buffering_body`: buffering starts
        // in the transform section below, so a body whose first chunk
        // alone crosses the cap arrives here before buffering exists,
        // and gating on it made the refusal miss exactly the
        // single-chunk delivery that small caps see most. The projected
        // size is whatever is buffered so far (zero on the first chunk)
        // plus this chunk.
        //
        // Two states are exempt. A pending fallback or replacement body
        // (consumed just below) discards the upstream body entirely, so
        // there is nothing oversized left to refuse. And once the
        // all-open pass-through has committed this response to raw
        // delivery, aborting a later chunk would truncate a stream
        // whose raw prefix the client already holds, which is worse
        // than the pass-through the open posture already chose.
        if let Some(chunk_len) = body.as_ref().map(bytes::Bytes::len) {
            if let Some(name) = closed_refusal_before_capture(ctx, chunk_len) {
                warn!(
                    hostname = %ctx.hostname,
                    chunk = chunk_len,
                    transform = %name,
                    "response body exceeded max_body_size; a closed transform \
                     cannot be skipped, failing the response"
                );
                return abort_committed_transform_response(body, ctx, &name);
            }
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
            // An origin with transforms attached stores the transform
            // chain's output, not the raw upstream bytes: the entry
            // holds what this miss ships, so a hit serves the same
            // content a miss does and a `closed` transform's guarantee
            // extends to cached responses. For those origins the store
            // dispatch lives in the transform section below, after the
            // chain has run; `cache_body_buf` stays `Some` as the
            // capture-active marker but accumulates nothing, so the
            // body is not buffered twice. A body that bypasses the
            // transform section entirely (an oversized pass-through, a
            // committed fallback or replacement) is deliberately not
            // stored: it did not go through the chain, so the cache
            // must not replay it.
            let origin_stores_transformed = ctx
                .origin_idx
                .and_then(|idx| ctx.pipeline.transforms.get(idx))
                .is_some_and(|transforms| !transforms.is_empty());
            if !origin_stores_transformed {
                if let Some(chunk) = body.as_ref() {
                    if let Some(buf) = &mut ctx.cache_body_buf {
                        buf.extend_from_slice(chunk);
                    }
                }
                if end_of_stream {
                    if let Some(body_buf) = ctx.cache_body_buf.take() {
                        dispatch_response_cache_store(ctx, &body_buf);
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
                let pipeline = ctx.pipeline.clone();
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
                        let pipeline = ctx.pipeline.clone();
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

        let pipeline = ctx.pipeline.clone();
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

        // A response committed to raw delivery stays raw (WOR-2418):
        // re-buffering after the overflow flush would run transforms and
        // the SRI scanner over the tail alone.
        if ctx.transform_passthrough_committed {
            return Ok(None);
        }

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
                    // The closed-posture refusal (WOR-2411) runs before
                    // the capture blocks on every chunk, so reaching
                    // this arm means every transform that applies to
                    // this content type is `open` and the documented
                    // pass-through stands.
                    warn!(
                        hostname = %ctx.hostname,
                        buffered = buf.len(),
                        chunk = chunk.len(),
                        max = max_size,
                        "response body buffer exceeded max_body_size, passing through unmodified"
                    );
                    // Flush the buffer plus this chunk as-is, and commit
                    // the rest of this response to raw delivery
                    // (WOR-2418): without the commitment, buffering
                    // restarted on the next chunk and the transforms
                    // plus the SRI scanner ran on the post-overflow
                    // tail alone, handing the client a raw head
                    // concatenated with a transformed tail, and the
                    // scanner a verdict over a fragment.
                    let combined = buf.split().freeze();
                    let mut out = bytes::BytesMut::with_capacity(combined.len() + chunk.len());
                    out.extend_from_slice(&combined);
                    out.extend_from_slice(&chunk);
                    *body = Some(out.freeze());
                    ctx.response_body_buf = None;
                    ctx.buffering_body = false;
                    ctx.transform_passthrough_committed = true;
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
                        // WOR-2318: one span per transform. `transform_type`
                        // is borrowed from the compiled transform and the
                        // body never reaches an attribute, so the span costs
                        // no allocation on a path that already owns the
                        // whole response in memory.
                        //
                        // Parented explicitly rather than contextually. This
                        // is a different Pingora callback from
                        // `request_filter`, so the intake span is not current
                        // here and there is nothing to inherit. Where the
                        // caller sent a `traceparent` the transform joins
                        // that trace, which is the case that matters; where
                        // it did not, the proxy's own root was synthesized
                        // and parenting on it would point at a span nothing
                        // ever exported, so this stays a root of its own.
                        let shape_span = sbproxy_observe::telemetry::transform_shape_span(
                            compiled_transform.transform.transform_type(),
                        );
                        sbproxy_observe::telemetry::parent_span_on_remote_trace_context(
                            &shape_span,
                            ctx.trace_ctx.as_ref(),
                            ctx.trace_parent_is_remote,
                        );
                        let shape_guard = shape_span.entered();
                        let transform_outcome = apply_transform_with_ctx(
                            compiled_transform,
                            &mut buf,
                            content_type,
                            ctx,
                        );
                        drop(shape_guard);
                        if let Err(e) = transform_outcome {
                            // WOR-168: a `TransformError::InvariantViolated`
                            // or `TransformError::Plugin` is a code-level
                            // bug or a misbehaving plugin; both must
                            // surface as a 500 regardless of the
                            // configured failure posture. The transform name flows
                            // onto the response as
                            // `x-sbproxy-transform-error` so the caller
                            // and operator can correlate.
                            //
                            // WOR-2268 carves one case out of that rule. A
                            // dynamic bundle transform declares its own
                            // posture in its manifest, and the operator
                            // installing it is making the same call WOR-168
                            // reserved for the host: a guest that times out
                            // or panics is exactly what `failure_posture`
                            // was written to describe. An invariant
                            // violation is still the host's own bug and
                            // still a 500 either way.
                            let transform_name = compiled_transform.transform.transform_type();
                            let is_typed_transform_error =
                                crate::server::transform_error_is_unconditional_500(
                                    compiled_transform,
                                    &e,
                                );
                            if is_typed_transform_error {
                                tracing::error!(
                                    hostname = %ctx.hostname,
                                    transform = transform_name,
                                    error = %e,
                                    "transform pipeline invariant violated, returning 500 with attribution"
                                );
                                return abort_committed_transform_response(
                                    body,
                                    ctx,
                                    transform_name,
                                );
                            }
                            // Read the resolved posture off the compiled
                            // transform, never the legacy `fail_on_error`
                            // wire boolean: the conversion happened once at
                            // config load ([`TransformConfig::failure_posture`]).
                            let posture = compiled_transform.failure_posture;
                            match posture {
                                FailureMode::Closed => {
                                    warn!(
                                        hostname = %ctx.hostname,
                                        transform = transform_name,
                                        error = %e,
                                        failure_posture = posture.as_label(),
                                        "transform failed; response failed by failure_posture"
                                    );
                                    return abort_committed_transform_response(
                                        body,
                                        ctx,
                                        transform_name,
                                    );
                                }
                                FailureMode::Open => {
                                    warn!(
                                        hostname = %ctx.hostname,
                                        transform = transform_name,
                                        error = %e,
                                        "transform failed, continuing with next transform"
                                    );
                                }
                                // Both are rejected at config load
                                // (`TransformConfig::validate_failure_posture`),
                                // so these arms are unreachable from a loaded
                                // config. Kept explicit (no wildcard) so
                                // defining degraded semantics here forces a
                                // decision rather than inheriting one; until
                                // then, honour their admitting nature.
                                FailureMode::Degraded | FailureMode::Observe => {
                                    warn!(
                                        hostname = %ctx.hostname,
                                        transform = transform_name,
                                        error = %e,
                                        failure_posture = posture.as_label(),
                                        "transform failed; posture admits, continuing"
                                    );
                                }
                            }
                        }
                    }
                }

                // --- Response cache: store the transform chain's output ---
                //
                // Ingest semantics (WOR-2417): the capture block above
                // left `cache_body_buf` as a marker on origins with
                // transforms, and this is the one point where the
                // final body exists after every transform and before
                // compression, which hits do not replay. A closed
                // transform failure returned above, so nothing unsafe
                // reaches this store.
                if has_transforms && ctx.cache_body_buf.take().is_some() {
                    dispatch_response_cache_store(ctx, &buf);
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
                    let pre = buf.len();
                    sbproxy_observe::metrics::record_response_body_bytes(
                        "pre_compress",
                        pre as u64,
                    );
                    if buf.len() >= ctx.compression_min_size {
                        match sbproxy_middleware::compression::compress_body(
                            &buf[..],
                            encoding,
                            ctx.compression_level,
                        ) {
                            Ok(compressed) => {
                                let post = compressed.len();
                                buf.clear();
                                buf.extend_from_slice(&compressed);
                                sbproxy_observe::metrics::record_response_body_bytes(
                                    "post_compress",
                                    post as u64,
                                );
                                sbproxy_observe::metrics::record_compression_decision(
                                    encoding.as_str(),
                                    "applied",
                                );
                                if pre > 0 {
                                    sbproxy_observe::metrics::record_compression_ratio(
                                        encoding.as_str(),
                                        post as f64 / pre as f64,
                                    );
                                }
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
                    } else {
                        // Buf is below the floor at end-of-stream;
                        // we set the Content-Encoding header earlier
                        // but the encoder is bypassed. Count this as
                        // a size skip so dashboards can flag origins
                        // configured at too high a `min_size`.
                        sbproxy_observe::metrics::record_compression_decision(
                            encoding.as_str(),
                            "skipped_size",
                        );
                    }
                } else {
                    sbproxy_observe::metrics::record_response_body_bytes(
                        "pre_compress",
                        buf.len() as u64,
                    );
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
    /// allows `connect_error` (or `timeout`, for the timeout-classed
    /// connect failures) and we are still under `max_attempts`, mark
    /// the error retryable so Pingora calls `upstream_peer` again.
    /// For load_balancer actions, the failed target is reported to
    /// the outlier detector so the next selection skips it.
    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<Error>,
    ) -> Box<Error> {
        let pipeline = ctx.pipeline.clone();
        finish_load_balancer_attempt(ctx, LoadBalancerAttemptOutcome::Failure);
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
        let retry_cfg = action.and_then(retry_config_for_action);
        let Some(cfg) = retry_cfg else {
            return e;
        };
        // A connect-phase timeout (TCP connect or TLS handshake
        // deadline) is both a connect error and a timeout, so either
        // `retry_on` token enables the retry.
        let timeout_phase = timeout_error_phase(e.etype());
        let allowed =
            cfg.allows("connect_error") || (timeout_phase.is_some() && cfg.allows("timeout"));
        // `retry_count` is shared with status-code and mid-proxy
        // timeout retries (`maybe_retry_upstream_status`,
        // `error_while_proxy`), so `max_attempts` caps the combined
        // total, never each source separately.
        if !allowed || !cfg.attempts_remaining(ctx.retry_count) {
            return e;
        }
        let backoff_ms = cfg.backoff_for_attempt(ctx.retry_count);
        ctx.retry_count += 1;
        ctx.retry_backoff_ms = Some(backoff_ms);
        // The timeout metric keys on the error class, not on which
        // `retry_on` token enabled the retry: a ConnectTimedout
        // retried under `connect_error` is still a timeout retry.
        if let Some(phase) = timeout_phase {
            sbproxy_observe::metrics::record_upstream_timeout_retry(ctx.hostname.as_str(), phase);
        }
        debug!(
            attempt = %ctx.retry_count,
            max = %cfg.max_attempts,
            backoff_ms = %backoff_ms,
            "upstream connect error, retrying"
        );
        e.set_retry(true);
        e
    }

    /// Pingora calls this when the request fails after the upstream
    /// connection was established (or reused). Two retry sources meet
    /// here, in order:
    ///
    /// 1. Pingora's reused-connection retry: an error marked
    ///    `ReusedOnly` (a stale pooled connection dying on first use)
    ///    becomes retryable when the connection was reused and the
    ///    retry buffer was not truncated. That default is preserved
    ///    verbatim and does not consume the configured attempt cap.
    /// 2. The action's `retry.retry_on: [timeout]` policy: a read or
    ///    write deadline on the upstream leg schedules a retry under
    ///    the same shared `max_attempts` counter as connect-error and
    ///    status-code retries. The proxy loop retries blindly on
    ///    `e.retry()`, so this callback must hold the two safety
    ///    gates itself: no response bytes written downstream, and a
    ///    request that is safe to replay (idempotent method, fully
    ///    buffered body).
    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        e: Box<Error>,
        ctx: &mut Self::CTX,
        client_reused: bool,
    ) -> Box<Error> {
        // Default fork behavior: peer context plus the
        // reused-connection retry decision.
        let mut e = e.more_context(format!("Peer: {peer}"));
        if crate::proxy_wasm_http::has_pending_local_response(ctx) {
            finish_terminal_load_balancer_attempt(ctx, None);
            e.set_retry(false);
            return e;
        }
        e.retry
            .decide_reuse(client_reused && !session.as_ref().retry_buffer_truncated());

        let pipeline = ctx.pipeline.clone();
        finish_terminal_load_balancer_attempt(ctx, Some(e.esource()));
        let Some(action) = active_action(&pipeline, ctx) else {
            return e;
        };
        if e.retry() {
            return e;
        }
        let Some(cfg) = retry_config_for_action(action) else {
            return e;
        };
        let response_started = session.as_ref().response_written().is_some();
        let replay_skip = status_retry_skip_reason(session);
        let Some(phase) = maybe_retry_upstream_timeout(
            cfg,
            e.etype(),
            e.esource(),
            ctx.retry_count,
            response_started,
            replay_skip,
        ) else {
            return e;
        };

        let backoff_ms = cfg.backoff_for_attempt(ctx.retry_count);
        ctx.retry_count += 1;
        ctx.retry_backoff_ms = Some(backoff_ms);
        sbproxy_observe::metrics::record_upstream_timeout_retry(ctx.hostname.as_str(), phase);
        debug!(
            attempt = %ctx.retry_count,
            max = %cfg.max_attempts,
            backoff_ms = %backoff_ms,
            phase = %phase,
            "upstream timeout, retrying"
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
        if let Some(local_response) = crate::proxy_wasm_http::take_pending_local_response(ctx) {
            let status = local_response.status;
            let _ = crate::proxy_wasm_http::send_terminal_local_response(session, &local_response)
                .await;
            ctx.response_status = Some(status);
            return FailToProxy {
                error_code: status,
                can_reuse_downstream: false,
            };
        }

        if crate::proxy_wasm_http::response_stream_failed(ctx) {
            return FailToProxy {
                error_code: 500,
                can_reuse_downstream: false,
            };
        }

        // Quota settlement is intentionally the final realtime outbound seam.
        // Preserve its exact response and bypass origin fallback if it fails
        // after Pingora has selected an upstream.
        if let Some(failure) = ctx.ai_realtime_quota_failure.take() {
            let _ = send_error(session, failure.status, failure.message).await;
            ctx.response_status = Some(failure.status);
            return FailToProxy {
                error_code: failure.status,
                can_reuse_downstream: false,
            };
        }

        // --- Request body validator rejection ---
        // The body filter intentionally aborted the upstream after a
        // validation failure. Surface the configured status / body
        // here rather than the generic 502.
        if let Some(cached) = ctx.idempotency_deferred_hit.take() {
            let status = cached.status;
            let _ = send_idempotency_cache_hit(session, cached).await;
            ctx.response_status = Some(status);
            return FailToProxy {
                error_code: status,
                can_reuse_downstream: false,
            };
        }

        if let Some((status, body, content_type)) = ctx.validator_failed.take() {
            // GraphQL validation runs in `upstream_request_filter`, after
            // Pingora selected an upstream. Pingora cannot reuse an HTTP/1
            // downstream after an error at that phase, so advertise the
            // close explicitly instead of emitting a misleading keep-alive.
            let close_downstream = ctx.graphql_validation_pending;
            let close_http1 = close_downstream
                && matches!(
                    session.req_header().version,
                    http::Version::HTTP_10 | http::Version::HTTP_11
                );
            if close_http1 {
                session.set_keepalive(None);
            }
            let mut header = match pingora_http::ResponseHeader::build(status, Some(2)) {
                Ok(h) => h,
                Err(_) => {
                    let _ = send_error(session, status, "validation failed").await;
                    ctx.response_status = Some(status);
                    return FailToProxy {
                        error_code: status,
                        can_reuse_downstream: !close_downstream,
                    };
                }
            };
            let _ = header.insert_header("content-type", content_type);
            let _ = header.insert_header("content-length", body.len().to_string());
            if close_http1 {
                let _ = header.insert_header("connection", "close");
            }
            let _ = session.write_response_header(Box::new(header), false).await;
            let _ = session
                .write_response_body(Some(bytes::Bytes::from(body)), true)
                .await;
            ctx.response_status = Some(status);
            return FailToProxy {
                error_code: status,
                can_reuse_downstream: !close_downstream,
            };
        }

        // Check if we have a fallback with on_error configured.
        if let Some(origin_idx) = ctx.origin_idx {
            let pipeline = ctx.pipeline.clone();
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
        let pipeline = ctx.pipeline.clone();
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
        crate::proxy_wasm_http::finish(ctx);

        // A body-bound BotAuth signature is provisional during the header
        // and policy phases. If a short circuit prevented the body verifier
        // from running, close the observation conservatively without
        // granting Strong from the unverified body binding.
        crate::trust_tier::finalize_pending_body_proof_at_request_end(ctx);

        // Decrement active connections gauge (global + per-origin).
        metrics().active_connections.dec();

        let status_u16 = final_response_status(ctx, session.response_written());
        let record_proxy_request_metrics =
            should_record_proxy_request_metrics(session.req_header().uri.path());

        // Phase 7: AI realtime WebSocket session-close hook. When the
        // request opened a realtime session, observe duration, tick
        // the active-sessions gauge down, and emit a session-end
        // AiBillingEvent with the wall-clock duration as an
        // approximation of the audio time forwarded. Frame-exact
        // audio metering would require terminating the WebSocket
        // (not transparent forwarding); the duration approximation
        // is the right OSS-v1 substitute since the session
        // lifetime IS the audio call.
        if let Some(rd) = take_accepted_realtime_dispatch(&mut ctx.ai_realtime_dispatch, status_u16)
        {
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
            let span = tracing::Span::current();
            emit_ai_billing_event(
                ctx.hostname.as_str(),
                rd.surface_label,
                &rd.provider_name,
                Some("gpt-4o-realtime-preview".to_string()),
                usage,
                0.0,
                Vec::new(),
                &ctx.attribution_tags,
                ctx.tenant_id.as_str(),
                ctx.principal.api_key_id(),
                &ctx.rollup_properties,
                // WOR-2140: the realtime surface bills like any other, so
                // it carries the same agent identity. `billable_id` still
                // refuses an unverified name, so this cannot become a way
                // to spend against an agent's budget over a websocket.
                sbproxy_ai::budget::AgentIdentity {
                    id: ctx
                        .a2a
                        .as_ref()
                        .map(|a2a| sbproxy_ai::tracing_spans::cap_agent_id(&a2a.caller_agent_id))
                        .filter(|id| !id.is_empty()),
                    verified: ctx.a2a.as_ref().is_some_and(|a2a| a2a.identity_verified),
                },
                &span,
                // The realtime close path reports the usage it measured over
                // the session; there is no estimate to substitute here.
                sbproxy_ai::budget::TokenDebit::Measured,
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

        // WOR-1921: compression savings become realized value only after the
        // terminal provider response succeeds. Always take the pending value
        // so this end-of-request hook cannot record it more than once.
        if let Some(pending) = take_realized_compression_value(ctx, status_u16, e.is_some()) {
            crate::compression_value::record_pending_compression_value(
                ctx.tenant_id.as_str(),
                ctx.hostname.as_str(),
                &pending,
            );
        }

        // WOR-1528 / WOR-1540: hand the completed AI call to the
        // configured usage sinks (the verifiable ledger among them).
        // No-op unless this request dispatched to an AI provider on an
        // origin with sinks configured.
        record_usage_sinks(ctx);

        // WOR-1541: fold the realized outcome into the routing feedback
        // store (no-op unless the origin uses outcome-aware routing).
        // WOR-2213: `status_u16`, not `ctx.response_status`. The AI
        // path never reaches the `response_filter` that sets that field,
        // so reading it recorded a failure for every successful call.
        record_routing_feedback(ctx, status_u16);

        // WOR-2145: cut the attested consumption receipt.
        //
        // Here rather than in `response_filter` because this is the
        // first point at which the facts a receipt states are all
        // final: the status after every override, the bytes that
        // actually crossed the wire, and whether the client stayed to
        // receive them. Metering off the response header would bill
        // intent rather than delivery.
        //
        // A downstream error source is the client going away. That is a
        // different commercial event from the origin failing, and the
        // outcome table prices the two separately, so the distinction
        // is carried rather than flattened into "something went wrong".
        //
        // No-op unless this origin's resolved role writes receipts.
        {
            let client_disconnected = client_disconnected(
                e.map(|error| error.esource().clone()),
                downstream_half_closed(session),
            );
            let path = session.req_header().uri.path().to_string();
            let settled = crate::meter_runtime::record_response(
                ctx,
                &method,
                &path,
                status_u16,
                client_disconnected,
            );

            // WOR-2169: queue what this request owes a usage reporter.
            //
            // Immediately after the receipt and from the same settlement,
            // never from a second derivation: whether a cache hit or a
            // policy block is billable is the operator's outcome table's
            // answer, and two independent readings of that table would
            // eventually disagree and put a charge on an invoice the
            // signed receipt says is free.
            //
            // A durable enqueue and nothing else. The provider call is the
            // recovery worker's, behind its own lease and its own
            // idempotency key, so no request ever waits on Stripe.
            //
            // No-op unless a usage reporter is configured, which is a
            // single `Option` test on the pinned pipeline.
            #[cfg(feature = "payments")]
            crate::usage_bridge::record_billable_usage(ctx, settled.as_ref()).await;
            #[cfg(not(feature = "payments"))]
            let _ = settled;
        }

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
        let latency_secs = ctx
            .request_start
            .map(|s| s.elapsed().as_secs_f64())
            .unwrap_or(0.0);
        if record_proxy_request_metrics {
            sbproxy_observe::metrics::record_request_with_labels(
                &hostname,
                &method,
                status_u16,
                latency_secs,
                ctx.request_body_bytes,
                ctx.response_body_bytes,
                agent_labels,
            );
        }
        // WOR-2093: one canonical id for the metric, the ring row below,
        // the access log, and spans.
        let accountable_key_id = ctx.accountable_key_id().map(str::to_string);
        record_inbound_key_request_for_path(
            session.req_header().uri.path(),
            ctx.native_key_provider.as_deref(),
            ctx.inbound_key_mode.as_str(),
            ctx.tenant_id.as_str(),
            accountable_key_id.as_deref(),
        );

        // WOR-1718: mirror the completed request into the admin request-log
        // ring buffer (and its SSE tail) when the admin server is running.
        if let Some(admin) = crate::admin::admin_log_sink() {
            let req = session.req_header();
            let path = req
                .uri
                .path_and_query()
                .map(|pq| pq.as_str().to_string())
                .unwrap_or_else(|| req.uri.path().to_string());
            admin.log_request(crate::admin::RequestLogEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                origin: hostname.clone(),
                method: method.clone(),
                path,
                status: status_u16,
                latency_ms: latency_secs * 1000.0,
                client_ip: session
                    .client_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_default(),
                // WOR-1874: correlation + AI columns so LogsView rows
                // expand usefully and the guardrail filters have data.
                request_id: (!ctx.request_id.is_empty()).then(|| ctx.request_id.to_string()),
                trace_id: ctx.trace_ctx.as_ref().map(|t| t.trace_id.clone()),
                session_id: ctx.session_id.map(|id| id.to_string()),
                parent_session_id: ctx.parent_session_id.map(|id| id.to_string()),
                properties: ctx.properties.clone(),
                cache_status: ctx.admin_cache_status.as_str().to_string(),
                retry_count: ctx.admin_retry_count(),
                failover_engaged: ctx.admin_failover_engaged(),
                failover_from: ctx.admin_failover_from.clone(),
                failover_to: ctx.admin_failover_to.clone(),
                load_balancer_strategy: ctx.admin_load_balancer_strategy.clone(),
                load_balancer_target: ctx.admin_load_balancer_target.clone(),
                provider: ctx.ai_provider.clone(),
                model: ctx.ai_model.clone(),
                tokens_in: ctx.ai_tokens_in,
                tokens_out: ctx.ai_tokens_out,
                cost_usd_micros: ctx.ai_cost_usd_micros,
                guardrail_category: ctx.ai_guardrail_category.clone(),
                guardrail_action: ctx.ai_guardrail_action.clone(),
                // WOR-2093: key accountability columns, from the same
                // canonical derivation as the metric emitted above.
                api_key_id: accountable_key_id,
                key_mode: ctx.inbound_key_mode.as_str().to_string(),
                key_provider: ctx.native_key_provider.clone(),
                tenant_id: ctx.tenant_id.to_string(),
                user_id: ctx.user_id.clone(),
                // WOR-2094: explainability columns; every row names the
                // config and policy generations that governed it and why
                // the gateway acted.
                error_class: super::access_log::classify_error_class(status_u16),
                config_revision: ctx.pipeline.config_revision.clone(),
                policy_version: ctx.ai_policy_version.clone(),
                policy_decisions: ctx.policy_decisions.clone(),
                deny_reason: ctx.deny_reason.clone(),
            });
        }

        // Record latency on the hostname-only histogram (legacy view).
        let duration = ctx
            .request_start
            .map(|s| s.elapsed().as_secs_f64())
            .unwrap_or(0.0);
        if record_proxy_request_metrics && duration > 0.0 {
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
        // counter + per-origin views were updated above for traffic
        // requests, so we only need to decrement the active gauge here.
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

        // Close any attempt that did not already end in a retry/error
        // callback. The token resolves its own main or forward-rule action, so
        // strategy, outlier, breaker, and connection state are updated once.
        finish_terminal_load_balancer_attempt(ctx, e.map(|error| error.esource()));

        // --- Access log emission (Prereq.A) ---
        //
        // Off by default. Gated on the compiled `access_log` block, then
        // filtered by status / method, then sampled. Each emit produces
        // one JSON line via the `access_log` tracing target. F2.11 will
        // build richer filter and sampling primitives on top of this; F2.12
        // will introduce enterprise sinks (S3, Kafka, Datadog).
        emit_access_log(session, ctx, status_u16, &method, &hostname, duration);

        // WOR-1496: per-attribution AI request outcome. Recorded once
        // per AI request in the logging phase so it is independent of
        // whether access-log emission is enabled (same rationale as the
        // boilerplate counter below), keyed by the authoritative
        // identity dimensions plus a closed outcome label so spend can
        // be sliced value-vs-waste. Non-AI traffic is skipped.
        if ctx.ai_provider.is_some() || ctx.ai_surface.is_some() {
            let outcome = crate::server::access_log::ai_outcome_label(
                status_u16,
                ctx.ai_outcome.as_deref(),
                ctx.admin_ai_attempts > 0,
            );
            let gateway_decision = crate::server::access_log::ai_gateway_decision(
                outcome,
                ctx.admin_ai_attempts,
                ctx.ai_gateway_action_reached,
            );
            if let Some((decision, reason)) = gateway_decision {
                sbproxy_ai::ai_metrics::record_ai_gateway_decision(decision, reason);
            }
            sbproxy_ai::ai_metrics::record_ai_outcome_attributed(
                ctx.hostname.as_str(),
                ctx.ai_provider.as_deref().unwrap_or(""),
                ctx.ai_model.as_deref().unwrap_or(""),
                ctx.ai_surface.as_deref().unwrap_or(""),
                ctx.tenant_id.as_str(),
                ctx.principal.api_key_id(),
                outcome,
            );
            // WOR-1875: request count + outcome split for the durable
            // spend rollups, once per AI request (blocked requests
            // that never billed included). Token / cost contributions
            // ride the billing choke point instead.
            sbproxy_observe::usage_rollup::record_usage_rollup(
                sbproxy_observe::usage_rollup::RollupEvent {
                    ts_secs: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                    dims: sbproxy_observe::usage_rollup::RollupDims {
                        origin: ctx.hostname.to_string(),
                        provider: ctx.ai_provider.clone().unwrap_or_default(),
                        model: ctx.ai_model.clone().unwrap_or_default(),
                        tenant: ctx.tenant_id.to_string(),
                        team: ctx.attribution_tags.team.clone().unwrap_or_default(),
                        api_key_id: ctx.principal.api_key_id().to_string(),
                        project: ctx.attribution_tags.project.clone().unwrap_or_default(),
                        // WOR-2140: same source as the usage path and the
                        // `agent_id` metric label. `attribution_tags` only
                        // carries an agent the proxy verified, so an
                        // unverified caller rolls up unattributed rather
                        // than under a name it chose for itself.
                        agent_id: ctx.attribution_tags.agent_id.clone().unwrap_or_default(),
                        properties: ctx.rollup_properties.clone(),
                    },
                    kind: sbproxy_observe::usage_rollup::RollupKind::Outcome(
                        sbproxy_observe::usage_rollup::RollupOutcome::from_outcome_label(outcome),
                    ),
                },
            );

            // WOR-1497: a request blocked before dispatch (budget cap,
            // guardrail, rate limit) or one that failed without an
            // upstream `usage` block emits no billing event, so its
            // prompt-side token volume would vanish from per-credential
            // reporting. When no measured usage was recorded
            // (`ai_tokens_in` is None) but we computed a request-path
            // estimate, attribute the estimated prompt tokens (cost 0,
            // `cache_read` direction is not used; recorded as `input`).
            // The `ai_tokens_in.is_none()` guard prevents double counting
            // against the measured spend recorded by the billing choke
            // point on the success path.
            // WOR-1833: charge this response's measured token usage into
            // the key's tokens-per-minute window. Done once at request
            // completion (covers unary and streaming alike, both of which
            // stamp `ai_tokens_*` when usage is extracted) so the next
            // request on the key sees the spent window.
            if let Some(bucket) = ctx.ai_key_tpm_bucket.as_deref() {
                let used = ctx.ai_tokens_in.unwrap_or(0) + ctx.ai_tokens_out.unwrap_or(0);
                if used > 0 {
                    super::ai_dispatch::key_rate_limiter().record_tokens(bucket, used);
                }
            }
            // WOR-2312: charge this response's measured token usage
            // into the agent_budget hourly window, on the same
            // completion-time seam as the key TPM charge above, so
            // the next request from the same agent is checked against
            // the spent window. Streamed responses already charged at
            // stream close in `relay_ai_stream`, where the SSE usage
            // frame aggregates; the sinks drain on first charge, so
            // the two seams cannot double count. A response that
            // reported no usage drains the sinks with zero and
            // consumes nothing.
            let agent_budget_used = ctx.ai_tokens_in.unwrap_or(0) + ctx.ai_tokens_out.unwrap_or(0);
            ctx.charge_agent_budget_tokens(agent_budget_used);
            if ctx.ai_tokens_in.is_none() {
                if let Some(est) = ctx.ai_prompt_tokens_est {
                    if est > 0 {
                        sbproxy_ai::ai_metrics::record_ai_request_attributed(
                            ctx.hostname.as_str(),
                            ctx.ai_provider.as_deref().unwrap_or(""),
                            ctx.ai_model.as_deref().unwrap_or(""),
                            ctx.ai_surface.as_deref().unwrap_or(""),
                            ctx.tenant_id.as_str(),
                            ctx.principal.api_key_id(),
                            &ctx.attribution_tags,
                            est,
                            0,
                            0,
                            0,
                            0,
                            0.0,
                        );
                    }
                }
            }
        }

        // WOR-1131: feed the boilerplate strip count into
        // `sbproxy_boilerplate_stripped_bytes_total`. Done here (not in the
        // transform apply) so the counter increments once per request and
        // independent of whether access-log emission is enabled; the
        // no-op-on-zero guard lives in the recorder.
        sbproxy_observe::metrics::record_boilerplate_stripped_bytes(
            &hostname,
            ctx.metrics.stripped_bytes,
        );

        // --- T4.6 envelope dispatch ---
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
        crate::capture_envelope::dispatch_terminal_event(
            ctx,
            crate::capture_envelope::DEFAULT_WORKSPACE_ID,
            latency_ms_envelope,
            error_class,
        );
    }
}

/// Write the standard forwarding headers, honoring each per-target
/// opt-out.
///
/// Split out of `upstream_request_filter` for WOR-2330. The seven
/// `disable_*_header` flags are read here and nowhere else, and the
/// config-reader guard cannot attribute a read that happens inside a
/// trait method: it skips trait impls deliberately, because a trait
/// method's name belongs to the trait rather than to the type. A free
/// function gives those seven keys a consumer the guard can name, which
/// is what lets `origins.*.action` be an `Enforced` root at all.
///
/// The same reasoning is already recorded on `LoadBalancerConfig`, which
/// lives at module scope rather than inside its constructor so the guard
/// can walk it. Keeping readers nameable is a standing requirement in
/// this workspace, not a one-off.
fn apply_forwarding_headers(
    forwarding: &sbproxy_modules::action::ForwardingHeaderControls,
    session: &Session,
    upstream_request: &mut pingora_http::RequestHeader,
    client_ip: Option<std::net::IpAddr>,
    client_host: Option<&str>,
) {
    let client_ip_str = client_ip.map(|ip| ip.to_string());
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
        if let Some(orig) = client_host {
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
    let pipeline = ctx.pipeline.clone();
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

/// Apply a response modifier's `status` override to the outgoing header.
///
/// The optional `reason` is the modifier's `status.text`. Pingora carries
/// it on [`pingora_http::ResponseHeader`] and serializes it into the
/// HTTP/1.x status line; HTTP/2 has no reason phrase on the wire, so the
/// value is ignored there. An invalid status code leaves the header
/// untouched, matching the pre-existing override behavior.
fn apply_response_status_override(
    response: &mut pingora_http::ResponseHeader,
    status_code: u16,
    reason: Option<&str>,
) {
    if let Ok(status) = http::StatusCode::from_u16(status_code) {
        response.set_status(status).ok();
        if reason.is_some() {
            response.set_reason_phrase(reason).ok();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora_error::ErrorSource;

    #[test]
    fn closed_transform_failure_aborts_a_committed_response() {
        let mut ctx = RequestContext::default();
        let mut body = Some(Bytes::from_static(b"unsafe upstream body"));

        let result = abort_committed_transform_response(&mut body, &mut ctx, "bundle");

        assert!(result.is_err());
        assert!(body.is_none());
        assert_eq!(ctx.response_status, Some(500));
        assert_eq!(ctx.response_status_override, Some(500));
        assert!(ctx.response_reason_override.is_none());
        assert_eq!(ctx.transform_error_attribution.as_deref(), Some("bundle"));
    }

    fn cap_test_transform(posture: FailureMode) -> sbproxy_modules::transform::CompiledTransform {
        let inner =
            sbproxy_modules::transform::HtmlToMarkdownTransform::from_config(serde_json::json!({}))
                .expect("default html_to_markdown");
        sbproxy_modules::transform::CompiledTransform {
            transform: sbproxy_modules::transform::Transform::HtmlToMarkdown(inner),
            content_types: Vec::new(),
            failure_posture: posture,
            max_body_size: 1024,
        }
    }

    fn refusal_test_ctx(config_yaml: &str) -> RequestContext {
        let config = sbproxy_config::compile_config(config_yaml).expect("fixture config");
        let pipeline =
            crate::pipeline::CompiledPipeline::from_config(config).expect("fixture pipeline");
        let mut ctx = RequestContext::new();
        ctx.pipeline = std::sync::Arc::new(pipeline);
        ctx.origin_idx = Some(0);
        ctx.upstream_content_type = Some("application/json".to_owned());
        ctx
    }

    const CLOSED_CAP_CONFIG: &str = r#"
origins:
  "cap.test":
    action:
      type: static
      body: placeholder
    transforms:
      - type: json
        set:
          safe: true
        failure_posture: closed
        max_body_size: 16
"#;

    #[test]
    fn a_single_oversized_first_chunk_is_refused_before_anything_captures_it() {
        // The re-review's crux. Buffering starts in the transform
        // section, so an earlier version gated this guard on
        // `buffering_body` and never fired for a body whose first chunk
        // alone crossed the cap: the cache write dispatched, the
        // pass-through arm served the body under a 200, and the closed
        // transform was bypassed entirely. Single-chunk delivery is the
        // common case for small caps, not the edge.
        let ctx = refusal_test_ctx(CLOSED_CAP_CONFIG);
        assert!(!ctx.buffering_body, "the crux: buffering has not started");
        assert_eq!(
            closed_refusal_before_capture(&ctx, 45).as_deref(),
            Some("json"),
            "the first chunk must be refused before the capture blocks see it"
        );
        assert_eq!(
            closed_refusal_before_capture(&ctx, 8),
            None,
            "a chunk under the cap proceeds"
        );
    }

    #[test]
    fn the_refusal_respects_the_exempt_states() {
        // A pending replacement discards the upstream body, so there is
        // nothing oversized left to refuse; and a response committed to
        // raw delivery must not be aborted after its raw prefix reached
        // the client.
        let mut ctx = refusal_test_ctx(CLOSED_CAP_CONFIG);
        ctx.transform_passthrough_committed = true;
        assert_eq!(closed_refusal_before_capture(&ctx, 45), None);

        let mut ctx = refusal_test_ctx(CLOSED_CAP_CONFIG);
        ctx.response_body_replacement = Some(bytes::Bytes::from_static(b"replacement"));
        assert_eq!(closed_refusal_before_capture(&ctx, 45), None);
    }

    #[test]
    fn the_refusal_counts_what_is_already_buffered() {
        let mut ctx = refusal_test_ctx(CLOSED_CAP_CONFIG);
        ctx.response_body_buf = Some(bytes::BytesMut::from(&b"twelve bytes"[..]));
        assert_eq!(
            closed_refusal_before_capture(&ctx, 8).as_deref(),
            Some("json"),
            "12 buffered + 8 arriving crosses a 16-byte cap"
        );
    }

    #[test]
    fn an_oversized_body_fails_the_response_when_a_closed_transform_is_attached() {
        // WOR-2411. A `closed` transform's contract is that the
        // untransformed body never reaches the client, and body size is
        // influenceable from either side of the proxy. Before this, a
        // big-enough body skipped the transform and passed through
        // unmodified: "make it big" bypassed exactly the control
        // `closed` promises, silently.
        let transforms = [
            cap_test_transform(FailureMode::Open),
            cap_test_transform(FailureMode::Closed),
        ];
        assert_eq!(
            oversized_body_refusal(&transforms, Some("text/html")),
            Some("html_to_markdown"),
            "one closed transform among open ones is enough to refuse"
        );
    }

    #[test]
    fn an_oversized_body_still_passes_through_when_every_transform_is_open() {
        // The documented pass-through is the correct behavior for the
        // open posture and must survive this change.
        let transforms = [cap_test_transform(FailureMode::Open)];
        assert_eq!(oversized_body_refusal(&transforms, Some("text/html")), None);
        assert_eq!(oversized_body_refusal(&[], Some("text/html")), None);
    }

    #[test]
    fn a_closed_transform_scoped_to_another_content_type_does_not_refuse() {
        // The over-refusal review caught: a closed HTML redactor scoped
        // to text/html must not abort every large zip download on the
        // same origin. The seam filters with the same predicate
        // apply-time uses, so a transform that would never have touched
        // this response cannot forbid delivering it.
        let mut scoped = cap_test_transform(FailureMode::Closed);
        scoped.content_types = vec!["text/html".to_owned()];
        let transforms = [scoped];
        assert_eq!(
            oversized_body_refusal(&transforms, Some("application/zip")),
            None,
            "a non-matching content type is outside the closed contract"
        );
        assert_eq!(
            oversized_body_refusal(&transforms, Some("text/html; charset=utf-8")),
            Some("html_to_markdown"),
            "the matching content type still refuses"
        );
    }

    #[test]
    fn a_delivered_response_over_a_half_closed_connection_is_not_a_disconnect() {
        // The billing dodge: RFC 9112 §9.6 half-close plus complete
        // delivery arrived with no error, and counting the FIN alone
        // let any client discount its own fully received response by
        // calling shutdown(SHUT_WR) after sending the request.
        assert!(
            !client_disconnected(None, true),
            "half-close with clean delivery is a delivered response"
        );
    }

    #[test]
    fn a_failed_delivery_still_classifies_as_a_client_disconnect() {
        // A downstream-sourced error counts on its own, as before.
        assert!(client_disconnected(
            Some(pingora_error::ErrorSource::Downstream),
            false
        ));
        // Half-close plus any delivery failure is the client gone
        // mid-response, whichever side the error was attributed to.
        assert!(client_disconnected(
            Some(pingora_error::ErrorSource::Upstream),
            true
        ));
        // An upstream failure with the client still fully connected is
        // the origin's problem, not a disconnect.
        assert!(!client_disconnected(
            Some(pingora_error::ErrorSource::Upstream),
            false
        ));
    }

    #[test]
    fn metrics_scrapes_do_not_count_as_proxy_traffic() {
        assert!(!should_record_proxy_request_metrics("/metrics"));
        assert!(should_record_proxy_request_metrics("/metrics/tenant"));
        assert!(should_record_proxy_request_metrics("/health"));
        assert!(!record_inbound_key_request_for_path(
            "/metrics", None, "none", "", None,
        ));
        assert!(record_inbound_key_request_for_path(
            "/metrics/tenant",
            None,
            "none",
            "",
            None,
        ));
    }

    #[test]
    fn forward_rule_advanced_request_modifiers_join_the_route_pipeline() {
        let config = sbproxy_config::compile_config(
            r#"
origins:
  "forward.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    forward_rules:
      - rules:
          - path:
              prefix: /api/
        origin:
          id: api
          action:
            type: proxy
            url: http://127.0.0.1:18889
          request_modifiers:
            - url:
                path:
                  replace:
                    old: /api/
                    new: /v2/
              query:
                set:
                  routed: forward
                remove:
                  - stale
              method: POST
              body:
                replace_json:
                  routed: true
"#,
        )
        .expect("fixture config");
        let pipeline = CompiledPipeline::from_config(config).expect("fixture pipeline");
        let modifiers = request_modifiers_for_route(&pipeline, 0, Some(0));
        let mut request =
            pingora_http::RequestHeader::build("GET", b"/api/items?stale=1", None).unwrap();
        let mut ctx = RequestContext::default();

        apply_advanced_request_modifiers(&modifiers, &mut request, &mut ctx);

        assert_eq!(request.method, http::Method::POST);
        assert_eq!(request.uri.to_string(), "/v2/items?routed=forward");
        assert_eq!(
            ctx.replacement_request_body.as_deref(),
            Some(&b"{\"routed\":true}"[..])
        );
    }

    /// `status.text` rides the header struct Pingora's HTTP/1.x
    /// serializer reads the status line from, so asserting on
    /// `get_reason_phrase` here is asserting on the wire bytes.
    #[test]
    fn status_override_carries_a_custom_reason_phrase() {
        let mut response = pingora_http::ResponseHeader::build(200, None).expect("build header");

        apply_response_status_override(&mut response, announcement_status(), Some("Custom Away"));

        assert_eq!(response.status.as_u16(), announcement_status());
        assert_eq!(response.get_reason_phrase(), Some("Custom Away"));
    }

    #[test]
    fn status_override_without_text_keeps_the_canonical_reason() {
        let mut response = pingora_http::ResponseHeader::build(200, None).expect("build header");

        apply_response_status_override(&mut response, 404, None);

        assert_eq!(response.status.as_u16(), 404);
        assert_eq!(response.get_reason_phrase(), Some("Not Found"));
    }

    #[test]
    fn status_override_with_an_invalid_code_changes_nothing() {
        let mut response = pingora_http::ResponseHeader::build(200, None).expect("build header");

        apply_response_status_override(&mut response, 99, Some("Bogus"));

        assert_eq!(response.status.as_u16(), 200);
        assert_eq!(response.get_reason_phrase(), Some("OK"));
    }

    /// 299 has no canonical reason in the `http` crate, proving the
    /// custom phrase is the one carried rather than a canonical echo.
    fn announcement_status() -> u16 {
        299
    }

    /// The service-discovery idle cap is a correctness bound (pooled
    /// connections must not outlive an IP rotation), so a configured idle
    /// combines with it via min(): neither side wins outright.
    #[test]
    fn sd_idle_cap_takes_the_min_of_configured_and_cap() {
        use std::time::Duration;

        // Configured idle above the cap: the cap wins.
        assert_eq!(
            cap_idle_for_service_discovery(
                Some(Duration::from_secs(90)),
                Some(Duration::from_secs(5))
            ),
            Some(Duration::from_secs(5))
        );
        // Configured idle below the cap: the configured value wins.
        assert_eq!(
            cap_idle_for_service_discovery(
                Some(Duration::from_secs(2)),
                Some(Duration::from_secs(5))
            ),
            Some(Duration::from_secs(2))
        );
        // No service discovery: the configured value passes through.
        assert_eq!(
            cap_idle_for_service_discovery(Some(Duration::from_secs(90)), None),
            Some(Duration::from_secs(90))
        );
        // No configured idle: the cap passes through.
        assert_eq!(
            cap_idle_for_service_discovery(None, Some(Duration::from_secs(5))),
            Some(Duration::from_secs(5))
        );
        // Neither side present: stays unset.
        assert_eq!(cap_idle_for_service_discovery(None, None), None);
    }

    #[test]
    fn dpop_resource_htu_uses_final_authority_and_path_without_query() {
        let mut request =
            pingora_http::RequestHeader::build("PATCH", b"/v2/items/a%2Fb?debug=true", None)
                .unwrap();
        request
            .insert_header("host", "api.example.test:8443")
            .unwrap();

        assert_eq!(
            dpop_resource_htu("https", &request).unwrap(),
            "https://api.example.test:8443/v2/items/a%2Fb"
        );
    }

    #[test]
    fn resource_nonce_challenge_requires_401_dpop_error_and_one_nonce() {
        let mut response = pingora_http::ResponseHeader::build(401, Some(2)).unwrap();
        response
            .insert_header(
                "www-authenticate",
                r#"DPoP error="use_dpop_nonce", error_description="nonce required""#,
            )
            .unwrap();
        response
            .insert_header("dpop-nonce", "resource-nonce")
            .unwrap();
        assert_eq!(
            dpop_resource_nonce_challenge(&response).as_deref(),
            Some("resource-nonce")
        );

        response.set_status(http::StatusCode::BAD_REQUEST).unwrap();
        assert!(dpop_resource_nonce_challenge(&response).is_none());
        response.set_status(http::StatusCode::UNAUTHORIZED).unwrap();
        response
            .append_header("dpop-nonce", "second-resource-nonce")
            .unwrap();
        assert!(dpop_resource_nonce_challenge(&response).is_none());
    }

    #[test]
    fn resource_nonce_challenge_finds_dpop_after_another_challenge() {
        let mut response = pingora_http::ResponseHeader::build(401, Some(3)).unwrap();
        response
            .insert_header(
                "www-authenticate",
                r#"Bearer realm="api", DPoP error = "use_dpop_nonce""#,
            )
            .unwrap();
        response.insert_header("dpop-nonce", "nonce-2").unwrap();

        assert_eq!(
            dpop_resource_nonce_challenge(&response).as_deref(),
            Some("nonce-2")
        );
    }

    #[test]
    fn resource_nonce_challenge_requires_the_exact_error_parameter_name() {
        let mut response = pingora_http::ResponseHeader::build(401, Some(3)).unwrap();
        response
            .insert_header(
                "www-authenticate",
                r#"DPoP fooerror="use_dpop_nonce", error_description="use_dpop_nonce""#,
            )
            .unwrap();
        response.insert_header("dpop-nonce", "nonce-3").unwrap();

        assert!(dpop_resource_nonce_challenge(&response).is_none());
    }

    #[test]
    fn malformed_nonce_does_not_hide_the_dpop_challenge() {
        let mut response = pingora_http::ResponseHeader::build(401, Some(3)).unwrap();
        response
            .insert_header("www-authenticate", r#"DPoP error="use_dpop_nonce""#)
            .unwrap();
        response
            .insert_header("dpop-nonce", "contains a space")
            .unwrap();

        assert!(dpop_resource_nonce_challenge_present(&response));
        assert!(dpop_resource_nonce_challenge(&response).is_none());
    }

    #[test]
    fn final_dpop_authorization_must_match_the_minted_token() {
        let mut request = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        request
            .insert_header("authorization", "DPoP minted-token")
            .unwrap();
        assert_eq!(
            final_dpop_access_token(&request, "minted-token").unwrap(),
            "minted-token"
        );

        // A post-credential Lua modifier can overwrite Authorization. The
        // final proof seam must reject that request instead of hashing the
        // stale minted token into `ath`.
        request
            .insert_header("authorization", "DPoP lua-token")
            .unwrap();
        assert!(final_dpop_access_token(&request, "minted-token").is_err());

        request
            .insert_header("authorization", "Bearer minted-token")
            .unwrap();
        assert!(final_dpop_access_token(&request, "minted-token").is_err());
    }

    #[test]
    fn malformed_outbound_credential_header_fails_closed() {
        let mut request = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        request
            .insert_header("authorization", "Bearer inbound-token")
            .unwrap();

        assert!(insert_outbound_credential_header(
            &mut request,
            "authorization".to_string(),
            "DPoP invalid\r\nvalue",
        )
        .is_err());
        assert_eq!(
            request.headers.get("authorization").unwrap(),
            "Bearer inbound-token"
        );
    }

    #[test]
    fn realtime_scrub_removes_caller_credentials_but_preserves_websocket_headers() {
        let mut request = pingora_http::RequestHeader::build("GET", b"/v1/realtime", None).unwrap();
        for (name, value) in [
            ("authorization", "Bearer caller-secret"),
            ("proxy-authorization", "Basic caller-secret"),
            ("dpop", "caller-proof"),
            ("x-api-key", "caller-secret"),
            ("api-key", "caller-secret"),
            ("x-goog-api-key", "caller-secret"),
            ("x-sb-api", "caller-secret"),
            ("x-custom-inbound-key", "caller-secret"),
        ] {
            request.insert_header(name, value).unwrap();
        }
        for (name, value) in [
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("openai-beta", "realtime=v1"),
        ] {
            request.insert_header(name, value).unwrap();
        }

        scrub_realtime_credentials(
            &mut request,
            &["x-custom-inbound-key".to_string()],
            &[],
            "authorization",
        );

        for name in [
            "authorization",
            "proxy-authorization",
            "dpop",
            "x-api-key",
            "api-key",
            "x-goog-api-key",
            "x-sb-api",
            "x-custom-inbound-key",
        ] {
            assert!(
                request.headers.get(name).is_none(),
                "{name} must be removed"
            );
        }
        assert_eq!(request.headers.get("upgrade").unwrap(), "websocket");
        assert_eq!(request.headers.get("connection").unwrap(), "Upgrade");
        assert_eq!(
            request.headers.get("sec-websocket-key").unwrap(),
            "dGhlIHNhbXBsZSBub25jZQ=="
        );
        assert_eq!(request.headers.get("openai-beta").unwrap(), "realtime=v1");
    }

    #[test]
    fn realtime_bound_credential_wins_over_provider_auth() {
        let credential = choose_realtime_credential(
            Some(RealtimeCredential {
                header: "authorization".to_string(),
                value: "Bearer bound-secret".to_string(),
            }),
            Some(RealtimeCredential {
                header: "authorization".to_string(),
                value: "Bearer provider-secret".to_string(),
            }),
        )
        .unwrap();

        assert_eq!(credential.header, "authorization");
        assert_eq!(credential.value, "Bearer bound-secret");
    }

    #[test]
    fn realtime_missing_provider_credential_fails_closed() {
        let provider: sbproxy_ai::ProviderConfig = serde_json::from_value(serde_json::json!({
            "name": "openai",
            "api_key": "   "
        }))
        .unwrap();

        let provider_auth = realtime_provider_credential(&provider);
        assert!(provider_auth.is_none(), "blank API keys are unavailable");
        assert!(choose_realtime_credential(None, provider_auth).is_err());
    }

    #[test]
    fn realtime_native_credential_requires_exact_destination_binding() {
        let unbound: sbproxy_ai::ProviderConfig = serde_json::from_value(serde_json::json!({
            "name": "primary",
            "provider_type": "openai",
            "api_key": "operator-key-must-not-be-billed"
        }))
        .unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer sk-caller-owned-canary"),
        );
        let inbound = sbproxy_config::types::KeyInboundConfig::default();

        assert!(
            realtime_native_provider_credential(
                &unbound,
                &headers,
                &inbound.provider_hints,
                "openai",
            )
            .is_none(),
            "wire format alone must not authorize caller-secret forwarding"
        );

        let bound: sbproxy_ai::ProviderConfig = serde_json::from_value(serde_json::json!({
            "name": "primary",
            "provider_type": "openai",
            "api_key": "operator-key-must-not-be-billed",
            "accept_native_credentials_for": "openai"
        }))
        .unwrap();
        let credential = realtime_native_provider_credential(
            &bound,
            &headers,
            &inbound.provider_hints,
            "openai",
        )
        .expect("matching caller credential");
        assert_eq!(credential.header, "Authorization");
        assert_eq!(credential.value, "Bearer sk-caller-owned-canary");
        assert!(!credential.value.contains("operator-key-must-not-be-billed"));
        assert!(realtime_native_provider_credential(
            &bound,
            &headers,
            &inbound.provider_hints,
            "anthropic",
        )
        .is_none());
    }

    fn realtime_pipeline_with_provider_hint(
        header: &str,
        value_prefix: &str,
    ) -> std::sync::Arc<CompiledPipeline> {
        let mut config = sbproxy_config::CompiledConfig::default();
        let mut key_management = sbproxy_config::KeyManagementConfig::default();
        key_management.inbound.headers.clear();
        key_management.inbound.provider_hints = vec![sbproxy_config::ProviderHintConfig {
            provider: "openai".to_string(),
            header: header.to_string(),
            scheme: String::new(),
            value_prefix: value_prefix.to_string(),
            also_header: None,
        }];
        config.server.key_management = Some(key_management);
        std::sync::Arc::new(
            CompiledPipeline::from_config_for_validation(config)
                .expect("compile realtime pipeline"),
        )
    }

    #[test]
    fn realtime_carriers_and_provider_hints_stay_pinned_across_reload() {
        let old_pipeline =
            realtime_pipeline_with_provider_hint("x-native-carrier-a", "old-caller-");
        let new_pipeline =
            realtime_pipeline_with_provider_hint("x-native-carrier-b", "new-caller-");
        let old_ctx = RequestContext {
            pipeline: std::sync::Arc::clone(&old_pipeline),
            ..RequestContext::default()
        };

        let carriers = realtime_inbound_carrier_names(&old_ctx);
        assert!(carriers.iter().any(|name| name == "x-native-carrier-a"));
        assert!(!carriers.iter().any(|name| name == "x-native-carrier-b"));

        let provider: sbproxy_ai::ProviderConfig = serde_json::from_value(serde_json::json!({
            "name": "primary",
            "provider_type": "openai",
            "api_key": "operator-key-must-not-be-billed",
            "accept_native_credentials_for": "openai"
        }))
        .unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-native-carrier-a",
            http::HeaderValue::from_static("old-caller-credential"),
        );

        let credential = realtime_native_provider_credential_for_pipeline(
            &provider,
            &headers,
            &old_pipeline,
            "openai",
        )
        .expect("old pipeline resolves its own provider hint");
        assert_eq!(credential.value, "Bearer old-caller-credential");
        assert!(
            realtime_native_provider_credential_for_pipeline(
                &provider,
                &headers,
                &new_pipeline,
                "openai",
            )
            .is_none(),
            "new pipeline hints must not change an old request"
        );
    }

    #[test]
    fn realtime_final_credential_overwrites_lua_authorization() {
        let mut request = pingora_http::RequestHeader::build("GET", b"/v1/realtime", None).unwrap();
        request
            .insert_header("authorization", "Bearer lua-secret")
            .unwrap();

        apply_realtime_credential(
            &mut request,
            &RealtimeCredential {
                header: "authorization".to_string(),
                value: "Bearer provider-secret".to_string(),
            },
            &[],
            &[],
        )
        .unwrap();

        let mut values = request.headers.get_all(http::header::AUTHORIZATION).iter();
        assert_eq!(values.next().unwrap(), "Bearer provider-secret");
        assert!(values.next().is_none());
    }

    #[test]
    fn realtime_final_credential_scrubs_all_custom_carriers_case_insensitively() {
        let mut request = pingora_http::RequestHeader::build("GET", b"/v1/realtime", None).unwrap();
        for (name, value) in [
            ("x-custom-inbound", "caller-secret"),
            ("x-custom-provider", "caller-provider-secret"),
            ("x-custom-bound", "lua-bound-secret"),
            ("openai-beta", "realtime=v1"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ] {
            request.insert_header(name, value).unwrap();
        }
        request
            .append_header("X-Custom-Provider", "lua-provider-secret")
            .unwrap();

        apply_realtime_credential(
            &mut request,
            &RealtimeCredential {
                header: "X-Custom-Bound".to_string(),
                value: "bound-secret".to_string(),
            },
            &["X-CUSTOM-INBOUND".to_string()],
            &[
                "X-CUSTOM-PROVIDER".to_string(),
                "x-custom-bound".to_string(),
            ],
        )
        .unwrap();

        assert!(request.headers.get("x-custom-inbound").is_none());
        assert!(request.headers.get("x-custom-provider").is_none());
        let mut bound_values = request.headers.get_all("x-custom-bound").iter();
        assert_eq!(bound_values.next().unwrap(), "bound-secret");
        assert!(bound_values.next().is_none());
        assert_eq!(request.headers.get("openai-beta").unwrap(), "realtime=v1");
        assert_eq!(
            request.headers.get("sec-websocket-key").unwrap(),
            "dGhlIHNhbXBsZSBub25jZQ=="
        );
    }

    #[test]
    fn realtime_carriers_include_the_origin_resolver_presentation_header() {
        let cases = [
            (
                serde_json::json!({
                    "type": "token_exchange",
                    "token_endpoint": "https://issuer.example/token",
                    "audience": "https://api.example"
                }),
                "authorization",
            ),
            (
                serde_json::json!({
                    "type": "client_credentials",
                    "token_endpoint": "https://issuer.example/token",
                    "client_id": "client",
                    "client_secret": "secret"
                }),
                "authorization",
            ),
            (
                serde_json::json!({
                    "type": "vault_secret",
                    "secret": "secret",
                    "header": "X-Origin-Secret"
                }),
                "x-origin-secret",
            ),
        ];

        for (config, expected_header) in cases {
            let config = serde_json::from_value(config).unwrap();
            assert_eq!(
                realtime_credential_headers(None, None, Some(&config)),
                [expected_header]
            );
        }
    }

    #[test]
    fn realtime_rejects_protocol_and_proxy_owned_credential_headers() {
        for header in [
            "OpenAI-Beta",
            "SEC-WebSocket-Key",
            "Upgrade",
            "TraceParent",
            "TRACESTATE",
            "Signature-Input",
            "Signature",
            "Signature-Agent",
        ] {
            let mut request =
                pingora_http::RequestHeader::build("GET", b"/v1/realtime", None).unwrap();
            let result = apply_realtime_credential(
                &mut request,
                &RealtimeCredential {
                    header: header.to_string(),
                    value: "provider-secret".to_string(),
                },
                &[],
                &[],
            );

            assert!(result.is_err(), "{header} must fail closed");
        }
    }

    #[test]
    fn realtime_session_accounting_requires_a_101_handshake() {
        let dispatch = || {
            Some(crate::context::RealtimeDispatchCtx {
                provider_name: "openai".to_string(),
                upstream_host: "api.openai.com".to_string(),
                upstream_port: 443,
                upstream_tls: true,
                model_override: None,
                started_at: std::time::Instant::now(),
                surface_label: "realtime",
            })
        };

        let mut rejected = dispatch();
        assert!(take_accepted_realtime_dispatch(&mut rejected, 401).is_none());
        assert!(rejected.is_none(), "failed dispatch state must be consumed");

        let mut accepted = dispatch();
        assert!(take_accepted_realtime_dispatch(&mut accepted, 101).is_some());
        assert!(
            accepted.is_none(),
            "accepted dispatch state must be consumed"
        );
    }

    #[test]
    fn origin_dpop_rejects_a_bound_credential_override() {
        let error = ensure_dpop_credential_source(Some("bound-credential"), true)
            .expect_err("bound credentials cannot silently bypass origin DPoP");
        assert!(error
            .to_string()
            .contains("bound credential cannot satisfy origin DPoP"));

        ensure_dpop_credential_source(None, true).unwrap();
        ensure_dpop_credential_source(Some("bound-credential"), false).unwrap();
    }

    fn target_selection(
        target_index: usize,
        selection_method: &str,
    ) -> sbproxy_modules::action::TargetSelection {
        sbproxy_modules::action::TargetSelection {
            host: format!("target-{target_index}.example.com"),
            port: 443,
            tls: true,
            target_index,
            selection_method: selection_method.to_string(),
        }
    }

    fn pending_compression_value() -> sbproxy_ai::PendingCompressionValue {
        let run = sbproxy_ai::compression::CompressionRun {
            messages: Vec::new(),
            initial_tokens: 20,
            final_tokens: 10,
            tokens_saved: 10,
            token_count_precision: sbproxy_ai::TokenCountPrecision::ModelTokenizer,
            lever_results: vec![sbproxy_ai::compression::LeverResult {
                lever: sbproxy_ai::compression::LeverKind::WindowFit,
                backend: None,
                outcome: sbproxy_ai::compression::LeverOutcome::Applied,
                before_tokens: 20,
                after_tokens: 10,
                tokens_saved: 10,
                duration: std::time::Duration::from_millis(1),
            }],
        };
        sbproxy_ai::PendingCompressionValue::from_run("gpt-4o", &run)
            .expect("pending compression value")
    }

    fn timeout_retry_cfg(
        retry_on: &[&str],
        max_attempts: u32,
    ) -> sbproxy_modules::action::RetryConfig {
        sbproxy_modules::action::RetryConfig {
            max_attempts,
            retry_on: retry_on.iter().map(|s| s.to_string()).collect(),
            backoff_ms: 0,
        }
    }

    fn lifecycle_load_balancer_action(target_urls: &[&str], open_duration_secs: u64) -> Action {
        let targets = target_urls
            .iter()
            .map(|url| serde_json::json!({ "url": url }))
            .collect::<Vec<_>>();
        sbproxy_modules::compile_action(&serde_json::json!({
            "type": "load_balancer",
            "targets": targets,
            "circuit_breaker": {
                "failure_threshold": 1,
                "success_threshold": 1,
                "open_duration_secs": open_duration_secs
            },
            "outlier_detection": {
                "threshold": 0.5,
                "window_secs": 60,
                "min_requests": 1,
                "ejection_duration_secs": 60
            }
        }))
        .unwrap()
    }

    fn lifecycle_pipeline_with_breaker_duration(
        open_duration_secs: u64,
    ) -> std::sync::Arc<CompiledPipeline> {
        let mut pipeline = CompiledPipeline::default();
        pipeline.actions.push(lifecycle_load_balancer_action(
            &["http://main-a:8080", "http://main-b:8080"],
            open_duration_secs,
        ));
        pipeline
            .forward_rules
            .push(vec![crate::pipeline::CompiledForwardRule {
                matchers: Vec::new(),
                action: lifecycle_load_balancer_action(
                    &["http://forward-a:8080", "http://forward-b:8080"],
                    open_duration_secs,
                ),
                request_modifiers: Vec::new(),
                parameters: Vec::new(),
            }]);
        std::sync::Arc::new(pipeline)
    }

    fn lifecycle_pipeline() -> std::sync::Arc<CompiledPipeline> {
        lifecycle_pipeline_with_breaker_duration(60)
    }

    fn load_balancer(action: &Action) -> std::sync::Arc<sbproxy_modules::LoadBalancerAction> {
        match action {
            Action::LoadBalancer(load_balancer) => std::sync::Arc::clone(load_balancer),
            other => panic!("expected load balancer, got {other:?}"),
        }
    }

    fn breaker_state(
        load_balancer: &sbproxy_modules::LoadBalancerAction,
        target_index: usize,
    ) -> sbproxy_platform::CircuitState {
        load_balancer.circuit_breakers.as_ref().unwrap()[target_index].state()
    }

    #[test]
    fn retry_finishes_the_previous_attempt_before_selecting_a_replacement() {
        let pipeline = lifecycle_pipeline();
        let main = load_balancer(&pipeline.actions[0]);
        let mut ctx = RequestContext {
            pipeline: std::sync::Arc::clone(&pipeline),
            ..RequestContext::default()
        };
        let action = LoadBalancerActionKey::new(0, None);

        begin_load_balancer_attempt(&mut ctx, action, &target_selection(0, "bandit"));
        finish_load_balancer_attempt(&mut ctx, LoadBalancerAttemptOutcome::Failure);
        begin_load_balancer_attempt(&mut ctx, action, &target_selection(1, "bandit"));

        assert_eq!(main.connection_count(0), 0);
        assert_eq!(main.connection_count(1), 1);
        assert_eq!(
            breaker_state(&main, 0),
            sbproxy_platform::CircuitState::Open,
            "the failed retry attempt must train its own breaker",
        );
    }

    #[test]
    fn selection_replacement_disconnects_an_unfinished_attempt_without_training_it() {
        let pipeline = lifecycle_pipeline();
        let main = load_balancer(&pipeline.actions[0]);
        let mut ctx = RequestContext {
            pipeline: std::sync::Arc::clone(&pipeline),
            ..RequestContext::default()
        };
        let action = LoadBalancerActionKey::new(0, None);

        begin_load_balancer_attempt(&mut ctx, action, &target_selection(0, "bandit"));
        begin_load_balancer_attempt(&mut ctx, action, &target_selection(1, "bandit"));

        assert_eq!(main.connection_count(0), 0);
        assert_eq!(main.connection_count(1), 1);
        assert_eq!(
            breaker_state(&main, 0),
            sbproxy_platform::CircuitState::Closed
        );
        assert!(
            !main
                .outlier_detector
                .as_ref()
                .unwrap()
                .is_ejected(&main.target_id(0)),
            "replacement cleanup is neutral, not a fabricated failure"
        );
    }

    #[test]
    fn forward_rule_success_cleans_up_its_own_attempt() {
        let pipeline = lifecycle_pipeline_with_breaker_duration(0);
        let main = load_balancer(&pipeline.actions[0]);
        let forward = load_balancer(&pipeline.forward_rules[0][0].action);
        let mut ctx = RequestContext {
            pipeline: std::sync::Arc::clone(&pipeline),
            ..RequestContext::default()
        };
        forward.record_breaker_failure(0);
        assert_eq!(
            breaker_state(&forward, 0),
            sbproxy_platform::CircuitState::HalfOpen
        );

        begin_load_balancer_attempt(
            &mut ctx,
            LoadBalancerActionKey::new(0, Some(0)),
            &target_selection(0, "bandit"),
        );
        finish_load_balancer_attempt(&mut ctx, LoadBalancerAttemptOutcome::Success);

        assert_eq!(forward.connection_count(0), 0);
        assert_eq!(main.connection_count(0), 0);
        assert_eq!(
            breaker_state(&forward, 0),
            sbproxy_platform::CircuitState::Closed,
            "success must close the forward rule's half-open breaker"
        );
        assert!(ctx.lb_attempt.is_none());
    }

    #[test]
    fn forward_rule_failure_updates_its_own_breaker_and_outlier() {
        let pipeline = lifecycle_pipeline();
        let main = load_balancer(&pipeline.actions[0]);
        let forward = load_balancer(&pipeline.forward_rules[0][0].action);
        let mut ctx = RequestContext {
            pipeline: std::sync::Arc::clone(&pipeline),
            ..RequestContext::default()
        };

        begin_load_balancer_attempt(
            &mut ctx,
            LoadBalancerActionKey::new(0, Some(0)),
            &target_selection(0, "bandit"),
        );
        finish_load_balancer_attempt(&mut ctx, LoadBalancerAttemptOutcome::Failure);

        assert_eq!(forward.connection_count(0), 0);
        assert_eq!(
            breaker_state(&forward, 0),
            sbproxy_platform::CircuitState::Open
        );
        assert!(forward
            .outlier_detector
            .as_ref()
            .unwrap()
            .is_ejected(&forward.target_id(0)));
        assert_eq!(
            breaker_state(&main, 0),
            sbproxy_platform::CircuitState::Closed
        );
        assert!(!main
            .outlier_detector
            .as_ref()
            .unwrap()
            .is_ejected(&main.target_id(0)));
    }

    #[test]
    fn terminal_attempt_cleanup_is_exactly_once_without_counter_underflow() {
        let pipeline = lifecycle_pipeline();
        let main = load_balancer(&pipeline.actions[0]);
        let mut ctx = RequestContext {
            pipeline: std::sync::Arc::clone(&pipeline),
            ..RequestContext::default()
        };

        begin_load_balancer_attempt(
            &mut ctx,
            LoadBalancerActionKey::new(0, None),
            &target_selection(0, "bandit"),
        );
        finish_load_balancer_attempt(&mut ctx, LoadBalancerAttemptOutcome::Success);
        finish_load_balancer_attempt(&mut ctx, LoadBalancerAttemptOutcome::Failure);

        assert_eq!(main.connection_count(0), 0);
        assert!(ctx.lb_attempt.is_none());
        assert_eq!(
            breaker_state(&main, 0),
            sbproxy_platform::CircuitState::Closed,
            "the second cleanup must not record a second outcome"
        );
        assert!(!main
            .outlier_detector
            .as_ref()
            .unwrap()
            .is_ejected(&main.target_id(0)));
    }

    #[test]
    fn downstream_errors_do_not_train_a_healthy_upstream_as_failed() {
        let pipeline = lifecycle_pipeline();
        let main = load_balancer(&pipeline.actions[0]);
        let mut ctx = RequestContext {
            pipeline: std::sync::Arc::clone(&pipeline),
            ..RequestContext::default()
        };
        begin_load_balancer_attempt(
            &mut ctx,
            LoadBalancerActionKey::new(0, None),
            &target_selection(0, "bandit"),
        );
        let downstream_outcome =
            terminal_load_balancer_attempt_outcome(200, Some(&ErrorSource::Downstream));
        finish_load_balancer_attempt(&mut ctx, downstream_outcome);

        assert_eq!(main.connection_count(0), 0);
        assert_eq!(
            breaker_state(&main, 0),
            sbproxy_platform::CircuitState::Closed
        );
        assert!(!main
            .outlier_detector
            .as_ref()
            .unwrap()
            .is_ejected(&main.target_id(0)));
        assert_eq!(downstream_outcome, LoadBalancerAttemptOutcome::Neutral);
        assert_eq!(
            terminal_load_balancer_attempt_outcome(200, Some(&ErrorSource::Upstream)),
            LoadBalancerAttemptOutcome::Failure
        );
        assert_eq!(
            terminal_load_balancer_attempt_outcome(200, None),
            LoadBalancerAttemptOutcome::Success
        );
        assert_eq!(
            terminal_load_balancer_attempt_outcome(503, Some(&ErrorSource::Downstream)),
            LoadBalancerAttemptOutcome::Failure,
            "a downstream write error must not erase an upstream 5xx"
        );
    }

    #[test]
    fn attempt_feedback_uses_observed_upstream_status_not_rewritten_downstream_status() {
        let pipeline = lifecycle_pipeline();
        let main = load_balancer(&pipeline.actions[0]);
        let mut ctx = RequestContext {
            pipeline: std::sync::Arc::clone(&pipeline),
            ..RequestContext::default()
        };
        let action = LoadBalancerActionKey::new(0, None);

        begin_load_balancer_attempt(&mut ctx, action, &target_selection(0, "bandit"));
        let upstream_ok = pingora_http::ResponseHeader::build(200, None).unwrap();
        capture_load_balancer_upstream_response(&mut ctx, &upstream_ok);
        ctx.response_status = Some(503);
        finish_terminal_load_balancer_attempt(&mut ctx, Some(&ErrorSource::Downstream));

        assert_eq!(main.connection_count(0), 0);
        assert_eq!(
            breaker_state(&main, 0),
            sbproxy_platform::CircuitState::Closed,
            "a downstream 5xx rewrite must not train an observed upstream 200 as failed"
        );
        assert!(!main
            .outlier_detector
            .as_ref()
            .unwrap()
            .is_ejected(&main.target_id(0)));

        begin_load_balancer_attempt(&mut ctx, action, &target_selection(1, "bandit"));
        let upstream_failure = pingora_http::ResponseHeader::build(503, None).unwrap();
        capture_load_balancer_upstream_response(&mut ctx, &upstream_failure);
        ctx.response_status = Some(200);
        finish_terminal_load_balancer_attempt(&mut ctx, None);

        assert_eq!(main.connection_count(1), 0);
        assert_eq!(
            breaker_state(&main, 1),
            sbproxy_platform::CircuitState::Open,
            "a downstream 2xx rewrite must not erase an observed upstream 503"
        );
        assert!(main
            .outlier_detector
            .as_ref()
            .unwrap()
            .is_ejected(&main.target_id(1)));
    }

    #[test]
    fn deferred_strategy_selection_records_the_builtin_algorithm() {
        let pipeline = lifecycle_pipeline();
        let mut ctx = RequestContext {
            pipeline: std::sync::Arc::clone(&pipeline),
            ..RequestContext::default()
        };
        let selection = target_selection(0, "round_robin");

        begin_load_balancer_attempt(&mut ctx, LoadBalancerActionKey::new(0, None), &selection);

        assert_eq!(
            ctx.admin_load_balancer_strategy.as_deref(),
            Some("round_robin")
        );
        assert_eq!(
            ctx.admin_load_balancer_target.as_deref(),
            Some("target-0.example.com:443")
        );
        finish_load_balancer_attempt(&mut ctx, LoadBalancerAttemptOutcome::Neutral);
    }

    #[test]
    fn timeout_retry_allows_upstream_timeouts_under_the_policy() {
        let cfg = timeout_retry_cfg(&["timeout"], 3);

        assert_eq!(
            maybe_retry_upstream_timeout(
                &cfg,
                &ErrorType::ReadTimedout,
                &ErrorSource::Upstream,
                0,
                false,
                None,
            ),
            Some("upstream")
        );
        assert_eq!(
            maybe_retry_upstream_timeout(
                &cfg,
                &ErrorType::WriteTimedout,
                &ErrorSource::Upstream,
                1,
                false,
                None,
            ),
            Some("upstream")
        );
    }

    #[test]
    fn timeout_retry_classifies_connect_phase_timeouts() {
        let cfg = timeout_retry_cfg(&["timeout"], 3);

        assert_eq!(
            maybe_retry_upstream_timeout(
                &cfg,
                &ErrorType::ConnectTimedout,
                &ErrorSource::Upstream,
                0,
                false,
                None,
            ),
            Some("connect")
        );
        assert_eq!(
            timeout_error_phase(&ErrorType::TLSHandshakeTimedout),
            Some("connect")
        );
    }

    #[test]
    fn timeout_retry_requires_the_timeout_token() {
        for retry_on in [&["connect_error"][..], &["502", "503"][..]] {
            let cfg = timeout_retry_cfg(retry_on, 3);
            assert_eq!(
                maybe_retry_upstream_timeout(
                    &cfg,
                    &ErrorType::ReadTimedout,
                    &ErrorSource::Upstream,
                    0,
                    false,
                    None,
                ),
                None,
                "retry_on {retry_on:?} must not enable timeout retries"
            );
        }
    }

    #[test]
    fn timeout_retry_enforces_the_shared_attempt_cap() {
        // max_attempts: 2 permits exactly one retry: retries_used 0
        // passes, 1 is the cap. 1 total attempt disables retries.
        let cfg = timeout_retry_cfg(&["timeout"], 2);
        assert!(maybe_retry_upstream_timeout(
            &cfg,
            &ErrorType::ReadTimedout,
            &ErrorSource::Upstream,
            0,
            false,
            None,
        )
        .is_some());
        assert_eq!(
            maybe_retry_upstream_timeout(
                &cfg,
                &ErrorType::ReadTimedout,
                &ErrorSource::Upstream,
                1,
                false,
                None,
            ),
            None
        );
        let disabled = timeout_retry_cfg(&["timeout"], 1);
        assert_eq!(
            maybe_retry_upstream_timeout(
                &disabled,
                &ErrorType::ReadTimedout,
                &ErrorSource::Upstream,
                0,
                false,
                None,
            ),
            None
        );
    }

    #[test]
    fn timeout_retry_leaves_non_timeout_errors_untouched() {
        let cfg = timeout_retry_cfg(&["timeout"], 3);
        for etype in [
            ErrorType::ConnectionClosed,
            ErrorType::ReadError,
            ErrorType::WriteError,
            ErrorType::ConnectRefused,
            ErrorType::HTTPStatus(504),
        ] {
            assert_eq!(
                maybe_retry_upstream_timeout(&cfg, &etype, &ErrorSource::Upstream, 0, false, None),
                None,
                "{etype:?} is not a timeout and must never schedule a timeout retry"
            );
        }
    }

    #[test]
    fn timeout_retry_requires_the_upstream_leg() {
        let cfg = timeout_retry_cfg(&["timeout"], 3);
        for esource in [
            ErrorSource::Downstream,
            ErrorSource::Internal,
            ErrorSource::Unset,
        ] {
            assert_eq!(
                maybe_retry_upstream_timeout(
                    &cfg,
                    &ErrorType::ReadTimedout,
                    &esource,
                    0,
                    false,
                    None,
                ),
                None,
                "{esource:?} timeouts are not upstream failures"
            );
        }
    }

    #[test]
    fn timeout_retry_blocks_once_the_response_started_downstream() {
        let cfg = timeout_retry_cfg(&["timeout"], 3);
        assert_eq!(
            maybe_retry_upstream_timeout(
                &cfg,
                &ErrorType::ReadTimedout,
                &ErrorSource::Upstream,
                0,
                true,
                None,
            ),
            None,
            "bytes already written downstream can never be recalled"
        );
    }

    #[test]
    fn timeout_retry_blocks_unreplayable_requests() {
        let cfg = timeout_retry_cfg(&["timeout"], 3);
        assert_eq!(
            maybe_retry_upstream_timeout(
                &cfg,
                &ErrorType::ReadTimedout,
                &ErrorSource::Upstream,
                0,
                false,
                Some("non_idempotent_method"),
            ),
            None,
            "a request that already reached the upstream must pass the replay gate"
        );
    }

    #[test]
    fn parsed_upstream_url_extracts_host_scheme_and_path() {
        let info = parsed_upstream_url("https://api.example.com:8443/v1/base");
        assert_eq!(info.host.as_deref(), Some("api.example.com"));
        assert_eq!(info.scheme.as_deref(), Some("https"));
        assert_eq!(info.path, "/v1/base");
    }

    #[test]
    fn parsed_upstream_url_handles_no_path_and_bad_url() {
        // Root path stays "/" (the base-path guard treats it as "no prefix").
        assert_eq!(parsed_upstream_url("http://host").path, "/");
        // A URL that does not parse yields no host and an empty path, so
        // the call sites behave exactly as the old `.ok()` handling did.
        let bad = parsed_upstream_url("not a url");
        assert!(bad.host.is_none());
        assert!(bad.path.is_empty());
    }

    #[test]
    fn parsed_upstream_url_memoizes_repeated_lookups() {
        let a = parsed_upstream_url("https://memo.example.com/x");
        let b = parsed_upstream_url("https://memo.example.com/x");
        // A cache hit returns the same Arc, not a fresh parse.
        assert!(std::sync::Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn final_response_status_falls_back_to_written_header() {
        let ctx = RequestContext::default();
        let header = pingora_http::ResponseHeader::build(200, None).unwrap();

        assert_eq!(final_response_status(&ctx, Some(&header)), 200);
    }

    #[test]
    fn final_response_status_prefers_context_status() {
        let mut ctx = RequestContext {
            response_status: Some(429),
            ..RequestContext::default()
        };
        let header = pingora_http::ResponseHeader::build(200, None).unwrap();

        assert_eq!(final_response_status(&ctx, Some(&header)), 429);
        ctx.response_status = None;
        assert_eq!(final_response_status(&ctx, None), 0);
    }

    #[test]
    fn compression_value_requires_a_terminal_provider_success() {
        assert!(is_billable_provider_success(200, Some("openai")));
        assert!(is_billable_provider_success(299, Some("local")));
        assert!(!is_billable_provider_success(302, Some("openai")));
        assert!(!is_billable_provider_success(429, Some("openai")));
        assert!(!is_billable_provider_success(200, None));
    }

    #[test]
    fn terminal_success_realizes_pending_compression_value_exactly_once() {
        let mut ctx = RequestContext {
            ai_provider: Some("openai".to_string()),
            pending_compression_value: Some(pending_compression_value()),
            ..RequestContext::default()
        };

        let realized = take_realized_compression_value(&mut ctx, 200, false);

        assert!(realized.is_some());
        assert!(ctx.pending_compression_value.is_none());
        assert!(take_realized_compression_value(&mut ctx, 200, false).is_none());
    }

    #[test]
    fn terminal_failure_consumes_pending_compression_value_without_realizing_it() {
        let mut ctx = RequestContext {
            ai_provider: Some("openai".to_string()),
            pending_compression_value: Some(pending_compression_value()),
            ..RequestContext::default()
        };

        let realized = take_realized_compression_value(&mut ctx, 500, false);

        assert!(realized.is_none());
        assert!(ctx.pending_compression_value.is_none());
    }

    #[test]
    fn fatal_error_after_success_headers_consumes_value_without_realizing_it() {
        let mut ctx = RequestContext {
            ai_provider: Some("openai".to_string()),
            pending_compression_value: Some(pending_compression_value()),
            ..RequestContext::default()
        };

        let realized = take_realized_compression_value(&mut ctx, 200, true);

        assert!(realized.is_none());
        assert!(ctx.pending_compression_value.is_none());
    }

    // --- The decision-audit gate (WOR-2405) ---

    /// One static origin, so every `decision_audit` fixture below has
    /// something to compile around.
    const AUDIT_ORIGIN_YAML: &str = r#"
origins:
  "api.example.com":
    action:
      type: static
      body: placeholder
"#;

    /// Compile a `proxy:` block plus [`AUDIT_ORIGIN_YAML`] into a
    /// pipeline. An empty `proxy_yaml` is the config of an operator who
    /// never wrote the key at all.
    ///
    /// Validation mode because these fixtures are read and dropped:
    /// `audit_publishes` only asks the compiled config a question, so
    /// there is nothing here that wants a cache directory or a
    /// background task.
    fn audit_pipeline(proxy_yaml: &str) -> CompiledPipeline {
        let config = sbproxy_config::compile_config(&format!("{proxy_yaml}{AUDIT_ORIGIN_YAML}"))
            .expect("fixture config");
        CompiledPipeline::from_config_for_validation(config).expect("fixture pipeline")
    }

    #[test]
    fn an_absent_decision_audit_block_publishes_nothing() {
        use sbproxy_observe::decision::DecisionEvent;

        // The default every deployment that has not asked for an audit
        // feed is running. `audit_publishes` is the only read of the
        // compiled block anywhere in this workspace, so a version that
        // answered `true` here would turn a per-request SIEM feed on for
        // everybody and every other test in this file would stay green.

        // No `proxy:` block at all.
        let never_written = audit_pipeline("");
        // A log block that mentions everything except the audit key.
        let log_without_audit = audit_pipeline(
            r#"proxy:
  http_bind_port: 8080
  observability:
    log:
      level: info
"#,
        );

        for event in [
            DecisionEvent::CacheAdmit,
            DecisionEvent::CacheKey,
            DecisionEvent::RouteDecide,
            DecisionEvent::Policy,
        ] {
            assert!(
                !(audit_publishes(&never_written, event, None, None)),
                "a config with no decision_audit block publishes nothing, and `{}` is not \
                 an exception",
                event.as_label()
            );
            assert!(
                !(audit_publishes(&log_without_audit, event, None, None)),
                "a log block that never mentions decision_audit must not synthesize one; \
                 `{}` stays off",
                event.as_label()
            );
        }
    }

    #[test]
    fn audit_publishes_reads_the_precedence_the_config_type_defines() {
        use sbproxy_observe::decision::DecisionEvent;

        // The gate that stands in front of the chokepoint. Three
        // readings have to survive the seam: the master switch reaches
        // an event the `events:` map does not name, a per-event entry
        // wins over the master switch in both directions, and
        // `ai.stream.event` stays off however the block is written.
        // Getting any of them wrong here would silence a feed the
        // operator turned on, or bill them for one they did not.

        let master_on = audit_pipeline(
            r#"proxy:
  http_bind_port: 8080
  observability:
    log:
      decision_audit:
        enabled: true
"#,
        );
        assert!(
            (audit_publishes(&master_on, DecisionEvent::CacheAdmit, None, None)),
            "the master switch has to reach an event the events map does not name"
        );
        assert!(
            !(audit_publishes(&master_on, DecisionEvent::AiStreamEvent, None, None)),
            "`ai.stream.event` fires once per streamed chunk and never publishes, whatever \
             the master switch says"
        );

        let per_event_only = audit_pipeline(
            r#"proxy:
  http_bind_port: 8080
  observability:
    log:
      decision_audit:
        events:
          cache.admit: true
"#,
        );
        assert!(
            (audit_publishes(&per_event_only, DecisionEvent::CacheAdmit, None, None)),
            "a per-event entry publishes without a master switch"
        );
        assert!(
            !(audit_publishes(&per_event_only, DecisionEvent::RouteDecide, None, None)),
            "an unset master switch is off, so naming one event must not turn on the rest"
        );

        let event_opted_out = audit_pipeline(
            r#"proxy:
  http_bind_port: 8080
  observability:
    log:
      decision_audit:
        enabled: true
        events:
          cache.admit: false
"#,
        );
        assert!(
            !(audit_publishes(&event_opted_out, DecisionEvent::CacheAdmit, None, None)),
            "a per-event `false` wins over the master switch"
        );
        assert!(
            (audit_publishes(&event_opted_out, DecisionEvent::RouteDecide, None, None)),
            "silencing one event must not silence the master switch for the others"
        );
    }

    /// A **wildcard** origin, so the configured origin id and the
    /// request's `Host` are different strings.
    ///
    /// `CompiledOrigin::origin_id` is built from the origin's config
    /// key, so in every non-wildcard config the two hold the same bytes
    /// and a swap at the emit site is invisible. A wildcard key is the
    /// one shape where they diverge: the id is the pattern, the `Host`
    /// is a concrete name under it.
    ///
    /// The script refuses the store so the emit site runs on the arm
    /// that publishes, and its `reason` is what the record has to carry.
    const WILDCARD_AUDIT_ORIGIN_YAML: &str = r#"
origins:
  "*.wildcard.example":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    response_cache:
      enabled: true
      admit_event:
        engine: lua
        source: "return {store = false, reason = 'declined by rule R-7'}"
"#;

    /// A context for [`WILDCARD_AUDIT_ORIGIN_YAML`] whose `Host` is a
    /// concrete name under the pattern.
    fn wildcard_admit_ctx(proxy_yaml: &str, request_id: &str) -> RequestContext {
        let config =
            sbproxy_config::compile_config(&format!("{proxy_yaml}{WILDCARD_AUDIT_ORIGIN_YAML}"))
                .expect("fixture config");
        let pipeline =
            CompiledPipeline::from_config_for_validation(config).expect("fixture pipeline");
        let mut ctx = RequestContext::new();
        ctx.pipeline = std::sync::Arc::new(pipeline);
        ctx.origin_idx = Some(0);
        ctx.hostname = compact_str::CompactString::new("api.wildcard.example");
        ctx.tenant_id = compact_str::CompactString::new("acme-corp");
        ctx.request_id = compact_str::CompactString::new(request_id);
        ctx.request_path = compact_str::CompactString::new("/v1/thing");
        ctx
    }

    #[test]
    fn the_emit_site_names_the_origin_id_and_publishes_only_when_the_config_asks() {
        // The call site, driven end to end. Everything else about this
        // family can be green with the six lines in `evaluate_cache_admit`
        // deleted: the constructor has tests, the bus has tests, the
        // config parser has tests, and `audit_publishes` now has tests.
        // This is the one that reads a record off the bus that only the
        // emit site could have put there.
        //
        // Two properties, and the first is the transposition
        // `RedactedReason::redact`'s rustdoc warns about. `origin_id`
        // names the record; `route` picks the operator's PII scope.
        // Hand them over the wrong way round and the record still
        // publishes, still validates, still reaches the SIEM, and the
        // origin-scoped redactor is silently skipped. The wildcard
        // fixture is what makes the swap observable at all.
        let (bus, mut rx) = crate::policy_bus::channel(8);
        // A sibling test in this binary may have installed a bus first.
        // Under nextest, which is how the gate and CI run this lane,
        // each test is its own process and this one wins.
        let _ = crate::policy_bus::init_global_bus(bus);

        let ctx = wildcard_admit_ctx(
            r#"proxy:
  http_bind_port: 8080
  observability:
    log:
      decision_audit:
        events:
          cache.admit: true
"#,
            "req-wildcard-audit-on",
        );
        let plan = evaluate_cache_admit(&ctx, 200, &[], 2);
        assert!(
            !plan.store,
            "the fixture script refuses the store, so the emit site runs on the arm that \
             publishes"
        );

        // The bus carries policy verdicts as well, so a record that is
        // not our decision is somebody else's traffic and is skipped
        // rather than failing the read.
        let mut ours = None;
        while let Ok(record) = rx.try_recv() {
            if let crate::policy_bus::AuditRecord::Decision(audit) = record {
                if audit.request_id == "req-wildcard-audit-on" {
                    ours = Some(audit);
                    break;
                }
            }
        }
        let audit = ours.expect(
            "a config that names cache.admit has to publish; a silent miss here is exactly \
             the hole this test exists to close",
        );

        assert_eq!(
            audit.origin, "*.wildcard.example",
            "the record carries the configured origin id. `api.wildcard.example` here means \
             the emit site was handed `ctx.hostname` in the `origin_id` slot, which also \
             hands the origin id to `route` and silently skips the operator's origin-scoped \
             PII rules"
        );
        assert_eq!(audit.tenant, "acme-corp");
        assert_eq!(
            audit.event,
            sbproxy_observe::decision::DecisionEvent::CacheAdmit
        );
        assert_eq!(
            audit.outcome,
            sbproxy_observe::decision::DecisionOutcome::Deny,
            "a refused store is a Deny, and the metric and the record have to agree"
        );
        assert!(
            audit.reason.as_str().contains("declined by rule R-7"),
            "the script's rationale is the payload; a record that only says a response was \
             not cached is not an investigation: {}",
            audit.reason.as_str()
        );

        // And the gate is read here rather than only in isolation. Same
        // origin, same script, no `decision_audit:` block anywhere.
        let ctx = wildcard_admit_ctx("", "req-wildcard-audit-off");
        let plan = evaluate_cache_admit(&ctx, 200, &[], 2);
        assert!(
            !plan.store,
            "the cache decision itself does not depend on whether it is audited"
        );
        while let Ok(record) = rx.try_recv() {
            if let crate::policy_bus::AuditRecord::Decision(audit) = record {
                assert_ne!(
                    audit.request_id, "req-wildcard-audit-off",
                    "a config with no decision_audit block published a record anyway"
                );
            }
        }
    }
}
