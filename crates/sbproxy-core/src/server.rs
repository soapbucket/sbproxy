//! Pingora server setup and ProxyHttp implementation.
//!
//! `SbProxy` implements Pingora's `ProxyHttp` trait. For each request it:
//! 1. Extracts the hostname from the Host header (in request_filter)
//! 2. Handles CORS preflight requests (before auth)
//! 3. Runs auth checks and policy enforcement
//! 4. Handles non-proxy actions directly (redirect, static, echo, mock, beacon, noop)
//! 5. For proxy actions, resolves the upstream peer in upstream_peer
//! 6. Applies request modifiers before sending to upstream (upstream_request_filter)
//! 7. Applies CORS, HSTS, security headers, and response modifiers (response_filter)

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use pingora_core::protocols::l4::ext::TcpKeepalive;
use pingora_core::upstreams::peer::{HttpPeer, ALPN};
use pingora_error::{Error, ErrorType, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{FailToProxy, ProxyHttp, Session};
use tracing::{debug, warn};

use crate::context::RequestContext;
use crate::pipeline::CompiledPipeline;
use crate::reload;
use sbproxy_ai::{AiClient, AiHandlerConfig, Router as AiRouter};
use sbproxy_modules::action::ForwardingHeaderControls;
use sbproxy_modules::{Action, Auth, Policy, RateLimitInfo, WafResult};
use sbproxy_observe::metrics;

/// Lazily-initialized global AI client (shared across all requests).
static AI_CLIENT: std::sync::LazyLock<AiClient> = std::sync::LazyLock::new(AiClient::new);

/// Process-wide AI budget tracker. Accumulates token and cost usage
/// across every AI proxy request and is consulted before each
/// upstream dispatch to enforce the configured budget limits.
static BUDGET_TRACKER: std::sync::LazyLock<sbproxy_ai::BudgetTracker> =
    std::sync::LazyLock::new(sbproxy_ai::BudgetTracker::new);

/// Tracks fire-and-forget webhook callback tasks so graceful shutdown
/// can drain them. `tokio_util::task::TaskTracker` provides the
/// `spawn` -> `close` -> `wait` pattern: every webhook task is spawned
/// on the tracker, and a shutdown driver calls
/// [`shutdown_webhook_tasks`] before tearing down the runtime so
/// in-flight callbacks complete (or hit their per-call timeout) rather
/// than being silently dropped.
static WEBHOOK_TASKS: std::sync::LazyLock<tokio_util::task::TaskTracker> =
    std::sync::LazyLock::new(tokio_util::task::TaskTracker::new);

/// Drain in-flight webhook callback tasks. Intended for graceful
/// shutdown drivers: call this from the same async context the server
/// runs in after the listeners stop accepting new connections so any
/// `on_request` / `on_response` callbacks already fired finish their
/// HTTP send (or hit their per-call timeout) before the runtime tears
/// down. The tracker is closed for new spawns afterward; subsequent
/// `WEBHOOK_TASKS.spawn(...)` calls become no-ops.
pub async fn shutdown_webhook_tasks() {
    WEBHOOK_TASKS.close();
    WEBHOOK_TASKS.wait().await;
}

/// Tracks stale-while-revalidate background refreshes so graceful
/// shutdown can drain them. Same `spawn` -> `close` -> `wait` pattern
/// as [`WEBHOOK_TASKS`] but a separate tracker so a slow upstream on
/// one feature does not stall the other.
static CACHE_REVALIDATE_TASKS: std::sync::LazyLock<tokio_util::task::TaskTracker> =
    std::sync::LazyLock::new(tokio_util::task::TaskTracker::new);

/// Drain in-flight stale-while-revalidate background refreshes. Call
/// from the graceful-shutdown driver after listeners stop. New spawns
/// after this returns become no-ops.
pub async fn shutdown_cache_revalidate_tasks() {
    CACHE_REVALIDATE_TASKS.close();
    CACHE_REVALIDATE_TASKS.wait().await;
}

/// Pending semantic-cache write produced by a cache-miss path.
///
/// Tuple components: (hook, prompt key, cacheable upstream statuses,
/// max response size in bytes, model id). When populated, the AI relay
/// dispatches `hook.store` after the upstream response is forwarded,
/// subject to the status and size gates.
type PendingSemcacheMiss = (
    std::sync::Arc<dyn crate::hooks::SemanticLookupHook>,
    String,
    Vec<u16>,
    Option<usize>,
    Option<String>,
);

/// The main proxy implementation.
///
/// Implements Pingora's `ProxyHttp` trait to handle incoming HTTP requests,
/// route them by hostname, and proxy them to the correct upstream.
pub struct SbProxy;

// --- Template context builder ---

/// Build a template context for request modifier interpolation.
///
/// Populates `request.id`, `request.method`, `request.path`, and `vars.*`
/// keys from the request and origin variables.
/// Build Pingora `TlsSettings` configured for mTLS client-cert
/// verification. The acceptor loads the configured CA bundle and
/// turns on peer verification. When `require: true`, the handshake
/// fails if the client does not present a certificate; when `false`,
/// anonymous clients are admitted and the upstream sees
/// `X-Client-Cert-Verified: 0`.
fn build_mtls_tls_settings(
    cert_path: &str,
    key_path: &str,
    mtls: &sbproxy_config::MtlsListenerConfig,
    cache: sbproxy_tls::mtls::MtlsCertCacheHandle,
) -> anyhow::Result<pingora_core::listeners::tls::TlsSettings> {
    let mut settings = pingora_core::listeners::tls::TlsSettings::intermediate(cert_path, key_path)
        .map_err(|e| anyhow::anyhow!("TlsSettings::intermediate: {e}"))?;
    let verifier =
        sbproxy_tls::mtls::build_client_cert_verifier(&mtls.client_ca_file, mtls.require, cache)?;
    settings.set_client_cert_verifier(verifier);
    Ok(settings)
}

/// Format an IP address as a node identifier for the RFC 7239 `Forwarded`
/// header. IPv4 addresses are bare; IPv6 addresses must be wrapped in
/// `"[…]"` per RFC 7239 §6 (and for hostnames-with-colons, similarly).
fn forwarded_node(ip: &str) -> String {
    if ip.contains(':') {
        format!("\"[{ip}]\"")
    } else {
        ip.to_string()
    }
}

// --- Wave 4 day-5: content-negotiation stamp helper ---

/// Stamp `ctx.content_shape_pricing` and `ctx.content_shape_transform`
/// from the origin's `auto_content_negotiate` config and the inbound
/// `Accept` header.
///
/// `neg_cfg` is the JSON value lifted from
/// `CompiledOrigin.auto_content_negotiate`. `None` means the origin
/// did not author `ai_crawl_control` or any Wave 4 content-shaping
/// transform; in that case the helper is a no-op and both ctx fields
/// stay `None` so legacy origins are unaffected.
///
/// `accept` is the raw `Accept` header value, or `None` when the
/// client sent no header. The helper delegates to
/// [`sbproxy_modules::resolve_shapes`] for the q-value-aware resolver.
fn stamp_content_negotiation(
    ctx: &mut RequestContext,
    neg_cfg: Option<&serde_json::Value>,
    accept: Option<&str>,
) {
    let Some(cfg) = neg_cfg else {
        return;
    };
    let parsed =
        sbproxy_modules::ContentNegotiateConfig::from_config(cfg.clone()).unwrap_or_default();
    let shapes = sbproxy_modules::resolve_shapes(accept, parsed.default_content_shape);
    ctx.content_shape_pricing = Some(shapes.pricing);
    ctx.content_shape_transform = Some(shapes.transform);
    if shapes.diverged() {
        debug!(
            pricing = ?shapes.pricing,
            transform = ?shapes.transform,
            accept = ?accept,
            "content_negotiate: pricing and transform shapes diverge"
        );
    }
}

/// Apply a single compiled transform with Wave 4 typed dispatch.
///
/// The standard `CompiledTransform::apply` entry point in
/// `sbproxy-modules` is content-type and (`body`, `content_type`)
/// based. The Wave 4 day-5 wiring needs to override two cases:
///
/// - `Boilerplate` reports the byte-count it stripped; surface the
///   number on `ctx.metrics.stripped_bytes` so the Q4.14 audit and
///   operator dashboards can read it.
/// - `HtmlToMarkdown` is gated on `ctx.content_shape_transform`
///   (Markdown / Json shapes only). When the gate is open the
///   transform's typed `project` is invoked and the result is stamped
///   onto `ctx.markdown_projection` + `ctx.markdown_token_estimate` so
///   downstream transforms (`CitationBlock`, `JsonEnvelope`) and the
///   response-header middleware (Item 5 in day-5) can read them.
///
/// `CitationBlock` and `JsonEnvelope` need typed dispatch with
/// per-request ctx fields too; their typed wiring lands in subsequent
/// day-5 commits. For now they fall through to the standard apply
/// which is a no-op for those two variants.
///
/// All other transform variants delegate to the standard apply.
fn apply_transform_with_ctx(
    compiled: &sbproxy_modules::CompiledTransform,
    body: &mut bytes::BytesMut,
    content_type: Option<&str>,
    ctx: &mut RequestContext,
) -> anyhow::Result<()> {
    use sbproxy_modules::Transform;
    if !compiled.matches_content_type(content_type) {
        return Ok(());
    }
    match &compiled.transform {
        Transform::Boilerplate(t) => {
            let stripped = t.apply(body)?;
            ctx.metrics.stripped_bytes = ctx.metrics.stripped_bytes.saturating_add(stripped);
            Ok(())
        }
        Transform::HtmlToMarkdown(t) => {
            // Gate on the negotiated transform shape. The Markdown
            // projection runs only when the agent asked for Markdown
            // or Json (the JSON envelope wraps the Markdown body); a
            // Html / Pdf / Other shape leaves the body alone.
            let shape = ctx.content_shape_transform;
            let needs_projection = matches!(
                shape,
                Some(sbproxy_modules::ContentShape::Markdown)
                    | Some(sbproxy_modules::ContentShape::Json)
            );
            // Legacy origins (no auto_content_negotiate) leave shape
            // as None. Treat None as "run the transform unchanged"
            // so operators with bare `html_to_markdown` in their
            // transforms list (no AI policy) still get the projection.
            if shape.is_some() && !needs_projection {
                return Ok(());
            }
            let html = match std::str::from_utf8(body) {
                Ok(s) => s.to_string(),
                Err(e) => anyhow::bail!("html_to_markdown: body is not utf-8: {e}"),
            };
            let projection = t.project(&html);
            body.clear();
            body.extend_from_slice(projection.body.as_bytes());
            ctx.markdown_token_estimate = Some(projection.token_estimate);
            ctx.markdown_projection = Some(projection);
            Ok(())
        }
        Transform::JsonEnvelope(t) => {
            // Wave 4 day-5 Item 3: typed dispatch for the JSON
            // envelope. The transform reads ctx fields (markdown
            // projection, canonical url, RSL urn, citation flag) and
            // writes the v1 envelope body when the negotiated shape
            // is Json. No-op for other shapes (transform's own
            // fall-through).
            let _applied = t.apply(
                body,
                ctx.content_shape_transform,
                ctx.markdown_projection.as_ref(),
                ctx.canonical_url.as_deref(),
                ctx.rsl_urn.as_deref(),
                ctx.citation_required,
            )?;
            Ok(())
        }
        Transform::CitationBlock(t) => {
            // Wave 4 day-5 Item 4: typed dispatch for the citation
            // block. The transform's own gate handles the
            // citation_required flag (ctx wins, falls back to its own
            // force_citation, finally false). Skipped for shapes that
            // aren't Markdown / Json since prepending a citation
            // blockquote to HTML / PDF / Other would corrupt the
            // body.
            let shape = ctx.content_shape_transform;
            let runs_for_shape = matches!(
                shape,
                None | Some(sbproxy_modules::ContentShape::Markdown)
                    | Some(sbproxy_modules::ContentShape::Json)
            );
            if !runs_for_shape {
                return Ok(());
            }
            t.apply(
                body,
                ctx.canonical_url.as_deref(),
                ctx.rsl_urn.as_deref(),
                ctx.citation_required,
            )?;
            // Keep the cached projection's body in sync so the JSON
            // envelope (which reads `ctx.markdown_projection.body`)
            // sees the citation prefix too. Only update when the
            // citation transform actually changed the body.
            if matches!(shape, Some(sbproxy_modules::ContentShape::Markdown)) {
                if let Some(projection) = ctx.markdown_projection.as_mut() {
                    if let Ok(s) = std::str::from_utf8(body) {
                        projection.body = s.to_string();
                    }
                }
            }
            Ok(())
        }
        Transform::CelScript(t) => {
            // Wave 5 day-6 Item 1: typed dispatch for the CEL response
            // transform. The body-rewriting expression continues to use
            // the standard `apply_with_response` overload (which the
            // body-buffer pipeline below already invokes via the fall-
            // through arm). We split the call here so the per-header
            // `headers:` rules can evaluate against the live response
            // context and stash mutations onto `ctx` for the static
            // action / response_filter to stamp onto the outgoing
            // response. Body and headers are independent: a transform
            // may carry only one or the other.
            //
            // The body-buffer call site does not own the live response
            // header map (Pingora exposes that via the session struct,
            // not the transform context), so the header rule evaluation
            // sees an empty header map; richer header-binding wiring is
            // reserved for a later cleanup. The response status, in
            // contrast, IS already on `ctx`: the static action stamps
            // it in before transforms run, and the upstream body filter
            // runs after `response_filter` populates it. Reading it
            // here lets `string(response.status)` resolve to the real
            // status (200 from the static action under test) rather
            // than the zero placeholder.
            let status = ctx.response_status.unwrap_or(0);
            let mutations = t.evaluate_headers(body.as_ref(), status, &http::HeaderMap::new());
            ctx.cel_response_header_mutations.extend(mutations);
            t.apply(body)
        }
        // All other transform variants: standard pipeline.
        _ => compiled.transform.apply(body, content_type),
    }
}

/// Decide whether to stamp the `x-markdown-tokens` response header
/// for this request.
///
/// Returns `Some(estimate)` when the negotiated transform shape is
/// Markdown or Json AND the response should carry the header.
/// `estimate` is `ctx.markdown_token_estimate` when populated;
/// otherwise it's a fallback computed from `body_len_hint` (typically
/// the upstream `Content-Length`) times the resolved per-origin
/// `token_bytes_ratio`. A `None` ratio falls back to
/// [`sbproxy_modules::DEFAULT_TOKEN_BYTES_RATIO`] (0.25).
///
/// Returns `None` for legacy origins (shape == None) and for shapes
/// that do not produce a Markdown projection (Html / Pdf / Other).
///
/// Retained as a thin shim over [`x_markdown_tokens_header_value_with_ratio`]
/// so existing call sites and unit tests stay terse when no per-origin
/// ratio override applies.
#[cfg(test)]
fn x_markdown_tokens_header_value(
    shape: Option<sbproxy_modules::ContentShape>,
    cached_estimate: Option<u32>,
    body_len_hint: Option<u64>,
) -> Option<u32> {
    x_markdown_tokens_header_value_with_ratio(shape, cached_estimate, body_len_hint, None)
}

/// Variant of `x_markdown_tokens_header_value` that accepts an
/// explicit per-origin tokens-per-byte ratio (A4.2 follow-up). When
/// `ratio_override` is `Some`, the fallback computation uses it
/// instead of [`sbproxy_modules::DEFAULT_TOKEN_BYTES_RATIO`]. The
/// override is ignored when `cached_estimate` is `Some(_)` because
/// the cached value already incorporates the per-origin ratio at
/// projection time.
fn x_markdown_tokens_header_value_with_ratio(
    shape: Option<sbproxy_modules::ContentShape>,
    cached_estimate: Option<u32>,
    body_len_hint: Option<u64>,
    ratio_override: Option<f32>,
) -> Option<u32> {
    let needs_header = matches!(
        shape,
        Some(sbproxy_modules::ContentShape::Markdown) | Some(sbproxy_modules::ContentShape::Json)
    );
    if !needs_header {
        return None;
    }
    if let Some(n) = cached_estimate {
        return Some(n);
    }
    let len = body_len_hint.unwrap_or(0);
    let ratio = ratio_override.unwrap_or(sbproxy_modules::DEFAULT_TOKEN_BYTES_RATIO);
    Some((len as f32 * ratio) as u32)
}

/// Map a request path onto the projection-kind tag used by the
/// data-plane handler.
///
/// Returns `None` for any path outside the closed set of well-known
/// projection URLs pinned by `docs/adr-policy-graph-projections.md`
/// (A4.1). The five recognised paths are the four projection
/// documents plus the `llms-full.txt` extended variant.
fn projection_kind_for_path(path: &str) -> Option<&'static str> {
    match path {
        "/robots.txt" => Some("robots"),
        "/llms.txt" => Some("llms"),
        "/llms-full.txt" => Some("llms-full"),
        "/licenses.xml" => Some("licenses"),
        "/.well-known/tdmrep.json" => Some("tdmrep"),
        _ => None,
    }
}

/// Map a projection kind onto its canonical Content-Type header value.
///
/// Robots / llms surface as `text/plain; charset=utf-8` per
/// IETF draft-koster-rep-ai and the Anthropic / Mistral convention.
/// Licenses is `application/xml` per RSL 1.0; tdmrep is
/// `application/json` per W3C TDMRep.
fn projection_content_type(kind: &str) -> &'static str {
    match kind {
        "robots" | "llms" | "llms-full" => "text/plain; charset=utf-8",
        "licenses" => "application/xml",
        "tdmrep" => "application/json",
        _ => "text/plain",
    }
}

/// Resolve the tokens-per-byte ratio the proxy uses for a given
/// origin's Markdown projection.
///
/// Per `docs/adr-json-envelope-schema.md` (A4.2) the ratio is a
/// per-origin knob defaulting to
/// [`sbproxy_modules::DEFAULT_TOKEN_BYTES_RATIO`] (0.25) for English
/// prose. Operators set `token_bytes_ratio:` at the origin level to
/// calibrate non-English or dense technical content. When the field
/// is unset, this helper falls back to the default constant so the
/// `x-markdown-tokens` header and the JSON envelope's `token_estimate`
/// remain stable for legacy origins.
fn resolved_token_bytes_ratio(origin: Option<&sbproxy_config::CompiledOrigin>) -> f32 {
    origin
        .and_then(|o| o.token_bytes_ratio)
        .unwrap_or(sbproxy_modules::DEFAULT_TOKEN_BYTES_RATIO)
}

/// Outcome of the Content-Signal / TDM-Reservation header decision
/// per `docs/adr-content-negotiation-and-pricing.md` § "Content-Signal
/// response header" (G4.1) and A4.1 § "tdmrep.json".
///
/// Surfaced as an enum so the response_filter and the static-action
/// short-circuit path can share one source of truth and the unit
/// tests can exercise the decision matrix without spinning a Session.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ContentSignalDecision {
    /// Stamp `Content-Signal: <value>` on the response.
    Stamp(String),
    /// Stamp `TDM-Reservation: 1` instead (origin opted into the
    /// projection cache but asserted no signal).
    TdmReservationFallback,
    /// Do nothing (non-2xx response or origin not enrolled).
    Skip,
}

/// Decide which (if any) of `Content-Signal` / `TDM-Reservation` to
/// stamp.
///
/// `is_2xx` gates the entire decision per G4.1 ("on 200 responses
/// only"). `origin_signal` is the validated `&'static str` form from
/// the compiled origin (closed enum, so any value is wire-safe).
/// `projection_signal` is the optional value the projection cache
/// carries; `Some(Some(_))` means the origin set the value via the
/// older `extensions["content_signal"]` slot, `Some(None)` means the
/// origin enrolled in the projection cache (i.e. has `ai_crawl_control`)
/// but asserted no signal, and `None` means the origin is not enrolled
/// at all.
fn resolve_content_signal_decision(
    is_2xx: bool,
    origin_signal: Option<&'static str>,
    projection_signal: Option<Option<&str>>,
) -> ContentSignalDecision {
    if !is_2xx {
        return ContentSignalDecision::Skip;
    }
    if let Some(s) = origin_signal {
        return ContentSignalDecision::Stamp(s.to_string());
    }
    match projection_signal {
        Some(Some(s)) => ContentSignalDecision::Stamp(s.to_string()),
        Some(None) => ContentSignalDecision::TdmReservationFallback,
        None => ContentSignalDecision::Skip,
    }
}

/// When the body has not been HTML-projected (e.g. a `static` action
/// serving a Markdown body, or an upstream that returned Markdown
/// directly), synthesise a [`sbproxy_modules::MarkdownProjection`]
/// from the body bytes so the JSON envelope, citation block, and
/// `x-markdown-tokens` header all see a consistent token estimate.
///
/// `token_bytes_ratio` should come from the per-origin override or
/// the default constant. Idempotent: returns early when
/// `ctx.markdown_projection` is already populated.
fn synthesise_markdown_projection_if_missing(
    ctx: &mut RequestContext,
    body: &[u8],
    token_bytes_ratio: f32,
) {
    if ctx.markdown_projection.is_some() {
        return;
    }
    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s.to_string(),
        Err(_) => return,
    };
    let token_estimate = (body_str.len() as f32 * token_bytes_ratio) as u32;
    let projection = sbproxy_modules::MarkdownProjection {
        body: body_str,
        title: None,
        token_estimate,
    };
    ctx.markdown_token_estimate = Some(projection.token_estimate);
    ctx.markdown_projection = Some(projection);
}

fn build_request_template_context(
    session: &Session,
    ctx: &RequestContext,
    origin: &sbproxy_config::CompiledOrigin,
) -> sbproxy_middleware::modifiers::TemplateContext {
    let mut tmpl = sbproxy_middleware::modifiers::TemplateContext::new();

    // Request metadata.
    tmpl.values.insert(
        "request.id".to_string(),
        if ctx.request_id.is_empty() {
            // Generate a simple unique ID if not set.
            format!(
                "{:016x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            )
        } else {
            ctx.request_id.to_string()
        },
    );
    tmpl.values.insert(
        "request.method".to_string(),
        session.req_header().method.as_str().to_string(),
    );
    tmpl.values.insert(
        "request.path".to_string(),
        session.req_header().uri.path().to_string(),
    );
    tmpl.values
        .insert("request.host".to_string(), ctx.hostname.to_string());

    // Origin variables.
    if let Some(vars) = &origin.variables {
        for (key, value) in vars.as_ref() {
            let val_str = match value {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            tmpl.values.insert(format!("vars.{}", key), val_str);
        }
    }

    tmpl
}

// --- Response cache key construction ---

/// Translate the config-crate `QueryNormalize` enum into the
/// cache-crate `QueryMode` enum. The two crates intentionally don't
/// depend on each other to keep the cache crate lean; this is the
/// single translation point.
fn query_mode_from_config(qn: &sbproxy_config::QueryNormalize) -> sbproxy_cache::QueryMode {
    match qn {
        sbproxy_config::QueryNormalize::IgnoreAll => sbproxy_cache::QueryMode::IgnoreAll,
        sbproxy_config::QueryNormalize::Sort => sbproxy_cache::QueryMode::Sort,
        sbproxy_config::QueryNormalize::Allowlist { allowlist } => {
            sbproxy_cache::QueryMode::Allowlist(allowlist.clone())
        }
    }
}

/// Snapshot the request headers that participate in the cache key per
/// the origin's `vary` config. Names are matched case-insensitively
/// and stored lowercased so the fingerprint is stable. Headers not
/// present on the request are recorded with an empty value (still
/// distinct from "header was set to empty"); this matches the
/// pre-existing behavior the e2e tests pin.
fn collect_vary_headers(
    req: &pingora_http::RequestHeader,
    vary: &[String],
) -> Vec<(String, String)> {
    if vary.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(vary.len());
    for name in vary {
        let lower = name.to_ascii_lowercase();
        let value = req
            .headers
            .get(&lower)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        out.push((lower, value));
    }
    out
}

/// Build the canonical response-cache key for a request.
///
/// `workspace` is the empty string in OSS / single-tenant mode; the
/// enterprise crate populates it. The result is the colon-delimited
/// shape documented at the top of `sbproxy_cache::response`.
fn build_response_cache_key(
    workspace: &str,
    hostname: &str,
    req: &pingora_http::RequestHeader,
    cfg: &sbproxy_config::ResponseCacheConfig,
) -> String {
    let method = req.method.as_str();
    let path = req.uri.path();
    let query = req.uri.query();
    let mode = query_mode_from_config(&cfg.query_normalize);
    let vary = collect_vary_headers(req, &cfg.vary);
    sbproxy_cache::compute_cache_key(workspace, hostname, method, path, query, &mode, &vary)
}

/// HTTP client used by the stale-while-revalidate path. Reused across
/// every SWR refresh so connection pooling and keep-alive amortize
/// across origins. The 30s timeout matches the conservative ceiling
/// the rest of the proxy uses for outbound HTTP.
static SWR_CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("swr reqwest::Client build must succeed")
});

/// Spawn an async refresh of `cache_key` against the origin's upstream.
///
/// The SWR window has just elapsed for an entry; serve the stale value
/// to the client (caller already did this) and dispatch a background
/// fetch that re-populates the cache when the refresh succeeds. The
/// task is registered with [`CACHE_REVALIDATE_TASKS`] so graceful
/// shutdown drains it.
///
/// Failures are logged at WARN and never propagate to the client.
/// `cacheable_status` is the same gate the response_filter applies, so
/// a 500 from the refresh does not poison the cache; the entry simply
/// keeps its existing (now-expired-and-stale-window-exhausted) state
/// until the next request hits a true MISS.
#[allow(clippy::too_many_arguments)]
fn spawn_swr_revalidation(
    cache_store: std::sync::Arc<dyn sbproxy_cache::CacheStore>,
    cache_key: String,
    ttl_secs: u64,
    action_config: serde_json::Value,
    hostname: String,
    path_and_query: String,
    cacheable_status: Vec<u16>,
) {
    // Extract the upstream URL from the action config. Only `proxy`
    // actions are revalidatable; static / redirect / etc. have no
    // upstream and we noop. The two field names (`url` and `target`)
    // both appear in the wild, so we accept either.
    let upstream_url = action_config
        .get("url")
        .or_else(|| action_config.get("target"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim_end_matches('/').to_string());
    let Some(base) = upstream_url else {
        tracing::debug!(
            host = %hostname,
            "swr: action has no proxy URL, skipping revalidation"
        );
        return;
    };
    let full_url = format!("{}{}", base, path_and_query);

    CACHE_REVALIDATE_TASKS.spawn(async move {
        // Build a clean GET against the upstream. We deliberately
        // forward only the Host header; downstream callbacks /
        // modifiers / forward rules etc. are skipped because they
        // already ran on the synchronous request that triggered this
        // refresh.
        let resp = match SWR_CLIENT
            .get(&full_url)
            .header("host", &hostname)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    url = %full_url,
                    "swr: revalidation request failed"
                );
                return;
            }
        };
        let status = resp.status().as_u16();
        // Apply the same cacheable_status gate the live path uses.
        // An empty list is treated as "200 only" to match the
        // response_filter default.
        let status_ok = if cacheable_status.is_empty() {
            status == 200
        } else {
            cacheable_status.contains(&status)
        };
        if !status_ok {
            tracing::debug!(
                status,
                url = %full_url,
                "swr: refresh got non-cacheable status, leaving stale"
            );
            return;
        }
        // Capture headers before consuming the body. Skip hop-by-hop
        // headers that the cache must not store.
        let mut headers: Vec<(String, String)> = Vec::with_capacity(resp.headers().len());
        for (name, value) in resp.headers() {
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
                headers.push((n, v.to_string()));
            }
        }
        let body = match resp.bytes().await {
            Ok(b) => b.to_vec(),
            Err(e) => {
                tracing::warn!(error = %e, "swr: failed to read refresh body");
                return;
            }
        };
        let entry = sbproxy_cache::CachedResponse {
            status,
            headers,
            body,
            cached_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            ttl_secs,
        };
        // Write-back goes through spawn_blocking for the same reason
        // the live path does: blocking I/O for the Redis backend.
        let _ = tokio::task::spawn_blocking(move || {
            if let Err(e) = cache_store.put(&cache_key, &entry) {
                tracing::warn!(error = %e, "swr: write-back to cache failed");
            }
        })
        .await;
    });
}

// --- Cache Reserve admission ---

/// Mirror an evicted-from-hot cache entry into the cold reserve, gated
/// by the configured admission filter (TTL floor, size cap, sample
/// rate). The write happens on a detached task so the request path
/// returns immediately; failures degrade to warning-level logs and
/// never propagate to the client.
///
/// Called from two sites in `request_filter`:
/// 1. The TTL+SWR-exhausted branch, just before the hot entry is
///    deleted, so a long-tail entry that's about to disappear from
///    the hot tier gets a chance to land in the reserve.
/// 2. The post-upstream cache-write path, so a fresh entry is admitted
///    proactively.
fn maybe_admit_to_reserve(
    reserve: std::sync::Arc<dyn sbproxy_cache::CacheReserveBackend>,
    admission: crate::pipeline::ReserveAdmission,
    key: String,
    entry: &sbproxy_cache::CachedResponse,
    origin_id: String,
) {
    if !admission.admits(entry.ttl_secs, entry.body.len()) {
        return;
    }
    if admission.sample_rate <= 0.0 {
        return;
    }
    if admission.sample_rate < 1.0 {
        // Cheap fast-path: skip the random draw on the always-admit
        // case so production traffic doesn't pay for it.
        if rand::random::<f64>() >= admission.sample_rate {
            return;
        }
    }

    let body = bytes::Bytes::from(entry.body.clone());
    let now = std::time::SystemTime::now();
    let expires_at = now + std::time::Duration::from_secs(entry.ttl_secs);
    // Pull content-type from the cached headers if present so the
    // reserve can serve it without re-walking the header list.
    let content_type = entry
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.clone());
    let metadata = sbproxy_cache::ReserveMetadata {
        created_at: now,
        expires_at,
        content_type,
        vary_fingerprint: None,
        size: entry.body.len() as u64,
        status: entry.status,
    };

    tokio::spawn(async move {
        match reserve.put(&key, body, metadata).await {
            Ok(()) => {
                sbproxy_observe::metrics()
                    .cache_reserve_writes
                    .with_label_values(&[origin_id.as_str()])
                    .inc();
            }
            Err(e) => {
                tracing::warn!(error = %e, "cache reserve put failed");
            }
        }
    });
}

// --- Advanced request modifier application ---

/// Apply URL rewrite, query injection, method override, and body replacement
/// modifiers to the upstream request. Header modifiers are handled separately
/// by `apply_request_modifiers_with_templates`.
fn apply_advanced_request_modifiers(
    modifiers: &[sbproxy_config::RequestModifierConfig],
    upstream_request: &mut RequestHeader,
    ctx: &mut RequestContext,
) {
    for modifier in modifiers {
        // URL path rewrite.
        if let Some(url_mod) = &modifier.url {
            if let Some(path_rewrite) = &url_mod.path {
                if let Some(replace) = &path_rewrite.replace {
                    let current_path = upstream_request.uri.path().to_string();
                    let new_path = current_path.replace(&replace.old, &replace.new);
                    if new_path != current_path {
                        let new_uri = if let Some(query) = upstream_request.uri.query() {
                            format!("{}?{}", new_path, query)
                        } else {
                            new_path
                        };
                        if let Ok(uri) = new_uri.parse::<http::Uri>() {
                            upstream_request.set_uri(uri);
                        }
                    }
                }
            }
        }

        // Query parameter injection.
        if let Some(query_mod) = &modifier.query {
            let current_path = upstream_request.uri.path().to_string();
            let existing_query = upstream_request.uri.query().unwrap_or("").to_string();

            let mut params: Vec<(String, String)> =
                url::form_urlencoded::parse(existing_query.as_bytes())
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect();

            // Remove specified keys.
            for key in &query_mod.remove {
                params.retain(|(k, _)| k != key);
            }

            // Set (overwrite) specified keys.
            for (key, value) in &query_mod.set {
                params.retain(|(k, _)| k != key);
                params.push((key.clone(), value.clone()));
            }

            // Add specified keys (append without removing existing).
            for (key, value) in &query_mod.add {
                params.push((key.clone(), value.clone()));
            }

            let new_query: String = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&params)
                .finish();
            let new_uri = if new_query.is_empty() {
                current_path
            } else {
                format!("{}?{}", current_path, new_query)
            };
            if let Ok(uri) = new_uri.parse::<http::Uri>() {
                upstream_request.set_uri(uri);
            }
        }

        // Method override.
        if let Some(method_str) = &modifier.method {
            if let Ok(method) = method_str.parse::<http::Method>() {
                upstream_request.set_method(method);
            }
        }

        // Body replacement: store in context for the body filter phase.
        if let Some(body_mod) = &modifier.body {
            if let Some(json_val) = &body_mod.replace_json {
                ctx.replacement_request_body = Some(Bytes::from(json_val.to_string()));
            } else if let Some(text) = &body_mod.replace {
                ctx.replacement_request_body = Some(Bytes::from(text.clone()));
            }
        }
    }
}

// --- CSP report redaction ---

/// Subset of CSP-report fields kept for structured logging.
///
/// Browsers POST violation reports either as the legacy
/// `application/csp-report` envelope (`{"csp-report": {...}}`) or as
/// the modern Reporting API envelope (`[{"type": "csp-violation",
/// "body": {...}}, ...]`). Both share the same field names inside
/// the inner object; we extract a fixed allowlist and drop any
/// unknown keys so a misbehaving browser cannot smuggle high-
/// cardinality or sensitive data into the structured log.
///
/// URL-shaped values have their query string stripped (replaced
/// with `?[redacted]`) and every value is capped at 256 bytes.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct RedactedCspReport {
    pub document_uri: Option<String>,
    pub violated_directive: Option<String>,
    pub blocked_uri: Option<String>,
    pub effective_directive: Option<String>,
    pub original_policy: Option<String>,
}

/// Maximum length of any single redacted field (post-redaction).
const REDACTED_FIELD_CAP: usize = 256;

/// Parse a CSP report body and emit a redacted view safe to log.
///
/// Unknown / unparseable bodies return an empty struct; the caller
/// still logs the byte count and the request metadata so noise is
/// observable.
pub(crate) fn redact_csp_report(body: &[u8]) -> RedactedCspReport {
    let value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return RedactedCspReport::default(),
    };

    // Two wire shapes: the legacy single-report envelope and the
    // Reporting API array. Normalise both into a single inner object.
    let inner: Option<&serde_json::Value> = match &value {
        serde_json::Value::Object(map) => map.get("csp-report").or(Some(&value)),
        serde_json::Value::Array(items) => items.first().and_then(|first| {
            first
                .get("body")
                .or_else(|| first.as_object().map(|_| first))
        }),
        _ => None,
    };

    let Some(inner) = inner else {
        return RedactedCspReport::default();
    };

    let pick = |key: &str| -> Option<String> {
        inner
            .get(key)
            .and_then(|v| v.as_str())
            .map(redact_field_value)
    };

    RedactedCspReport {
        document_uri: pick("document-uri").or_else(|| pick("documentURL")),
        violated_directive: pick("violated-directive"),
        blocked_uri: pick("blocked-uri").or_else(|| pick("blockedURL")),
        effective_directive: pick("effective-directive"),
        original_policy: pick("original-policy"),
    }
}

/// Redact one CSP-report value: strip query strings on URL-shaped
/// inputs and cap the byte length at [`REDACTED_FIELD_CAP`].
fn redact_field_value(raw: &str) -> String {
    // URL-ish values get the query string masked. We do this on a
    // best-effort textual basis so non-URL fields (like
    // `violated-directive`) remain readable. Any input that contains
    // `://` and a `?` after that is treated as a URL; the part
    // after the first `?` (and before the first `#`) is replaced
    // with `[redacted]`.
    let cleaned = if raw.contains("://") {
        if let Some(q_idx) = raw.find('?') {
            let (head, tail) = raw.split_at(q_idx);
            // Preserve any `#fragment` so we do not lose a directive
            // hint; everything between `?` and `#` is dropped.
            let fragment = tail.find('#').map(|i| &tail[i..]).unwrap_or("");
            format!("{head}?[redacted]{fragment}")
        } else {
            raw.to_string()
        }
    } else {
        raw.to_string()
    };

    if cleaned.len() <= REDACTED_FIELD_CAP {
        cleaned
    } else {
        // Truncate on a char boundary so utf-8 stays valid.
        let mut end = REDACTED_FIELD_CAP;
        while end > 0 && !cleaned.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &cleaned[..end])
    }
}

// --- Response helpers ---

/// Send a complete response with status, content-type, and body, then short-circuit.
///
/// Always sets Content-Length so clients know the exact response size
/// without relying on connection close or chunked encoding.
async fn send_response(
    session: &mut Session,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let mut header = pingora_http::ResponseHeader::build(status, Some(2)).map_err(|e| {
        Error::because(
            ErrorType::InternalError,
            "failed to build response header",
            e,
        )
    })?;
    header
        .insert_header("content-type", content_type)
        .map_err(|e| Error::because(ErrorType::InternalError, "failed to set content-type", e))?;
    header
        .insert_header("content-length", body.len().to_string())
        .map_err(|e| Error::because(ErrorType::InternalError, "failed to set content-length", e))?;
    session
        .write_response_header(Box::new(header), false)
        .await?;
    session
        .write_response_body(Some(bytes::Bytes::copy_from_slice(body)), true)
        .await?;
    Ok(())
}

/// Send a JSON error response.
async fn send_error(session: &mut Session, status: u16, message: &str) -> Result<()> {
    let body = format!("{{\"error\":\"{message}\"}}");
    send_response(session, status, "application/json", body.as_bytes()).await
}

/// Send a JSON error response with extra response headers attached.
///
/// Used by the auth dispatch path when an [`sbproxy_plugin::AuthProvider`]
/// returns [`sbproxy_plugin::AuthDecision::DenyWithHeaders`]. The
/// canonical use is the OAuth 2.0 Protected Resource Metadata response
/// (RFC 9728) where the resource server points clients at the
/// authorization server discovery document via a `WWW-Authenticate`
/// header on the 401.
///
/// Header names and values are copied verbatim. Invalid header
/// constructions are skipped with a warning log so a single malformed
/// entry from a third-party plugin cannot poison the whole response.
async fn send_error_with_extra_headers(
    session: &mut Session,
    status: u16,
    message: &str,
    extra_headers: &[(String, String)],
) -> Result<()> {
    let body = format!("{{\"error\":\"{message}\"}}");
    let mut header = pingora_http::ResponseHeader::build(status, Some(2 + extra_headers.len()))
        .map_err(|e| {
            Error::because(
                ErrorType::InternalError,
                "failed to build response header",
                e,
            )
        })?;
    header
        .insert_header("content-type", "application/json")
        .map_err(|e| Error::because(ErrorType::InternalError, "failed to set content-type", e))?;
    header
        .insert_header("content-length", body.len().to_string())
        .map_err(|e| Error::because(ErrorType::InternalError, "failed to set content-length", e))?;
    for (name, value) in extra_headers {
        if let Err(e) = header.append_header(name.clone(), value) {
            warn!(
                header_name = %name,
                error = %e,
                "auth plugin emitted invalid response header; skipping",
            );
        }
    }
    session
        .write_response_header(Box::new(header), false)
        .await?;
    session
        .write_response_body(Some(bytes::Bytes::copy_from_slice(body.as_bytes())), true)
        .await?;
    Ok(())
}

/// Send an error response, checking for custom error_pages config first.
///
/// If the origin has error_pages configured and one or more entries match the
/// status code, the best representation for the request's `Accept` header is
/// selected via content negotiation. If multiple entries match and the client
/// expresses no preference (or no `Accept` header is present), JSON is
/// preferred, then HTML, then the first match. Falls back to the default
/// plain-text error if no entry matches.
async fn send_error_with_pages(
    session: &mut Session,
    status: u16,
    message: &str,
    error_pages: &Option<serde_json::Value>,
    request_path: &str,
) -> Result<()> {
    if let Some(pages) = error_pages {
        if let Some(pages_arr) = pages.as_array() {
            // Collect every entry that matches this status.
            let candidates: Vec<&serde_json::Value> = pages_arr
                .iter()
                .filter(|page| page_matches_status(page, status))
                .collect();

            if !candidates.is_empty() {
                let accept = session
                    .req_header()
                    .headers
                    .get("accept")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let chosen = select_error_page(&candidates, accept);

                let ct = chosen
                    .get("content_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("application/json");
                let body_template = chosen.get("body").and_then(|v| v.as_str()).unwrap_or("");
                let is_template = chosen
                    .get("template")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                let body = if is_template {
                    body_template
                        .replace("{{ status_code }}", &status.to_string())
                        .replace("{{status_code}}", &status.to_string())
                        .replace("{{ request.path }}", request_path)
                        .replace("{{request.path}}", request_path)
                } else {
                    body_template.to_string()
                };

                return send_response(session, status, ct, body.as_bytes()).await;
            }
        }
    }

    // No matching error page, use default.
    send_error(session, status, message).await
}

/// Returns true if the page config's `status` field includes the given status.
/// `status` may be a single integer or an array of integers.
fn page_matches_status(page: &serde_json::Value, status: u16) -> bool {
    let Some(status_val) = page.get("status") else {
        return false;
    };
    if let Some(arr) = status_val.as_array() {
        arr.iter().any(|v| v.as_u64() == Some(status as u64))
    } else {
        status_val.as_u64() == Some(status as u64)
    }
}

/// Select the best error page entry for the client's `Accept` header.
///
/// Parses the `Accept` header (q-values, wildcards) and picks the highest-
/// quality candidate whose `content_type` matches an accepted media range.
/// If no candidate matches, falls back in order:
///   1. application/json entry
///   2. text/html entry
///   3. first candidate
fn select_error_page<'a>(
    candidates: &[&'a serde_json::Value],
    accept_header: &str,
) -> &'a serde_json::Value {
    let ranges = parse_accept_ranges(accept_header);

    // If the client expresses a concrete preference (anything other than
    // a wildcard `*/*`), honor it: score each candidate by its best-matching
    // q-value, higher wins, ties break on candidate order.
    let has_concrete_pref = ranges.iter().any(|r| r.typ != "*" || r.subtype != "*");
    if has_concrete_pref {
        let mut best_idx: usize = 0;
        let mut best_q: f32 = 0.0;
        for (i, cand) in candidates.iter().enumerate() {
            let ct = cand
                .get("content_type")
                .and_then(|v| v.as_str())
                .unwrap_or("application/octet-stream");
            let q = match_accept_q(&ranges, ct);
            if q > best_q {
                best_q = q;
                best_idx = i;
            }
        }
        if best_q > 0.0 {
            return candidates[best_idx];
        }
    }

    // No concrete preference (missing Accept, empty, or `*/*` only), or
    // concrete prefs matched nothing: apply a sensible default.
    for pref in ["application/json", "text/html"] {
        if let Some(c) = candidates.iter().find(|c| {
            c.get("content_type")
                .and_then(|v| v.as_str())
                .map(|s| s.starts_with(pref))
                .unwrap_or(false)
        }) {
            return c;
        }
    }
    candidates[0]
}

/// A single parsed entry from an `Accept` header.
struct AcceptRange {
    typ: String,     // "text", "application", or "*"
    subtype: String, // "html", "json", or "*"
    q: f32,
}

fn parse_accept_ranges(header: &str) -> Vec<AcceptRange> {
    if header.is_empty() {
        return Vec::new();
    }
    header
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
            let mut params = part.split(';');
            let media = params.next()?.trim();
            let (typ, subtype) = media.split_once('/')?;
            let mut q: f32 = 1.0;
            for p in params {
                let p = p.trim();
                if let Some(qval) = p.strip_prefix("q=") {
                    q = qval.parse().unwrap_or(1.0);
                }
            }
            Some(AcceptRange {
                typ: typ.to_ascii_lowercase(),
                subtype: subtype.to_ascii_lowercase(),
                q,
            })
        })
        .collect()
}

/// Returns the highest q-value among accept ranges that match `content_type`.
/// Returns 0.0 if no range matches. A `*/*` range matches with its own q.
fn match_accept_q(ranges: &[AcceptRange], content_type: &str) -> f32 {
    // Strip any ";charset=..." suffix and lowercase.
    let ct = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim();
    let (ct_type, ct_sub) = match ct.split_once('/') {
        Some((t, s)) => (t.to_ascii_lowercase(), s.to_ascii_lowercase()),
        None => return 0.0,
    };

    let mut best: f32 = 0.0;
    for r in ranges {
        let type_match = r.typ == "*" || r.typ == ct_type;
        let sub_match = r.subtype == "*" || r.subtype == ct_sub;
        if type_match && sub_match && r.q > best {
            best = r.q;
        }
    }
    best
}

// --- Fallback action helper ---

/// Serve a fallback action's response directly (for error/status fallback).
/// Returns Ok(status_code) on success.
async fn serve_fallback_action(
    session: &mut Session,
    action: &Action,
    add_debug_header: bool,
    trigger: &str,
) -> Result<u16> {
    match action {
        Action::Static(s) => {
            let ct = s.content_type.as_deref().unwrap_or("text/plain");
            let num_headers = 2 + s.headers.len() + if add_debug_header { 1 } else { 0 };
            let mut header = pingora_http::ResponseHeader::build(s.status, Some(num_headers))
                .map_err(|e| {
                    Error::because(
                        ErrorType::InternalError,
                        "failed to build fallback header",
                        e,
                    )
                })?;
            header.insert_header("content-type", ct).map_err(|e| {
                Error::because(ErrorType::InternalError, "failed to set content-type", e)
            })?;
            header
                .insert_header("content-length", s.body.len().to_string())
                .map_err(|e| {
                    Error::because(ErrorType::InternalError, "failed to set content-length", e)
                })?;
            for (k, v) in &s.headers {
                let _ = header.insert_header(k.clone(), v.clone());
            }
            if add_debug_header {
                let _ = header.insert_header("X-Fallback-Trigger", trigger);
            }
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session
                .write_response_body(Some(bytes::Bytes::copy_from_slice(s.body.as_bytes())), true)
                .await?;
            Ok(s.status)
        }
        _ => {
            // For non-static fallback actions, serve a generic fallback error.
            // This could be extended to support proxy/redirect fallback actions.
            let body = b"{\"error\":\"fallback not available\"}";
            let mut header = pingora_http::ResponseHeader::build(502, Some(2)).map_err(|e| {
                Error::because(
                    ErrorType::InternalError,
                    "failed to build fallback error header",
                    e,
                )
            })?;
            header
                .insert_header("content-type", "application/json")
                .map_err(|e| {
                    Error::because(ErrorType::InternalError, "failed to set content-type", e)
                })?;
            if add_debug_header {
                let _ = header.insert_header("X-Fallback-Trigger", trigger);
            }
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session
                .write_response_body(Some(bytes::Bytes::copy_from_slice(body)), true)
                .await?;
            Ok(502)
        }
    }
}

// --- Auth checking ---

/// Result of running an auth check.
enum AuthResult {
    /// Auth passed. `sub` carries the resolved end-user subject when
    /// the provider could identify one (JWT `sub` claim, basic-auth
    /// username, forward-auth response header); `source` describes
    /// which channel produced it. Both are `None` for providers that
    /// authenticate without binding to a specific user (API key,
    /// shared bearer token, bot agent, noop).
    Allow {
        /// Resolved subject identifier.
        sub: Option<String>,
        /// Origin of `sub`.
        source: Option<sbproxy_plugin::AuthSubjectSource>,
    },
    /// Auth failed with this status code and message.
    Deny(u16, String),
    /// Auth failed with this status code, message, and provider-supplied
    /// response headers (e.g. RFC 9728 `WWW-Authenticate` from the MCP
    /// resource-server provider). Headers are appended verbatim to the
    /// 4xx response.
    DenyWithHeaders(u16, String, Vec<(String, String)>),
    /// Digest auth needs a challenge response.
    DigestChallenge(String),
}

impl AuthResult {
    /// Convenience: build an `Allow` with no resolved subject.
    fn allow_anonymous() -> Self {
        Self::Allow {
            sub: None,
            source: None,
        }
    }
}

/// Run the auth check for a given origin. Returns AuthResult. `path`
/// is the request-line path (no scheme/authority); for BotAuth it
/// reconstructs `@target-uri` so the verifier sees the same canonical
/// component the signer covered.
///
/// `Auth::Plugin(provider)` dispatches into the third-party
/// [`sbproxy_plugin::AuthProvider`] supplied by the inventory-based
/// registration channel (see [`sbproxy_plugin::AuthPluginRegistration`]).
/// The provider's [`sbproxy_plugin::AuthDecision`] is translated into
/// the corresponding [`AuthResult`] variant; `DenyWithHeaders` is
/// preserved end-to-end so providers can attach challenge headers
/// (RFC 9728, OAuth 2.0 PRM, etc.) on the 4xx response.
async fn check_auth(
    auth: &Auth,
    headers: &http::HeaderMap,
    query: Option<&str>,
    method: &str,
    path: &str,
) -> AuthResult {
    match auth {
        Auth::ApiKey(a) => {
            if a.check_request(headers, query) {
                AuthResult::allow_anonymous()
            } else {
                AuthResult::Deny(401, "unauthorized".to_string())
            }
        }
        Auth::BasicAuth(a) => match a.check_request_with_subject(headers) {
            Some(username) => AuthResult::Allow {
                sub: Some(username),
                source: Some(sbproxy_plugin::AuthSubjectSource::Header),
            },
            None => AuthResult::Deny(401, "unauthorized".to_string()),
        },
        Auth::Bearer(a) => {
            if a.check_request(headers) {
                AuthResult::allow_anonymous()
            } else {
                AuthResult::Deny(401, "unauthorized".to_string())
            }
        }
        Auth::Jwt(a) => match a.check_request_with_subject(headers) {
            Some(sub) if !sub.is_empty() => AuthResult::Allow {
                sub: Some(sub),
                source: Some(sbproxy_plugin::AuthSubjectSource::Jwt),
            },
            // Token validated but carried no `sub` claim: still
            // authenticated, just without an identifiable subject.
            Some(_) => AuthResult::allow_anonymous(),
            None => AuthResult::Deny(401, "unauthorized".to_string()),
        },
        Auth::Digest(d) => {
            if headers.get(http::header::AUTHORIZATION).is_some() {
                match d.check_request_with_subject(headers, method) {
                    Some(username) => AuthResult::Allow {
                        sub: Some(username),
                        source: Some(sbproxy_plugin::AuthSubjectSource::Header),
                    },
                    None => {
                        let nonce = sbproxy_modules::auth::DigestAuth::generate_nonce();
                        AuthResult::DigestChallenge(d.challenge(&nonce))
                    }
                }
            } else {
                let nonce = sbproxy_modules::auth::DigestAuth::generate_nonce();
                AuthResult::DigestChallenge(d.challenge(&nonce))
            }
        }
        // ForwardAuth runs as a separate async subrequest in the
        // calling site; the result, including any trust headers
        // carrying the resolved user, lands on `ctx` after this
        // function returns. Treat it as an anonymous allow at the
        // dispatch layer; the post-auth capture step picks the user
        // out of `ctx.trust_headers` instead.
        Auth::ForwardAuth(_) => AuthResult::allow_anonymous(),
        Auth::BotAuth(b) => {
            use sbproxy_modules::auth::BotAuthVerdict;
            // Synthesize a minimal http::Request the verifier can read
            // method / target-uri / headers from. Verification runs
            // before the body is buffered, so we pass an empty body;
            // signatures that cover content-digest (rare for bot
            // crawlers) will fail and surface in the verdict.
            //
            // Reconstruct the path-and-query exactly as it appeared on
            // the request line so the RFC 9421 `@target-uri` / `@path`
            // / `@query` derived components match what the signer
            // covered. Falling back to `/` would silently accept
            // signatures bound to a different path.
            let target_uri = match query {
                Some(q) if !q.is_empty() => format!("{}?{}", path, q),
                _ => path.to_string(),
            };
            let builder = http::Request::builder().method(method);
            let mut req = match builder.uri(target_uri.as_str()).body(bytes::Bytes::new()) {
                Ok(r) => r,
                Err(_) => return AuthResult::Deny(500, "bot_auth: bad request".to_string()),
            };
            *req.headers_mut() = headers.clone();
            match b.verify(&req) {
                BotAuthVerdict::Verified { agent_name } => {
                    tracing::info!(agent = %agent_name, "bot_auth verified");
                    AuthResult::allow_anonymous()
                }
                BotAuthVerdict::Missing => {
                    AuthResult::Deny(401, "bot_auth: signature required".to_string())
                }
                BotAuthVerdict::UnknownAgent { key_id } => {
                    AuthResult::Deny(401, format!("bot_auth: unknown agent keyid {}", key_id))
                }
                BotAuthVerdict::Failed { agent_name, reason } => {
                    let agent = agent_name.unwrap_or_else(|| "<unknown>".to_string());
                    tracing::warn!(agent = %agent, reason = %reason, "bot_auth verification failed");
                    AuthResult::Deny(401, "bot_auth: verification failed".to_string())
                }
                BotAuthVerdict::DirectoryUnavailable { reason } => {
                    // Wave 1 / G1.7: directory-side failure (HTTPS
                    // violation, allowlist mismatch, fetch deadline,
                    // self-signature failure, stale grace exceeded).
                    // Map to 401 like the other unsigned variants;
                    // the deny message stays generic so it does not
                    // leak directory state to a probing client.
                    tracing::warn!(reason = %reason, "bot_auth directory unavailable");
                    AuthResult::Deny(401, "bot_auth: directory unavailable".to_string())
                }
            }
        }
        Auth::Cap(verifier) => {
            use sbproxy_modules::auth::CapVerdict;
            // CAP verification needs the request host (for `aud`) and
            // path (for `glob`). The resolved agent_id binding is
            // pulled from the Wave 1 resolver chain when present;
            // without an upstream resolver, the verifier accepts any
            // sub.
            //
            // Reconstruct the request shape so the verifier can read
            // headers + host. Body is empty: the verifier never reads
            // it. Path-and-query mirror the on-the-wire request line
            // so future extensions that bind the glob to the query do
            // not regress.
            let target_uri = match query {
                Some(q) if !q.is_empty() => format!("{}?{}", path, q),
                _ => path.to_string(),
            };
            let host = headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("")
                .to_string();
            let builder = http::Request::builder().method(method);
            let mut req = match builder.uri(target_uri.as_str()).body(bytes::Bytes::new()) {
                Ok(r) => r,
                Err(_) => return AuthResult::Deny(500, "cap: bad request".to_string()),
            };
            *req.headers_mut() = headers.clone();
            // Resolved agent_id from the Wave 1 resolver chain is not
            // plumbed into this synchronous dispatch site yet; pass
            // None so the verifier skips the binding check. Stamping
            // the resolved id is a follow-up tracked in WATCH.md.
            match verifier.verify(&req, &host, path, None) {
                CapVerdict::Verified(_view) => AuthResult::allow_anonymous(),
                CapVerdict::Missing => AuthResult::Deny(401, "cap: token required".to_string()),
                CapVerdict::Invalid(err) => {
                    let status = err.http_status();
                    AuthResult::Deny(status, format!("cap: {}", err.www_auth_code()))
                }
            }
        }
        Auth::Noop => AuthResult::allow_anonymous(),
        Auth::Plugin(provider) => {
            // Build a synthetic http::Request the provider can read
            // method / target-uri / headers from. We deliberately pass
            // an empty body: auth runs before the request body is
            // buffered, and dragging the (potentially large) body in
            // here would force every plugin call to pay for a buffer
            // it almost never needs. Providers that genuinely need
            // body bytes (rare for auth) should arrange to read them
            // out of the session via a transform / hook instead.
            let target_uri = match query {
                Some(q) if !q.is_empty() => format!("{}?{}", path, q),
                _ => path.to_string(),
            };
            let builder = http::Request::builder().method(method);
            let mut req = match builder.uri(target_uri.as_str()).body(bytes::Bytes::new()) {
                Ok(r) => r,
                Err(_) => {
                    return AuthResult::Deny(
                        500,
                        format!(
                            "auth plugin {:?}: failed to build request",
                            provider.auth_type()
                        ),
                    );
                }
            };
            *req.headers_mut() = headers.clone();

            // The trait threads `&mut dyn Any` for per-request state.
            // The pipeline does not yet plumb a typed context through
            // here; pass a placeholder unit so providers that ignore
            // ctx (the common case) work transparently. When a typed
            // request context lands, swap the placeholder for it.
            let mut ctx: () = ();
            match provider.authenticate(&req, &mut ctx).await {
                Ok(sbproxy_plugin::AuthDecision::Allow { sub, source }) => {
                    AuthResult::Allow { sub, source }
                }
                Ok(sbproxy_plugin::AuthDecision::Deny { status, message }) => {
                    AuthResult::Deny(status, message)
                }
                Ok(sbproxy_plugin::AuthDecision::DenyWithHeaders {
                    status,
                    message,
                    headers,
                }) => AuthResult::DenyWithHeaders(status, message, headers),
                Err(err) => {
                    tracing::warn!(
                        plugin = %provider.auth_type(),
                        error = %err,
                        "auth plugin returned error; denying request",
                    );
                    AuthResult::Deny(500, format!("auth plugin {:?} error", provider.auth_type()))
                }
            }
        }
    }
}

/// Lazily-initialized HTTP client for forward-auth subrequests. A
/// single pooled client across all requests avoids the per-request
/// socket and TLS-handshake cost of constructing a fresh
/// `reqwest::Client`. The per-call `fwd.timeout` is applied as a
/// request-scoped deadline below.
static FORWARD_AUTH_CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("forward-auth reqwest::Client build must succeed")
});

/// Run forward auth by making an HTTP subrequest to the auth service.
async fn check_forward_auth(
    fwd: &sbproxy_modules::auth::ForwardAuthProvider,
    request_headers: &http::HeaderMap,
) -> std::result::Result<Vec<(String, String)>, (u16, String)> {
    let client = &*FORWARD_AUTH_CLIENT;
    let timeout = std::time::Duration::from_secs(fwd.timeout.unwrap_or(5));

    let method_str = fwd.method.as_deref().unwrap_or("GET");
    let req_method = method_str
        .parse::<reqwest::Method>()
        .unwrap_or(reqwest::Method::GET);
    let mut req = client.request(req_method, &fwd.url).timeout(timeout);

    for header_name in &fwd.headers_to_forward {
        if let Some(val) = request_headers.get(header_name.as_str()) {
            if let Ok(val_str) = val.to_str() {
                req = req.header(header_name.as_str(), val_str);
            }
        }
    }

    let response = req.send().await.map_err(|e| {
        warn!(error = %e, url = %fwd.url, "forward auth request failed");
        (503u16, "auth service unavailable".to_string())
    })?;

    let status = response.status().as_u16();
    let success = fwd.success_status.map_or(status == 200, |s| status == s);

    if success {
        let mut forwarded = Vec::new();
        for header_name in &fwd.trust_headers {
            if let Some(val) = response.headers().get(header_name.as_str()) {
                if let Ok(val_str) = val.to_str() {
                    forwarded.push((header_name.clone(), val_str.to_string()));
                }
            }
        }
        Ok(forwarded)
    } else {
        Err((401u16, "unauthorized".to_string()))
    }
}

/// Emit a `security_audit` entry for an authentication failure.
/// Centralised so every Deny / Challenge / forward-auth-Err arm uses
/// the same audit shape; the `event_type` argument differentiates
/// the failure mode in the SIEM.
fn emit_auth_audit(
    event_type: &'static str,
    auth_type: &str,
    status: u16,
    origin_label: &str,
    ctx: &RequestContext,
    session: &Session,
) {
    sbproxy_observe::SecurityAuditEntry::auth_failure(
        event_type,
        auth_type,
        status,
        Some(origin_label.to_string()),
        ctx.client_ip,
        Some(ctx.request_id.to_string()),
        Some(session.req_header().method.as_str().to_string()),
    )
    .emit();
}

/// Find the resolved user identifier in a forward-auth response's
/// trust headers. Scans the configured trust-header list for any of
/// the conventional names the auth gateway ecosystem (Authelia,
/// Caddy forward_auth, Traefik forwardAuth, oauth2-proxy) uses to
/// stamp the authenticated user. Returns the first non-empty match
/// (case-insensitive on the header name).
fn forward_auth_user_from_trust_headers(headers: &[(String, String)]) -> Option<String> {
    const USER_HEADERS: &[&str] = &[
        "x-forwarded-user",
        "x-auth-request-user",
        "x-auth-user",
        "x-user",
        "remote-user",
    ];
    for (name, value) in headers {
        let n = name.to_ascii_lowercase();
        if USER_HEADERS.contains(&n.as_str()) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

// --- Policy checking ---

/// Result of running policy checks on a request.
enum PolicyResult {
    /// All policies passed, with optional rate limit info for response headers.
    Allow(Option<RateLimitInfo>),
    /// A policy rejected the request with this status, message, optional
    /// rate-limit metadata, and the stable label of the enforcing
    /// policy (`rate_limit`, `waf`, `ip_filter`, ...). The label
    /// flows through to the `sbproxy_policy_triggers_total` metric
    /// and the security-audit channel so dashboards and SIEM rules
    /// can break down by enforcing module instead of guessing from
    /// the response status.
    Deny(u16, String, Option<RateLimitInfo>, &'static str),
}

/// Evaluate a rate-limit `key:` CEL expression against the current
/// request. Returns the result coerced to a string when evaluation
/// succeeds and produces a non-empty value, otherwise `None` so the
/// caller can fall back to the default IP-based key.
fn rate_limit_key_from_cel(session: &Session, ctx: &RequestContext, expr: &str) -> Option<String> {
    use sbproxy_extension::cel::context::{
        build_request_context, populate_envelope_namespace, EnvelopeView,
    };
    use sbproxy_extension::cel::{CelEngine, CelValue};

    let req = session.req_header();
    let method = req.method.as_str();
    let path = req.uri.path();
    let query = req.uri.query();
    let client_ip = ctx.client_ip.map(|ip| ip.to_string());

    let mut cel_ctx = build_request_context(
        method,
        path,
        &req.headers,
        query,
        client_ip.as_deref(),
        ctx.hostname.as_str(),
    );
    // T2.3 / T3.3: expose the Wave 8 envelope so rate-limit keys can
    // bucket per session_id / user_id without inventing new CEL
    // syntax. Default empty strings keep `expr` evaluable even when
    // the corresponding dimension never resolved.
    let session_str = ctx.session_id.map(|s| s.to_string());
    let parent_str = ctx.parent_session_id.map(|s| s.to_string());
    let envelope = EnvelopeView {
        user_id: ctx.user_id.as_deref(),
        user_id_source: ctx.user_id_source.map(|s| s.as_str()),
        session_id: session_str.as_deref(),
        parent_session_id: parent_str.as_deref(),
        workspace_id: None,
        properties: Some(&ctx.properties),
    };
    populate_envelope_namespace(&mut cel_ctx, &envelope);

    let engine = CelEngine::new();
    let value = match engine.eval_source(expr, &cel_ctx) {
        Ok(v) => v,
        Err(err) => {
            warn!(error = %err, expression = expr, "rate-limit key CEL evaluation failed; falling back to default key");
            return None;
        }
    };
    let s = match value {
        CelValue::String(s) => s,
        CelValue::Int(i) => i.to_string(),
        CelValue::Float(f) => f.to_string(),
        CelValue::Bool(b) => b.to_string(),
        CelValue::Null => return None,
        CelValue::Map(_) | CelValue::List(_) => {
            warn!(
                expression = expr,
                "rate-limit key CEL expression produced a map/list; falling back to default key"
            );
            return None;
        }
    };
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Decide whether the inbound request is on HTTPS.
///
/// The decision is:
///
/// 1. The listener itself is TLS (Pingora gave us an `ssl_digest`).
///    Authoritative; ignore everything else.
/// 2. The immediate TCP peer is in the operator's
///    `proxy.trusted_proxies` set AND the inbound `X-Forwarded-Proto`
///    header says `https`. Honoured because the trusted hop is in a
///    better position to know the original scheme than we are.
/// 3. Otherwise: plain HTTP.
///
/// Splitting this out as a pure function makes the WOR-46 fix
/// regression-testable without a full Pingora `Session`.
fn is_request_https(listener_is_tls: bool, peer_trusted: bool, xfp: Option<&str>) -> bool {
    if listener_is_tls {
        return true;
    }
    if !peer_trusted {
        return false;
    }
    matches!(xfp, Some(v) if v.eq_ignore_ascii_case("https"))
}

/// SSRF guard for an upstream URL we are about to dial.
///
/// Reconstructs the URL string from the action's already-parsed
/// (host, port, tls) tuple and runs it through
/// [`sbproxy_security::validate_url_resolved`]. Hosts that match
/// the operator-supplied `allow_private_cidrs` allowlist are
/// permitted to resolve to private addresses; all other private,
/// loopback, link-local, CGNAT, and metadata addresses are rejected
/// before [`HttpPeer`] construction. The resolved address is then
/// re-checked against [`sbproxy_security::is_private_ip`] as a
/// defence against DNS rebinding (the resolver could return a
/// different answer between validation and dial time).
///
/// On success returns the validated [`std::net::SocketAddr`] so the
/// caller can pin the dial to it. On failure returns a Pingora
/// `Error` shaped as a `ConnectError` so the response surfaces as a
/// generic 502.
fn guard_upstream(
    host: &str,
    port: u16,
    tls: bool,
    allow_private_cidrs: &[ipnetwork::IpNetwork],
) -> Result<()> {
    use sbproxy_security::ssrf;
    let scheme = if tls { "https" } else { "http" };
    // We rebuild a URL just for the validator. IPv6 hosts must be
    // bracketed; everything else passes through.
    let host_part = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let candidate = format!("{scheme}://{host_part}:{port}/");

    // The allowlist is applied to the URL host only when the parsed
    // host is an IP. For hostname URLs, we check whether any
    // resolved IP falls in an allowed CIDR after `validate_url_resolved`
    // returns.
    let host_string = host.to_string();
    let host_allowlist = vec![host_string.clone()];

    // First pass: cheap reject for non-allowlisted private literals.
    match ssrf::validate_url_resolved(&candidate, &[]) {
        Ok(resolved) => {
            // Re-check resolved addresses against `is_private_ip`,
            // honouring the operator's allow_private_cidrs override.
            for addr in &resolved.addrs {
                let ip = addr.ip();
                if ssrf::is_private_ip(&ip)
                    && !allow_private_cidrs.iter().any(|net| net.contains(ip))
                {
                    warn!(
                        upstream_host = %host,
                        upstream_ip = %ip,
                        "SSRF: blocked upstream resolving to private IP",
                    );
                    return Err(Error::because(
                        ErrorType::ConnectError,
                        "SSRF: upstream resolved to private network",
                        anyhow::anyhow!("blocked private IP {ip}"),
                    ));
                }
            }
            Ok(())
        }
        Err(reason) => {
            // Validation failed. If the operator allow-listed the URL
            // host (or one of its resolved IPs), retry with the
            // allowlist; otherwise reject.
            if allow_private_cidrs.is_empty() {
                warn!(
                    upstream_host = %host,
                    reason = %reason,
                    "SSRF: blocked upstream URL",
                );
                return Err(Error::because(
                    ErrorType::ConnectError,
                    "SSRF: blocked upstream URL",
                    anyhow::anyhow!(reason),
                ));
            }
            // Retry with hostname allowlist so the validator returns
            // the resolved set without rejecting on private IPs; we
            // then enforce allow_private_cidrs ourselves.
            match ssrf::validate_url_resolved(&candidate, &host_allowlist) {
                Ok(resolved) => {
                    for addr in &resolved.addrs {
                        let ip = addr.ip();
                        if ssrf::is_private_ip(&ip)
                            && !allow_private_cidrs.iter().any(|net| net.contains(ip))
                        {
                            warn!(
                                upstream_host = %host,
                                upstream_ip = %ip,
                                "SSRF: blocked upstream resolving to private IP outside allow_private_cidrs",
                            );
                            return Err(Error::because(
                                ErrorType::ConnectError,
                                "SSRF: upstream resolved to private network",
                                anyhow::anyhow!("blocked private IP {ip}"),
                            ));
                        }
                    }
                    Ok(())
                }
                Err(reason) => {
                    warn!(
                        upstream_host = %host,
                        reason = %reason,
                        "SSRF: blocked upstream URL (with allowlist retry)",
                    );
                    Err(Error::because(
                        ErrorType::ConnectError,
                        "SSRF: blocked upstream URL",
                        anyhow::anyhow!(reason),
                    ))
                }
            }
        }
    }
}

/// Parse a `resolve_override` value into a `host:port` connect string.
/// Accepts `"ip"`, `"ip:port"`, or `"[ipv6]:port"` forms; falls back
/// to combining the override with the URL's port when no port is
/// supplied.
fn resolve_addr_override(over: &str, default_port: u16) -> String {
    let trimmed = over.trim();
    // IPv6 bracketed form: [::1]:8443 or [::1]
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(close) = rest.find(']') {
            let host = &rest[..close];
            let after = &rest[close + 1..];
            return if let Some(port) = after.strip_prefix(':') {
                format!("[{}]:{}", host, port)
            } else {
                format!("[{}]:{}", host, default_port)
            };
        }
    }
    // host:port (with no IPv6 brackets) - split on the *last* colon
    // so IPv4 forms parse cleanly and bare-IPv6 forms (rare without
    // brackets) still pin to the default port.
    if let Some(idx) = trimmed.rfind(':') {
        let head = &trimmed[..idx];
        let tail = &trimmed[idx + 1..];
        // If the head still contains a colon, the input is an unbracketed
        // IPv6 address - pin to default port and bracket on output.
        if head.contains(':') {
            return format!("[{}]:{}", trimmed, default_port);
        }
        if tail.parse::<u16>().is_ok() {
            return format!("{}:{}", head, tail);
        }
    }
    format!("{}:{}", trimmed, default_port)
}

/// Run all policies for an origin. Returns Allow or Deny with status/message.
///
/// Async because rate-limit policies with an attached L2 (Redis) store must
/// call `allow_with_info_async`, which internally uses `spawn_blocking` to
/// issue the blocking Redis INCR. Local-only token-bucket rate limiters
/// short-circuit synchronously inside `allow_with_info_async` without hitting
/// the runtime.
async fn check_policies(
    policies: &[Policy],
    session: &Session,
    ctx: &mut RequestContext,
) -> PolicyResult {
    let mut rate_limit_info: Option<RateLimitInfo> = None;

    // Derive a stable per-request client identifier used as the Redis
    // counter suffix. Falls back to the hostname when the client IP is
    // unavailable (e.g. internal traffic).
    let default_client_id = ctx
        .client_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| ctx.hostname.to_string());

    for policy in policies {
        match policy {
            Policy::RateLimit(p) => {
                let client_id = match p.key.as_deref() {
                    None => default_client_id.clone(),
                    Some(expr) => rate_limit_key_from_cel(session, ctx, expr)
                        .unwrap_or_else(|| default_client_id.clone()),
                };
                let info = p.allow_with_info_async(&client_id).await;
                if !info.allowed {
                    return PolicyResult::Deny(
                        429,
                        "rate limited".to_string(),
                        Some(info),
                        "rate_limit",
                    );
                }
                rate_limit_info = Some(info);
            }
            Policy::IpFilter(p) => {
                if let Some(ip) = ctx.client_ip {
                    if !p.check_ip(&ip) {
                        return PolicyResult::Deny(403, "forbidden".to_string(), None, "ip_filter");
                    }
                }
            }
            Policy::RequestLimit(p) => {
                let header_count = session.req_header().headers.len();
                let url_len = session.req_header().uri.to_string().len();
                let query_len = session
                    .req_header()
                    .uri
                    .query()
                    .map(|q| q.len())
                    .unwrap_or(0);
                // Find the largest header value size.
                let max_header_size = session
                    .req_header()
                    .headers
                    .values()
                    .map(|v| v.len())
                    .max()
                    .unwrap_or(0);
                // Pull declared body size from `Content-Length` so honest
                // clients are rejected up-front before any body bytes
                // arrive. Chunked / unknown-length uploads still hit the
                // streaming check below.
                let declared_body_size = session
                    .req_header()
                    .headers
                    .get(http::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(0);
                if let Err(msg) = p.check_request(
                    declared_body_size,
                    header_count,
                    max_header_size,
                    url_len,
                    query_len,
                ) {
                    debug!(detail = %msg, "request limit exceeded");
                    return PolicyResult::Deny(
                        413,
                        "request entity too large".to_string(),
                        None,
                        "request_limit",
                    );
                }
                // Forward the body-size cap to the streaming filter so
                // chunked / unknown-length uploads are also enforced
                // once the bytes are seen. This also catches clients
                // that lie about Content-Length.
                if let Some(max) = p.max_body_size {
                    let cap = ctx.body_size_limit.map(|c| c.min(max)).unwrap_or(max);
                    ctx.body_size_limit = Some(cap);
                }
            }
            Policy::Waf(w) => {
                let uri = session.req_header().uri.to_string();
                let headers = &session.req_header().headers;
                match w.check_request(&uri, headers, None) {
                    WafResult::Clean => {}
                    WafResult::Blocked(msg) => {
                        return PolicyResult::Deny(403, msg, None, "waf");
                    }
                    WafResult::Error(err) => {
                        if w.fail_open {
                            warn!(error = %err, "WAF engine error, fail_open=true, allowing request");
                        } else {
                            warn!(error = %err, "WAF engine error, fail_open=false, blocking request");
                            return PolicyResult::Deny(
                                403,
                                "WAF engine error".to_string(),
                                None,
                                "waf",
                            );
                        }
                    }
                }
            }
            // SecHeaders / PageShield run in the response phase. Sri runs
            // alongside response transforms. Plugin policies run via the
            // plugin dispatch.
            Policy::SecHeaders(_) | Policy::PageShield(_) | Policy::Sri(_) | Policy::Plugin(_) => {}
            Policy::HttpFraming(p) => {
                // Defense against the request-smuggling / desync class
                // documented at portswigger.net/research/http-desync-attacks-request-smuggling-reborn.
                // Pingora's parser strictness handles the wire-level
                // malformed input; this policy adds the
                // semantic-ambiguity layer (CL+TE, duplicate CL,
                // malformed TE, duplicate TE, control chars).
                //
                // Three observable signals on every block:
                //   1. sbproxy_http_framing_blocks_total{reason}
                //      (Prometheus, low-cardinality)
                //   2. tracing::warn target=sbproxy::http_framing
                //      (operational log alongside other policy events)
                //   3. SecurityAuditEntry on target=security_audit
                //      (dedicated security log for SIEM forwarding)
                if let Err(violation) = p.check_request(&session.req_header().headers) {
                    let reason = violation.metric_reason();
                    sbproxy_observe::metrics::record_http_framing_block(reason);
                    tracing::warn!(
                        target: "sbproxy::http_framing",
                        reason = %reason,
                        hostname = %ctx.hostname,
                        "blocked: HTTP framing violation"
                    );
                    sbproxy_observe::SecurityAuditEntry::framing_violation(
                        reason,
                        Some(ctx.hostname.to_string()),
                        ctx.client_ip,
                        Some(ctx.request_id.to_string()),
                        Some(session.req_header().method.as_str().to_string()),
                    )
                    .emit();
                    return PolicyResult::Deny(
                        400,
                        violation.message().to_string(),
                        None,
                        "http_framing",
                    );
                }
            }
            Policy::Ddos(p) => {
                use sbproxy_modules::DdosCheckResult;
                if let Some(ip) = ctx.client_ip {
                    if let DdosCheckResult::Block { retry_after_secs } = p.check(ip) {
                        // Synthesize a RateLimitInfo so the existing
                        // 429 response path emits a Retry-After header.
                        let info = RateLimitInfo {
                            allowed: false,
                            limit: p.requests_per_second as u64,
                            remaining: 0,
                            reset_secs: retry_after_secs,
                            headers_enabled: true,
                            include_retry_after: true,
                        };
                        return PolicyResult::Deny(
                            429,
                            "ddos protection: too many requests".to_string(),
                            Some(info),
                            "ddos",
                        );
                    }
                }
            }
            Policy::ExposedCreds(p) => {
                use sbproxy_modules::{ExposedCredsAction, ExposedCredsResult};
                if let ExposedCredsResult::Hit { reason } = p.check(&session.req_header().headers) {
                    match p.action() {
                        ExposedCredsAction::Block => {
                            return PolicyResult::Deny(
                                403,
                                "credential flagged as exposed".to_string(),
                                None,
                                "exposed_credentials",
                            );
                        }
                        ExposedCredsAction::Tag => {
                            let entry = (p.header_name().to_string(), reason.to_string());
                            match ctx.trust_headers.as_mut() {
                                Some(v) => v.push(entry),
                                None => ctx.trust_headers = Some(vec![entry]),
                            }
                        }
                    }
                }
            }
            // RequestValidator is body-required and runs in
            // request_body_filter once the body is fully buffered.
            // Mark the context so the body filter knows to accumulate.
            Policy::RequestValidator(_) | Policy::OpenApiValidation(_) => {
                ctx.validate_request_body = true;
            }
            Policy::PromptInjectionV2(p) => {
                use sbproxy_modules::{PromptInjectionAction, PromptInjectionV2Outcome};
                // Run detection at request_filter time on the
                // request-line text + headers so the tag-action path
                // can stamp trust headers before
                // `upstream_request_filter` builds the upstream
                // request. Body-aware detection (the prompt usually
                // lives in the JSON body) lands with the ONNX
                // classifier follow-up; for the OSS scaffold the
                // heuristic detector still fires on injection
                // vocabulary present in the URL or in custom headers
                // (a real-world pattern: chat consoles that send the
                // prompt as a `q=` query parameter), and operators
                // who want body-aware detection today should pair the
                // policy with `request_validator` or use the v1
                // `prompt_injection` guardrail inside `ai_proxy`.
                let req = session.req_header();
                let mut prompt = req.uri.to_string();
                for (name, value) in req.headers.iter() {
                    let n = name.as_str();
                    // Skip auth-class headers so tokens carried by
                    // design don't self-flag, mirroring DLP.
                    if n == "authorization" || n == "cookie" || n == "set-cookie" {
                        continue;
                    }
                    if let Ok(v) = value.to_str() {
                        prompt.push('\n');
                        prompt.push_str(v);
                    }
                }
                if let PromptInjectionV2Outcome::Hit { result } = p.evaluate(&prompt) {
                    match p.action() {
                        PromptInjectionAction::Block => {
                            tracing::warn!(
                                target: "sbproxy::prompt_injection_v2",
                                detector = %p.detector_name(),
                                score = %result.score,
                                label = %result.label,
                                reason = ?result.reason,
                                "blocked: detector matched"
                            );
                            return PolicyResult::Deny(
                                403,
                                p.block_body().to_string(),
                                None,
                                "prompt_injection",
                            );
                        }
                        PromptInjectionAction::Tag => {
                            let score_entry =
                                (p.score_header().to_string(), format!("{:.3}", result.score));
                            let label_entry = (
                                p.label_header().to_string(),
                                result.label.as_str().to_string(),
                            );
                            match ctx.trust_headers.as_mut() {
                                Some(v) => {
                                    v.push(score_entry);
                                    v.push(label_entry);
                                }
                                None => {
                                    ctx.trust_headers = Some(vec![score_entry, label_entry]);
                                }
                            }
                        }
                        PromptInjectionAction::Log => {
                            tracing::warn!(
                                target: "sbproxy::prompt_injection_v2",
                                detector = %p.detector_name(),
                                score = %result.score,
                                label = %result.label,
                                reason = ?result.reason,
                                "prompt injection detected (log mode)"
                            );
                        }
                    }
                }
            }
            Policy::AiCrawl(p) => {
                use sbproxy_modules::AiCrawlDecision;
                let req = session.req_header();
                let method = req.method.as_str();
                let path = req.uri.path();
                // G1.4 -> G3.6 thread: pass the resolved agent identifier
                // through to the quote-token signer so the JWS `sub` claim
                // is the resolved id, not the Wave 1 `"unknown"` placeholder.
                // Feature-gated because `agent_id` only exists on the
                // context when the `agent-class` feature is enabled.
                #[cfg(feature = "agent-class")]
                let agent_id_str: Option<String> =
                    ctx.agent_id.as_ref().map(|aid| aid.as_str().to_string());
                #[cfg(feature = "agent-class")]
                let agent_id_param: Option<&str> = agent_id_str.as_deref();
                #[cfg(not(feature = "agent-class"))]
                let agent_id_param: Option<&str> = None;
                // --- G4.4 + G4.10 closeout: resolve the matched tier's
                // `citation_required` flag and stamp it into the
                // request context so downstream transforms read a
                // single source of truth. The lookup mirrors the one
                // in `AiCrawlControlPolicy::check`; a separate call is
                // unfortunate but unavoidable without widening the
                // policy's return type. The cost is one tier-list scan
                // per request that already runs the full AiCrawl path.
                {
                    let accept = req
                        .headers
                        .get(http::header::ACCEPT)
                        .and_then(|v| v.to_str().ok());
                    let agent_id_for_tier = agent_id_param.unwrap_or("");
                    if let Some(tier) = p.matched_tier_for_request(path, agent_id_for_tier, accept)
                    {
                        ctx.citation_required = Some(tier.citation_required);
                    }
                }
                match p.check(method, &ctx.hostname, path, &req.headers, agent_id_param) {
                    AiCrawlDecision::Allow => {}
                    AiCrawlDecision::Charge { body, challenge } => {
                        ctx.crawl_challenge = Some((p.header_name().to_string(), challenge, body));
                        return PolicyResult::Deny(
                            402,
                            "payment required".to_string(),
                            None,
                            "ai_crawl_payment",
                        );
                    }
                    AiCrawlDecision::MultiRail { body, content_type } => {
                        // G3.4 multi-rail body. We piggyback on the
                        // existing crawl_challenge slot: the second tuple
                        // element carries the Content-Type for the
                        // response writer; the third carries the JSON
                        // body. The header name is replaced by a sentinel
                        // (`Content-Type`) so the response writer knows
                        // to stamp Content-Type instead of the Wave 1
                        // Crawler-Payment header.
                        ctx.crawl_challenge =
                            Some(("Content-Type".to_string(), content_type.to_string(), body));
                        return PolicyResult::Deny(
                            402,
                            "payment required".to_string(),
                            None,
                            "ai_crawl_multi_rail",
                        );
                    }
                    AiCrawlDecision::NoAcceptableRail { body } => {
                        // 406 Not Acceptable: agent's Accept-Payment list
                        // has no overlap with the configured rails. The
                        // body lists the supported rails so the agent can
                        // recover; we surface it through the same slot.
                        ctx.crawl_challenge = Some((
                            "Content-Type".to_string(),
                            "application/json".to_string(),
                            body,
                        ));
                        return PolicyResult::Deny(
                            406,
                            "no acceptable rail".to_string(),
                            None,
                            "ai_crawl_no_acceptable_rail",
                        );
                    }
                    AiCrawlDecision::LedgerUnavailable {
                        body,
                        retry_after_seconds,
                    } => {
                        // Reuse the 402 challenge response slot to carry
                        // the 503 body; the response writer reads from
                        // ctx.crawl_challenge whenever the deny status
                        // is 402, so for 503 we pass the body through
                        // RateLimitInfo + the deny message.
                        //
                        // NB: a future refactor may give 503-from-policy
                        // its own response slot; for Wave 1 we synthesize
                        // a RateLimitInfo so the existing Retry-After
                        // emission path covers us.
                        ctx.crawl_challenge =
                            Some((p.header_name().to_string(), String::new(), body));
                        let info = RateLimitInfo {
                            allowed: false,
                            limit: 0,
                            remaining: 0,
                            reset_secs: retry_after_seconds as u64,
                            headers_enabled: false,
                            include_retry_after: true,
                        };
                        return PolicyResult::Deny(
                            503,
                            "ledger unavailable".to_string(),
                            Some(info),
                            "ai_crawl_ledger_unavailable",
                        );
                    }
                }
            }
            Policy::Dlp(p) => {
                use sbproxy_modules::{DlpAction, DlpScanResult};
                let req = session.req_header();
                let path_and_query = req.uri.to_string();
                if let DlpScanResult::Hit { detectors } = p.scan(&path_and_query, &req.headers) {
                    let detector_csv = detectors.join(",");
                    match p.action() {
                        DlpAction::Block => {
                            return PolicyResult::Deny(
                                403,
                                format!("dlp: detector {detector_csv} matched"),
                                None,
                                "dlp",
                            );
                        }
                        DlpAction::Tag => {
                            let entry = (p.header_name().to_string(), detector_csv);
                            match ctx.trust_headers.as_mut() {
                                Some(v) => v.push(entry),
                                None => ctx.trust_headers = Some(vec![entry]),
                            }
                        }
                    }
                }
            }
            Policy::ConcurrentLimit(p) => {
                let origin_id = ctx.origin_idx.map(|i| i.to_string()).unwrap_or_default();
                let client_ip_str = ctx.client_ip.map(|ip| ip.to_string());
                let key = p.resolve_key(
                    &origin_id,
                    client_ip_str.as_deref(),
                    &session.req_header().headers,
                );
                match p.try_acquire(&key) {
                    Some(guard) => ctx.concurrent_limit_guards.push(guard),
                    None => {
                        debug!(key = %key, max = %p.max, "concurrent limit exceeded");
                        return PolicyResult::Deny(
                            p.status,
                            "too many concurrent requests".to_string(),
                            None,
                            "concurrent_limit",
                        );
                    }
                }
            }
            Policy::Csrf(csrf) => {
                let method = session.req_header().method.as_str();
                let path = session.req_header().uri.path();

                // Check if path is exempt.
                let exempt = csrf
                    .exempt_paths
                    .iter()
                    .any(|p| path.starts_with(p.as_str()));
                if !exempt {
                    let is_protected = csrf.is_protected_method(method);
                    if !is_protected {
                        let timestamp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos();
                        let token = match csrf_token(
                            csrf.secret_key.as_str(),
                            timestamp,
                            ctx.hostname.as_str(),
                        ) {
                            Ok(t) => t,
                            Err(e) => {
                                warn!(error = %e, "csrf: token generation failed");
                                return PolicyResult::Deny(
                                    500,
                                    "CSRF token generation failed".to_string(),
                                    None,
                                    "csrf",
                                );
                            }
                        };
                        let cookie_path = csrf.cookie_path.as_deref().unwrap_or("/");
                        let same_site = csrf.cookie_same_site.as_deref().unwrap_or("Lax");
                        let is_secure = session
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
                        let mut cookie = format!(
                            "{}={}; Path={}; SameSite={}",
                            csrf.cookie_name, token, cookie_path, same_site,
                        );
                        if is_secure {
                            cookie.push_str("; Secure");
                        }
                        ctx.csrf_cookie = Some(cookie);
                    } else {
                        // Unsafe method: validate token from header matches cookie.
                        let header_token = session
                            .req_header()
                            .headers
                            .get(csrf.header_name.as_str())
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        let cookie_token = session
                            .req_header()
                            .headers
                            .get("cookie")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|cookies| {
                                cookies.split(';').find_map(|c| {
                                    let c = c.trim();
                                    let (name, value) = c.split_once('=')?;
                                    if name.trim() == csrf.cookie_name {
                                        Some(value.trim().to_string())
                                    } else {
                                        None
                                    }
                                })
                            })
                            .unwrap_or_default();
                        if header_token.is_empty()
                            || cookie_token.is_empty()
                            || header_token != cookie_token
                        {
                            return PolicyResult::Deny(
                                403,
                                "CSRF token missing or invalid".to_string(),
                                None,
                                "csrf",
                            );
                        }
                    }
                }
            }
            Policy::Expression(p) => {
                let method = session.req_header().method.as_str();
                let path = session.req_header().uri.path();
                let headers = &session.req_header().headers;
                let query = session.req_header().uri.query();
                let client_ip_str = ctx.client_ip.map(|ip| ip.to_string());
                // Wave 4 / G4.9 + Wave 5 / G5.1, A5.2: thread the
                // parsed aipref signal, the KYA verdict, and the ML
                // classifier verdict so CEL expressions can branch on
                // `request.aipref.*`, `request.kya.*`, and
                // `request.ml_classification.*` without owning the
                // verifier / classifier themselves.
                #[cfg(feature = "agent-class")]
                let kya_view = Some(sbproxy_extension::cel::context::KyaVerdictView {
                    verdict: ctx.kya_verdict,
                    agent_id: ctx.agent_id.as_ref().map(|id| id.as_str()),
                    vendor: ctx.kya_vendor.as_deref(),
                    kya_version: ctx.kya_version.as_deref(),
                    kyab_balance: ctx.kya_kyab_balance,
                });
                #[cfg(not(feature = "agent-class"))]
                let kya_view: Option<
                    sbproxy_extension::cel::context::KyaVerdictView<'_>,
                > = None;

                #[cfg(feature = "agent-classifier")]
                let ml_view = ctx.ml_classification.as_ref().map(|m| {
                    sbproxy_extension::cel::context::MlClassificationView {
                        class: Some(m.class.as_str()),
                        confidence: Some(m.confidence),
                        model_version: Some(m.model_version),
                        feature_schema_version: Some(m.feature_schema_version),
                    }
                });
                #[cfg(not(feature = "agent-classifier"))]
                let ml_view: Option<
                    sbproxy_extension::cel::context::MlClassificationView<'_>,
                > = None;

                let views = sbproxy_modules::ExpressionViews {
                    aipref: ctx.aipref.as_ref(),
                    kya: kya_view,
                    ml: ml_view,
                };
                if !p.evaluate_with_views(
                    method,
                    path,
                    headers,
                    query,
                    client_ip_str.as_deref(),
                    &ctx.hostname,
                    views,
                ) {
                    return PolicyResult::Deny(
                        p.deny_status,
                        p.deny_message.clone(),
                        None,
                        "expression",
                    );
                }
            }
            Policy::Assertion(_) => {} // Assertions are response-phase (informational)
            // G1.4 wire: the agent_class policy is a marker. The
            // resolver runs in `request_filter` via
            // `core::agent_class::stamp_request_context`, so this arm
            // has nothing to enforce at policy-evaluation time. A
            // future wave will read the per-policy header_name knobs
            // here when the upstream-header stamping moves out of the
            // request_filter and into the policy phase.
            #[cfg(feature = "agent-class")]
            Policy::AgentClass(_) => {}
            // Wave 7 / A7.2 A2A protocol policy. Reads the typed
            // envelope populated earlier in `request_filter` and
            // enforces chain-depth, cycle, callee-allowlist and
            // caller-denylist checks. Allow paths still emit the
            // per-hop metric so dashboards see depth distribution.
            Policy::A2A(p) => {
                if let Some(a2a_ctx) = ctx.a2a.clone() {
                    let route = ctx.hostname.to_string();
                    let spec_label = a2a_ctx.spec.as_label();
                    let callable_endpoint = session.req_header().uri.path().to_string();
                    let decision = p.evaluate(&a2a_ctx, &callable_endpoint);
                    sbproxy_observe::metrics::record_a2a_chain_depth(
                        &route,
                        spec_label,
                        a2a_ctx.chain_depth,
                    );
                    if decision.is_allow() {
                        sbproxy_observe::metrics::record_a2a_hop(&route, spec_label, "allow");
                    } else {
                        let reason = decision.reason_label();
                        sbproxy_observe::metrics::record_a2a_hop(
                            &route,
                            spec_label,
                            &format!("deny:{reason}"),
                        );
                        sbproxy_observe::metrics::record_a2a_denied(&route, reason);
                        let body = decision.json_body();
                        let status = decision.http_status();
                        ctx.a2a_denial_body = Some(body.clone());
                        let policy_type: &'static str = match reason {
                            "depth" => "a2a_chain_depth_exceeded",
                            "cycle" => "a2a_cycle_detected",
                            "callee_not_allowed" => "a2a_callee_not_allowed",
                            "caller_denied" => "a2a_caller_denied",
                            _ => "a2a",
                        };
                        return PolicyResult::Deny(status, body, None, policy_type);
                    }
                }
            }
        }
    }
    PolicyResult::Allow(rate_limit_info)
}

// --- Lua modifier helpers ---

/// Execute a Lua request modifier script.
///
/// The script must define `modify_request(req, ctx)` which receives the request
/// data as a table with `method`, `path`, and `headers` fields, and an empty
/// context table. It must return a table with `set_headers` (and optionally
/// `remove_headers`) to apply to the upstream request.
///
/// Returns a list of (header_name, header_value) pairs to set.
fn lua_request_modifier(
    script: &str,
    req_header: &RequestHeader,
    hostname: &str,
) -> anyhow::Result<Vec<(String, String)>> {
    use sbproxy_extension::lua::LuaEngine;

    let engine = LuaEngine::new()?;

    // Build request table for the Lua script
    let mut headers_map = std::collections::HashMap::new();
    for (name, value) in req_header.headers.iter() {
        if let Ok(v) = value.to_str() {
            headers_map.insert(name.as_str().to_string(), v.to_string());
        }
    }

    let req_table = serde_json::json!({
        "method": req_header.method.as_str(),
        "path": req_header.uri.path(),
        "headers": headers_map,
        "host": hostname,
    });
    let ctx_table = serde_json::json!({});

    // Try the Rust format first (modify_request returning {set_headers: {...}}).
    // If not found, try the Go format (match_request with req:set_header()).
    let result = engine.call_function(
        script,
        "modify_request",
        vec![req_table.clone(), ctx_table.clone()],
    );

    let mut headers_to_set = Vec::new();
    match result {
        Ok(result) => {
            // Extract set_headers from the result table
            if let Some(set_headers) = result.get("set_headers").and_then(|h| h.as_object()) {
                for (key, value) in set_headers {
                    if let Some(v) = value.as_str() {
                        headers_to_set.push((key.clone(), v.to_string()));
                    }
                }
            }
        }
        Err(_) => {
            // Try Go format: match_request(req, ctx) with req:set_header() calls.
            // We wrap the Go-style script to capture set_header calls.
            // Pass data via globals (safe from escaping issues).
            let wrapper = format!(
                r#"
local __headers = {{}}
function __make_req(data)
    local req = {{}}
    if data then for k, v in pairs(data) do req[k] = v end end
    function req:set_header(name, value)
        __headers[name] = value
    end
    function req:method()
        return (data and data.method) or "GET"
    end
    function req:path()
        return (data and data.path) or "/"
    end
    function req:host()
        return (data and data.host) or ""
    end
    function req:header(name)
        if data and data.headers then return data.headers[string.lower(name)] end
        return nil
    end
    return req
end

{script}

local __req_obj = __make_req(__req_data)
local __ctx_obj = __ctx_data or {{}}
match_request(__req_obj, __ctx_obj)
return __headers
"#,
                script = script,
            );
            let go_engine = LuaEngine::new()?;
            let mut globals = std::collections::HashMap::new();
            globals.insert("__req_data".to_string(), req_table);
            globals.insert("__ctx_data".to_string(), ctx_table);
            let go_result = go_engine.execute(&wrapper, globals)?;
            if let Some(obj) = go_result.as_object() {
                for (key, value) in obj {
                    if let Some(v) = value.as_str() {
                        headers_to_set.push((key.clone(), v.to_string()));
                    }
                }
            }
        }
    }
    Ok(headers_to_set)
}

/// Execute a Lua response modifier script.
///
/// Supports two formats:
/// - Rust: `modify_response(resp, ctx)` returning `{set_headers = {...}}`
/// - Go: `match_response(resp, ctx)` with `resp:set_header()` method calls
///
/// Returns a list of (header_name, header_value) pairs to set.
fn lua_response_modifier(script: &str, status: u16) -> anyhow::Result<Vec<(String, String)>> {
    use sbproxy_extension::lua::LuaEngine;

    let engine = LuaEngine::new()?;

    let resp_table = serde_json::json!({
        "status_code": status,
    });
    let ctx_table = serde_json::json!({});

    // Try the Rust format first (modify_response returning {set_headers: {...}}).
    let result = engine.call_function(
        script,
        "modify_response",
        vec![resp_table.clone(), ctx_table.clone()],
    );

    let mut headers_to_set = Vec::new();
    match result {
        Ok(result) => {
            if let Some(set_headers) = result.get("set_headers").and_then(|h| h.as_object()) {
                for (key, value) in set_headers {
                    if let Some(v) = value.as_str() {
                        headers_to_set.push((key.clone(), v.to_string()));
                    }
                }
            }
        }
        Err(_) => {
            // Try Go format: match_response(resp, ctx) with resp:set_header() calls.
            let wrapper = format!(
                r#"
local __headers = {{}}
function __make_resp(data)
    local resp = {{}}
    if data then for k, v in pairs(data) do resp[k] = v end end
    function resp:set_header(name, value)
        __headers[name] = value
    end
    function resp:status()
        return (data and data.status_code) or 0
    end
    return resp
end

{script}

local __resp_obj = __make_resp(__resp_data)
local __ctx_obj = __ctx_data or {{}}
match_response(__resp_obj, __ctx_obj)
return __headers
"#,
                script = script,
            );
            let go_engine = LuaEngine::new()?;
            let mut globals = std::collections::HashMap::new();
            globals.insert("__resp_data".to_string(), resp_table);
            globals.insert("__ctx_data".to_string(), ctx_table);
            let go_result = go_engine.execute(&wrapper, globals)?;
            if let Some(obj) = go_result.as_object() {
                for (key, value) in obj {
                    if let Some(v) = value.as_str() {
                        headers_to_set.push((key.clone(), v.to_string()));
                    }
                }
            }
        }
    }
    Ok(headers_to_set)
}

// --- Session cookie builder ---

/// Build a Set-Cookie header value for a session cookie.
///
/// Returns a cookie string like `sbproxy_sid=<uuid>; Path=/; Max-Age=3600; SameSite=Lax; HttpOnly`
fn build_session_cookie(config: &sbproxy_config::SessionConfig, session_id: &str) -> String {
    let cookie_name = config.cookie_name.as_deref().unwrap_or("sbproxy_sid");
    let max_age = config.max_age.unwrap_or(3600);
    let same_site = config.same_site.as_deref().unwrap_or("Lax");

    let mut parts = vec![
        format!("{}={}", cookie_name, session_id),
        "Path=/".to_string(),
        format!("Max-Age={}", max_age),
        format!("SameSite={}", same_site),
    ];
    if config.http_only || !config.allow_non_ssl {
        parts.push("HttpOnly".to_string());
    }
    if config.secure {
        parts.push("Secure".to_string());
    }
    parts.join("; ")
}

// --- Callback firing ---

/// Lazily-initialized HTTP client for firing callbacks. Builder
/// failure here means a malformed default TLS root store or a
/// system-level resource starvation; both are unrecoverable for the
/// callback path, so we surface the failure via panic rather than
/// silently dropping to a `Client::default()` (which has no timeout).
static CALLBACK_CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("callback reqwest::Client build must succeed")
});

/// Fire a fire-and-forget shadow copy of an inbound request at a
/// mirror URL. The response is read and discarded; errors are logged
/// at debug level. Body data is NOT mirrored in this initial cut
/// (the inbound body is consumed by Pingora to forward to the primary
/// upstream); only method, path/query, and headers are sent. This is
/// sufficient for safe rollouts of new backends and for replay-style
/// shadowing of read endpoints. Body mirroring requires teeing the
/// inbound body and is a follow-on.
/// Fire a pending mirror with whatever body has been buffered. The
/// `mirror_pending` slot is taken from `ctx` so the mirror only ever
/// fires once. Bodies that exceed the configured cap are dropped (we
/// fire the mirror without a body rather than skip it entirely).
fn fire_pending_mirror(ctx: &mut crate::context::RequestContext) {
    let params = match ctx.mirror_pending.take() {
        Some(p) => p,
        None => return,
    };
    let body = ctx.request_body_buf.take().map(|buf| buf.freeze());
    let body_for_mirror = body.filter(|b| b.len() <= params.max_body_bytes);
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
}

#[allow(clippy::too_many_arguments)]
async fn fire_request_mirror(
    mirror_url: String,
    timeout: std::time::Duration,
    method: String,
    path_and_query: String,
    headers: http::HeaderMap,
    request_id: String,
    body: Option<bytes::Bytes>,
) {
    // Compose the full URL: mirror base + the original path + query.
    // Trim trailing slash on the base so we don't double up.
    let full_url = {
        let base = mirror_url.trim_end_matches('/');
        if path_and_query.starts_with('/') {
            format!("{base}{path_and_query}")
        } else {
            format!("{base}/{path_and_query}")
        }
    };

    let client = &*CALLBACK_CLIENT;
    let method = match method.as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        other => match reqwest::Method::from_bytes(other.as_bytes()) {
            Ok(m) => m,
            Err(_) => return,
        },
    };

    let mut req = client.request(method, &full_url).timeout(timeout);
    // Forward most headers, but skip hop-by-hop and ones reqwest will
    // recompute (Host gets rewritten by reqwest from the URL; Content-
    // Length is no longer accurate without the body).
    for (name, value) in headers.iter() {
        let n = name.as_str();
        if matches!(
            n,
            "host"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailers"
                | "upgrade"
        ) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            req = req.header(n, v);
        }
    }
    req = req
        .header("x-sbproxy-mirror", "1")
        .header("x-sbproxy-request-id", request_id.as_str())
        .header("x-sbproxy-instance", crate::identity::instance_id());
    if let Some(b) = body {
        req = req.body(b);
    }

    match req.send().await {
        Ok(resp) => {
            debug!(url = %full_url, status = %resp.status(), "mirror sent");
            // Drain the body so the connection can be returned to the pool.
            let _ = resp.bytes().await;
        }
        Err(e) => {
            debug!(url = %full_url, error = %e, "mirror delivery failed");
        }
    }
}

/// HMAC-SHA256 sign a payload with a shared secret. Returns the
/// `v1=<hex>` value used in `X-Sbproxy-Signature`. Surfaces an error
/// rather than panicking when the HMAC primitive cannot accept the
/// provided key bytes.
fn sign_webhook(secret: &str, body: &[u8], timestamp: i64) -> anyhow::Result<String> {
    use hmac::{KeyInit, Mac, SimpleHmac};
    use sha2::Sha256;
    let mut mac = SimpleHmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|e| anyhow::anyhow!("webhook hmac init failed: {e}"))?;
    // GitHub-style: include timestamp in the signed material so old
    // signatures cannot be replayed past the receiver's tolerance window.
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let bytes = mac.finalize().into_bytes();
    Ok(format!("v1={}", hex::encode(bytes)))
}

/// HMAC-SHA256-derived CSRF token bound to a per-config secret, the
/// request hostname, and a timestamp. Hex-encoded so it drops directly
/// into a Set-Cookie value. Forging a token requires knowledge of
/// `secret`, which never leaves the process.
fn csrf_token(secret: &str, timestamp: u128, hostname: &str) -> anyhow::Result<String> {
    use hmac::{KeyInit, Mac, SimpleHmac};
    use sha2::Sha256;
    let mut mac = SimpleHmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|e| anyhow::anyhow!("csrf hmac init failed: {e}"))?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(hostname.as_bytes());
    let bytes = mac.finalize().into_bytes();
    Ok(hex::encode(bytes))
}

/// Build the standard webhook envelope shared by `on_request` and
/// `on_response`. Receivers can correlate the pair via `request.id`.
fn webhook_envelope(
    event: &str,
    request_id: &str,
    config_revision: &str,
    extra: serde_json::Value,
) -> serde_json::Value {
    let mut base = serde_json::json!({
        "event": event,
        "proxy": {
            "instance_id": crate::identity::instance_id(),
            "version": crate::identity::version(),
            "config_revision": config_revision,
        },
        "request": {
            "id": request_id,
            "received_at": chrono::Utc::now().to_rfc3339(),
        },
    });
    if let (serde_json::Value::Object(ref mut base_map), serde_json::Value::Object(extra_map)) =
        (&mut base, extra)
    {
        for (k, v) in extra_map {
            base_map.insert(k, v);
        }
    }
    base
}

/// Prefix that marks headers on a callback response as injection
/// directives. The callback responds with `X-Inject-Foo: bar`; the
/// proxy strips the prefix and adds `Foo: bar` to either the upstream
/// request (`on_request` enrichment) or the client-facing response
/// (`on_response` enrichment).
const CALLBACK_INJECT_PREFIX: &str = "x-inject-";

/// Read the `enrich` flag from a callback config object. Defaults to
/// `false` so existing audit-only callbacks keep their fire-and-forget
/// semantics. Accepts either `enrich: true` or `mode: "enrich"`.
fn callback_is_enrich(cb_val: &serde_json::Value) -> bool {
    if let Some(b) = cb_val.get("enrich").and_then(|v| v.as_bool()) {
        return b;
    }
    matches!(
        cb_val.get("mode").and_then(|v| v.as_str()),
        Some(m) if m.eq_ignore_ascii_case("enrich")
    )
}

/// Extract injection directives from a callback response. Any header
/// whose name starts with `X-Inject-` is converted into a
/// `(unprefixed_name, value)` pair. Returns an empty vec when the
/// callback does not include any injection headers.
fn extract_inject_headers(resp_headers: &reqwest::header::HeaderMap) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, value) in resp_headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if let Some(stripped) = lower.strip_prefix(CALLBACK_INJECT_PREFIX) {
            if stripped.is_empty() {
                continue;
            }
            if let Ok(v) = value.to_str() {
                out.push((stripped.to_string(), v.to_string()));
            }
        }
    }
    out
}

/// Fire on_request callbacks for an origin. Audit-mode callbacks are
/// dispatched through [`WEBHOOK_TASKS`] (fire-and-forget, drained on
/// shutdown). Enrichment callbacks (`enrich: true`) are awaited inline
/// and any `X-Inject-*` response headers are returned for injection
/// into the upstream request.
#[allow(clippy::too_many_arguments)]
async fn fire_on_request_callbacks(
    callbacks: &[serde_json::Value],
    method: &str,
    path: &str,
    hostname: &str,
    client_ip: Option<String>,
    request_id: &str,
    config_revision: &str,
    headers: &http::HeaderMap,
) -> Vec<(String, String)> {
    let mut inject: Vec<(String, String)> = Vec::new();

    for cb_val in callbacks {
        let url = match cb_val.get("url").and_then(|v| v.as_str()) {
            Some(u) => u.to_string(),
            None => continue,
        };
        let cb_method = cb_val
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("POST")
            .to_uppercase();
        let secret = cb_val
            .get("secret")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let mut header_map = serde_json::Map::new();
        for (name, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                header_map.insert(name.to_string(), serde_json::Value::String(v.to_string()));
            }
        }
        let payload = webhook_envelope(
            "on_request",
            request_id,
            config_revision,
            serde_json::json!({
                "origin": { "name": hostname },
                "method": method,
                "path": path,
                "host": hostname,
                "client_ip": client_ip,
                "headers": header_map,
            }),
        );

        let timeout_secs = cb_val.get("timeout").and_then(|v| v.as_u64()).unwrap_or(5);
        let request_id_owned = request_id.to_string();
        let config_revision_owned = config_revision.to_string();

        if callback_is_enrich(cb_val) {
            let injected = send_webhook_collect_inject(
                &url,
                &cb_method,
                &payload,
                secret.as_deref(),
                "on_request",
                &request_id_owned,
                &config_revision_owned,
                timeout_secs,
            )
            .await;
            inject.extend(injected);
        } else {
            WEBHOOK_TASKS.spawn(async move {
                send_webhook(
                    &url,
                    &cb_method,
                    &payload,
                    secret.as_deref(),
                    "on_request",
                    &request_id_owned,
                    &config_revision_owned,
                    timeout_secs,
                )
                .await;
            });
        }
    }

    inject
}

/// Fire on_response callbacks for an origin. Audit-mode callbacks are
/// dispatched through [`WEBHOOK_TASKS`] (fire-and-forget, drained on
/// shutdown). Enrichment callbacks (`enrich: true`) are awaited inline
/// and any `X-Inject-*` response headers are returned for injection
/// into the client-facing response.
#[allow(clippy::too_many_arguments)]
async fn fire_on_response_callbacks(
    callbacks: &[serde_json::Value],
    status: u16,
    hostname: &str,
    path: &str,
    request_id: &str,
    config_revision: &str,
    duration_ms: Option<u64>,
) -> Vec<(String, String)> {
    let mut inject: Vec<(String, String)> = Vec::new();

    for cb_val in callbacks {
        let url = match cb_val.get("url").and_then(|v| v.as_str()) {
            Some(u) => u.to_string(),
            None => continue,
        };
        let cb_method = cb_val
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("POST")
            .to_uppercase();
        let secret = cb_val
            .get("secret")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let payload = webhook_envelope(
            "on_response",
            request_id,
            config_revision,
            serde_json::json!({
                "origin": { "name": hostname },
                "status": status,
                "host": hostname,
                "path": path,
                "duration_ms": duration_ms,
            }),
        );

        let timeout_secs = cb_val.get("timeout").and_then(|v| v.as_u64()).unwrap_or(5);
        let request_id_owned = request_id.to_string();
        let config_revision_owned = config_revision.to_string();

        if callback_is_enrich(cb_val) {
            let injected = send_webhook_collect_inject(
                &url,
                &cb_method,
                &payload,
                secret.as_deref(),
                "on_response",
                &request_id_owned,
                &config_revision_owned,
                timeout_secs,
            )
            .await;
            inject.extend(injected);
        } else {
            WEBHOOK_TASKS.spawn(async move {
                send_webhook(
                    &url,
                    &cb_method,
                    &payload,
                    secret.as_deref(),
                    "on_response",
                    &request_id_owned,
                    &config_revision_owned,
                    timeout_secs,
                )
                .await;
            });
        }
    }

    inject
}

/// Build the outbound webhook request with the standard envelope,
/// identifying headers, and optional HMAC signature. Returns `None`
/// when payload serialization fails so callers can short-circuit.
#[allow(clippy::too_many_arguments)]
fn build_webhook_request(
    url: &str,
    method: &str,
    payload: &serde_json::Value,
    secret: Option<&str>,
    event: &str,
    request_id: &str,
    config_revision: &str,
    timeout_secs: u64,
) -> Option<reqwest::RequestBuilder> {
    let client = &*CALLBACK_CLIENT;
    let body = match serde_json::to_vec(payload) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "webhook payload serialize failed");
            return None;
        }
    };
    let timestamp = chrono::Utc::now().timestamp();

    let mut req = match method {
        "GET" => client.get(url),
        "PUT" => client.put(url).body(body.clone()),
        _ => client.post(url).body(body.clone()),
    };
    req = req
        .header("content-type", "application/json")
        .header(
            "user-agent",
            format!("sbproxy/{}", crate::identity::version()),
        )
        .header("x-sbproxy-event", event)
        .header("x-sbproxy-instance", crate::identity::instance_id())
        .header("x-sbproxy-request-id", request_id)
        .header("x-sbproxy-config-revision", config_revision)
        .header("x-sbproxy-timestamp", timestamp.to_string());
    if let Some(s) = secret {
        match sign_webhook(s, &body, timestamp) {
            Ok(sig) => {
                req = req.header("x-sbproxy-signature", sig);
            }
            Err(e) => {
                warn!(url = %url, event = %event, error = %e, "webhook signing failed; sending without signature");
            }
        }
    }
    Some(req.timeout(std::time::Duration::from_secs(timeout_secs)))
}

/// Send a webhook in audit mode. Errors are logged and dropped; the
/// response body is discarded.
#[allow(clippy::too_many_arguments)]
async fn send_webhook(
    url: &str,
    method: &str,
    payload: &serde_json::Value,
    secret: Option<&str>,
    event: &str,
    request_id: &str,
    config_revision: &str,
    timeout_secs: u64,
) {
    let Some(req) = build_webhook_request(
        url,
        method,
        payload,
        secret,
        event,
        request_id,
        config_revision,
        timeout_secs,
    ) else {
        return;
    };
    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            debug!(url = %url, event = %event, "webhook sent");
        }
        Ok(resp) => {
            warn!(url = %url, event = %event, status = %resp.status(), "webhook non-success");
        }
        Err(e) => {
            warn!(url = %url, event = %event, error = %e, "webhook delivery failed");
        }
    }
}

/// Send a webhook in enrichment mode. Awaits the response, harvests
/// any `X-Inject-*` response headers, and returns them as
/// `(unprefixed_name, value)` pairs. A timed-out, non-success, or
/// failed callback returns an empty vec so the request still flows.
#[allow(clippy::too_many_arguments)]
async fn send_webhook_collect_inject(
    url: &str,
    method: &str,
    payload: &serde_json::Value,
    secret: Option<&str>,
    event: &str,
    request_id: &str,
    config_revision: &str,
    timeout_secs: u64,
) -> Vec<(String, String)> {
    let Some(req) = build_webhook_request(
        url,
        method,
        payload,
        secret,
        event,
        request_id,
        config_revision,
        timeout_secs,
    ) else {
        return Vec::new();
    };
    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            let injected = extract_inject_headers(resp.headers());
            debug!(
                url = %url,
                event = %event,
                injected = injected.len(),
                "enrichment webhook returned"
            );
            injected
        }
        Ok(resp) => {
            warn!(url = %url, event = %event, status = %resp.status(), "enrichment webhook non-success");
            Vec::new()
        }
        Err(e) => {
            warn!(url = %url, event = %event, error = %e, "enrichment webhook delivery failed");
            Vec::new()
        }
    }
}

// --- AI proxy helpers ---

/// Process-wide memoization of compiled guardrail pipelines, keyed by
/// the address of the configured `GuardrailsConfig`. The address is
/// stable for the lifetime of an `AiHandlerConfig` (held in the
/// reload-managed `Arc<Pipeline>`), so a hit returns the
/// already-compiled `GuardrailPipeline` rather than re-running regex
/// compilation on every request. Hot reload swaps in a new pipeline
/// (and therefore a new config address), so stale entries fall out of
/// use; the map is small (one entry per ai handler config) and never
/// grows hot.
static GUARDRAIL_PIPELINE_CACHE: std::sync::LazyLock<
    std::sync::Mutex<
        std::collections::HashMap<usize, std::sync::Arc<sbproxy_ai::guardrails::GuardrailPipeline>>,
    >,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Look up (or compile-and-cache) the guardrail pipeline for the given
/// configuration. Returns `None` and emits a `tracing::warn!` when
/// `compile_pipeline` fails so the AI proxy can fall through to its
/// no-guardrails behaviour (matching the previous best-effort policy).
fn cached_guardrails_pipeline(
    guardrails_config: &sbproxy_ai::guardrails::GuardrailsConfig,
) -> Option<std::sync::Arc<sbproxy_ai::guardrails::GuardrailPipeline>> {
    let key = guardrails_config as *const _ as usize;
    if let Ok(map) = GUARDRAIL_PIPELINE_CACHE.lock() {
        if let Some(p) = map.get(&key) {
            return Some(p.clone());
        }
    }
    match sbproxy_ai::guardrails::compile_pipeline(guardrails_config) {
        Ok(pipeline) => {
            let arc = std::sync::Arc::new(pipeline);
            if let Ok(mut map) = GUARDRAIL_PIPELINE_CACHE.lock() {
                map.insert(key, arc.clone());
            }
            Some(arc)
        }
        Err(e) => {
            warn!(error = %e, "AI proxy: failed to compile guardrails, skipping");
            None
        }
    }
}

/// Best-effort extraction of a single prompt string from a parsed AI request
/// body.
///
/// Handles the common OpenAI-style `messages: [{role, content}]` shape by
/// concatenating the content of the trailing user messages. Falls back to a
/// bare `prompt` string field when present (legacy completions). Returns an
/// empty string when nothing usable is found; callers should treat an empty
/// result as "skip classification".
///
/// This is intentionally minimal. Task A20 tracks a richer extractor that
/// understands tool-use parts, multimodal content, and system prompts.
/// Extract a textual representation of the prompt from an AI request
/// body. Used by classifier hooks, semantic-cache key derivation, and
/// PII redaction logging.
///
/// Handles the major API surfaces:
///
/// - **OpenAI chat completions**: `messages[*].content` as string or
///   array of `{type, text|image_url|image}` parts.
/// - **OpenAI Responses API**: top-level `input` as string or array.
/// - **Anthropic Messages API**: top-level `system` as string or array
///   of text blocks, plus `messages[*]` with content blocks.
/// - **Tool use / tool result blocks**: `type: tool_use` (extract the
///   tool's `input` JSON), `type: tool_result` (extract `content`).
/// - **Multimodal image parts**: emit a `[image]` placeholder so
///   classifiers see *something* representing the modality rather
///   than silently dropping the segment.
/// - **Legacy completions**: bare `prompt` field as string or array.
fn extract_prompt_text(body: &serde_json::Value) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Anthropic-style top-level system prompt.
    if let Some(system) = body.get("system") {
        extract_into(system, &mut parts);
    }

    // OpenAI chat completions / Anthropic messages: messages[*].content
    if let Some(messages) = body.get("messages").and_then(|v| v.as_array()) {
        for msg in messages {
            if let Some(content) = msg.get("content") {
                extract_into(content, &mut parts);
            }
            // OpenAI tool calls: messages[*].tool_calls[*].function.arguments
            if let Some(tool_calls) = msg.get("tool_calls").and_then(|v| v.as_array()) {
                for call in tool_calls {
                    if let Some(args) = call
                        .get("function")
                        .and_then(|f| f.get("arguments"))
                        .and_then(|a| a.as_str())
                    {
                        parts.push(args.to_string());
                    }
                }
            }
        }
    }

    // OpenAI Responses API: top-level `input` (string or content array).
    if parts.is_empty() {
        if let Some(input) = body.get("input") {
            extract_into(input, &mut parts);
        }
    }

    // Legacy completions: bare `prompt` field.
    if parts.is_empty() {
        if let Some(prompt) = body.get("prompt") {
            extract_into(prompt, &mut parts);
        }
    }

    parts.join("\n")
}

/// Recursively walk a value drawing text out of every shape we know:
/// raw strings, arrays of content blocks, objects with `text`,
/// `tool_use` `input` payloads, `tool_result` `content`, and image
/// placeholders.
fn extract_into(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) if !s.is_empty() => {
            out.push(s.clone());
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                extract_into(item, out);
            }
        }
        serde_json::Value::Object(obj) => {
            // Block-typed content (Anthropic + OpenAI multimodal).
            let block_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
            match block_type {
                "text" => {
                    if let Some(t) = obj.get("text").and_then(|v| v.as_str()) {
                        if !t.is_empty() {
                            out.push(t.to_string());
                        }
                    }
                }
                "image" | "image_url" | "input_image" => {
                    // Surface a marker so classifiers / cache keys
                    // see a placeholder for the image rather than
                    // dropping the entire block.
                    out.push("[image]".to_string());
                }
                "tool_use" => {
                    // Anthropic tool_use: serialise the JSON `input`
                    // so classifiers see the structured arguments.
                    if let Some(input) = obj.get("input") {
                        if let Ok(s) = serde_json::to_string(input) {
                            out.push(s);
                        }
                    }
                }
                "tool_result" => {
                    if let Some(content) = obj.get("content") {
                        extract_into(content, out);
                    }
                }
                _ => {
                    // Generic fallback for shapes we have not
                    // catalogued yet: pull `text` if present, else
                    // recurse into each value once. This keeps the
                    // extractor tolerant of new vendor shapes.
                    if let Some(t) = obj.get("text").and_then(|v| v.as_str()) {
                        if !t.is_empty() {
                            out.push(t.to_string());
                        }
                    } else if let Some(content) = obj.get("content") {
                        extract_into(content, out);
                    }
                }
            }
        }
        _ => {}
    }
}

// --- AI proxy handler ---

/// Outcome of a pre-dispatch budget check. Tells the caller whether
/// the request should proceed, fail with a 402, or have its model
/// rewritten before forwarding upstream.
enum BudgetGate {
    /// No limit was exceeded. Continue with the original model.
    Allow,
    /// At least one limit fired and the configured action is `block`.
    /// The caller must short-circuit with the supplied status + JSON body.
    Block { status: u16, body: Vec<u8> },
    /// At least one limit fired and the configured action is `downgrade`.
    /// The caller must rewrite the request body's `model` to this name.
    Downgrade { model: String },
}

/// Build the list of scope keys to check / record against for a given
/// AI request. We compute one key per limit so a workspace cap can
/// coexist with a per-api-key cap on the same origin.
fn budget_scope_keys(
    cfg: &sbproxy_ai::BudgetConfig,
    workspace_id: &str,
    api_key: Option<&str>,
    user: Option<&str>,
    model: Option<&str>,
    origin: Option<&str>,
    tag: Option<&str>,
) -> Vec<(usize, String)> {
    let mut out = Vec::with_capacity(cfg.limits.len());
    for (idx, limit) in cfg.limits.iter().enumerate() {
        if let Some(key) = sbproxy_ai::budget::BudgetTracker::scope_key(
            &limit.scope,
            workspace_id,
            api_key,
            user,
            model,
            origin,
            tag,
        ) {
            out.push((idx, key));
        }
    }
    out
}

/// Compute a single limit's utilization ratio for the
/// `sbproxy_ai_budget_utilization_ratio` gauge. Returns `None` when
/// the limit has neither a token nor cost cap configured.
fn limit_utilization(
    usage_tokens: u64,
    usage_cost: f64,
    limit: &sbproxy_ai::budget::BudgetLimit,
) -> Option<f64> {
    if let Some(max) = limit.max_tokens {
        if max > 0 {
            return Some(usage_tokens as f64 / max as f64);
        }
    }
    if let Some(max) = limit.max_cost_usd {
        if max > 0.0 {
            return Some(usage_cost / max);
        }
    }
    None
}

/// Run the budget pre-flight for a request.
///
/// Each configured limit produces a scope key. The first limit that
/// reports `exceeded == true` decides the action: `Log` falls
/// through (so a stricter `Block` later in the list still fires),
/// `Block` short-circuits with 402, and `Downgrade` rewrites the
/// request's model. When `downgrade_to` is unset, the cheapest model
/// across the configured providers' `models` lists is selected from
/// the embedded price catalog; if no candidates are available the
/// request blocks instead of silently passing through.
fn budget_preflight(
    cfg: &sbproxy_ai::BudgetConfig,
    keys: &[(usize, String)],
    providers: &[sbproxy_ai::ProviderConfig],
) -> BudgetGate {
    for (limit_idx, key) in keys {
        let result = match BUDGET_TRACKER.check_limits(cfg, key) {
            Some(r) => r,
            None => continue,
        };
        if !result.exceeded {
            continue;
        }
        let limit = &cfg.limits[*limit_idx];
        if let Some(ratio) =
            limit_utilization(result.current_tokens, result.current_cost_usd, limit)
        {
            sbproxy_ai::ai_metrics::set_budget_utilization(scope_label(&limit.scope), ratio);
        }
        match result.action {
            sbproxy_ai::OnExceedAction::Log => {
                tracing::warn!(
                    scope = scope_label(&limit.scope),
                    reason = %result.reason,
                    "AI budget: limit exceeded (log; allowing request)"
                );
                continue;
            }
            sbproxy_ai::OnExceedAction::Block => {
                tracing::warn!(
                    scope = scope_label(&limit.scope),
                    reason = %result.reason,
                    "AI budget: limit exceeded (block; rejecting request)"
                );
                let body = serde_json::json!({
                    "error": {
                        "type": "budget_exceeded",
                        "scope": scope_label(&limit.scope),
                        "message": result.reason,
                    }
                });
                return BudgetGate::Block {
                    status: 402,
                    body: serde_json::to_vec(&body).unwrap_or_default(),
                };
            }
            sbproxy_ai::OnExceedAction::Downgrade => {
                let target = limit.downgrade_to.clone().or_else(|| {
                    let mut candidates: Vec<String> = Vec::new();
                    for p in providers {
                        for m in &p.models {
                            candidates.push(m.clone());
                        }
                    }
                    sbproxy_ai::cheapest_model(&candidates)
                });
                match target {
                    Some(model) => {
                        tracing::warn!(
                            scope = scope_label(&limit.scope),
                            new_model = %model,
                            reason = %result.reason,
                            "AI budget: limit exceeded (downgrade; rewriting model)"
                        );
                        return BudgetGate::Downgrade { model };
                    }
                    None => {
                        tracing::warn!(
                            scope = scope_label(&limit.scope),
                            reason = %result.reason,
                            "AI budget: limit exceeded (downgrade unset and no candidates; blocking)"
                        );
                        let body = serde_json::json!({
                            "error": {
                                "type": "budget_exceeded",
                                "scope": scope_label(&limit.scope),
                                "message": format!(
                                    "{}; downgrade target unavailable",
                                    result.reason
                                ),
                            }
                        });
                        return BudgetGate::Block {
                            status: 402,
                            body: serde_json::to_vec(&body).unwrap_or_default(),
                        };
                    }
                }
            }
        }
    }
    BudgetGate::Allow
}

/// Stable label for the budget metric `scope` dimension.
fn scope_label(scope: &sbproxy_ai::budget::BudgetScope) -> &'static str {
    match scope {
        sbproxy_ai::budget::BudgetScope::Workspace => "workspace",
        sbproxy_ai::budget::BudgetScope::ApiKey => "api_key",
        sbproxy_ai::budget::BudgetScope::User => "user",
        sbproxy_ai::budget::BudgetScope::Model => "model",
        sbproxy_ai::budget::BudgetScope::Origin => "origin",
        sbproxy_ai::budget::BudgetScope::Tag => "tag",
    }
}

/// Extract `(prompt_tokens, completion_tokens)` from an
/// OpenAI-shaped chat completion JSON response. Falls back to
/// Anthropic's `input_tokens` / `output_tokens` so non-translated
/// upstreams still report usage. Returns `(0, 0)` when no usage
/// block is present.
fn extract_usage(body: &[u8]) -> (u64, u64) {
    let parsed: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (0, 0),
    };
    let usage = match parsed.get("usage") {
        Some(u) => u,
        None => return (0, 0),
    };
    let prompt = usage
        .get("prompt_tokens")
        .or_else(|| usage.get("input_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let completion = usage
        .get("completion_tokens")
        .or_else(|| usage.get("output_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    (prompt, completion)
}

/// Streaming-aware accumulator for SSE `usage` blocks.
///
/// AI providers report token usage in the terminal SSE chunk rather
/// than in a `Content-Length`-framed JSON body. The two shapes we
/// care about are:
///
/// * OpenAI: `data: {"id":"...", "usage":{"prompt_tokens":N,
///   "completion_tokens":M, ...}, ...}` followed by `data: [DONE]`.
/// * Anthropic: `event: message_delta\ndata: {"usage":{
///   "input_tokens":N, "output_tokens":M}, ...}`.
///
/// `feed` accepts arbitrary chunk bytes (frames may arrive split or
/// coalesced), splits them at `\n` boundaries, and parses every
/// `data: <json>` line that contains a `usage` object. Anthropic's
/// `message_start` reports a partial usage (input only) and
/// `message_delta` updates it with output tokens; we keep the
/// largest values seen so the post-stream record reflects the final
/// totals from either shape.
///
/// The scanner buffers at most a single line of pending bytes so
/// Deprecated thin shim around the pluggable
/// [`sbproxy_ai::SseUsageParser`] family. Kept for one release
/// cycle so external callers that picked up the previous
/// public-by-accident type do not break; the streaming relay now
/// constructs parsers directly via
/// [`sbproxy_ai::select_parser`].
///
/// Compiled only under `cfg(test)` because it has no other in-tree
/// users; pinning the legacy public API surface lives in the
/// `sbproxy-ai` crate's `usage_parser` module.
#[cfg(test)]
#[deprecated(
    note = "use sbproxy_ai::select_parser with usage_parser: auto; this shim only handles \
            the OpenAI / Anthropic shapes and will be removed in a future release"
)]
struct SseUsageScanner {
    inner: Box<dyn sbproxy_ai::SseUsageParser>,
}

#[cfg(test)]
#[allow(deprecated)]
impl SseUsageScanner {
    /// Build a scanner backed by the generic parser, which handles
    /// both OpenAI and Anthropic shapes (and silently passes through
    /// other shapes too).
    fn new() -> Self {
        let hints = sbproxy_ai::UsageParserHints::default();
        // `select_parser("generic", ...)` always returns `Some`.
        let inner = sbproxy_ai::select_parser("generic", &hints)
            .expect("generic parser must always be available");
        Self { inner }
    }

    /// Feed a chunk of stream bytes.
    fn feed(&mut self, bytes: &[u8]) {
        self.inner.feed(bytes);
    }

    /// Tokens captured so far. Returns `(0, 0)` until the first
    /// `usage` block is parsed (matches the legacy contract).
    fn totals(&self) -> (u64, u64) {
        match self.inner.snapshot() {
            Some(t) => (t.prompt_tokens as u64, t.completion_tokens as u64),
            None => (0, 0),
        }
    }
}

/// Record post-dispatch usage against every configured budget scope
/// for this request. Tokens come from the upstream `usage` block;
/// cost is estimated against the model the request actually
/// executed against using the embedded price catalog in
/// `sbproxy-ai/src/budget.rs`.
fn record_budget_usage(
    cfg: &sbproxy_ai::BudgetConfig,
    keys: &[(usize, String)],
    model: &str,
    prompt_tokens: u64,
    completion_tokens: u64,
) {
    if prompt_tokens == 0 && completion_tokens == 0 {
        return;
    }
    let total_tokens = prompt_tokens + completion_tokens;
    let cost = sbproxy_ai::estimate_cost(model, prompt_tokens, completion_tokens);
    for (limit_idx, key) in keys {
        BUDGET_TRACKER.record_usage(key, total_tokens, cost);
        let limit = &cfg.limits[*limit_idx];
        let usage = BUDGET_TRACKER.get_usage(key);
        if let Some(ratio) = limit_utilization(usage.tokens, usage.cost_usd, limit) {
            sbproxy_ai::ai_metrics::set_budget_utilization(scope_label(&limit.scope), ratio);
        }
    }
}

/// Read a request header value as an owned `String`. Returns `None`
/// when the header is missing or the value is not valid UTF-8.
fn req_header_value(session: &Session, name: &str) -> Option<String> {
    session
        .req_header()
        .headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Handle an AI proxy request by forwarding to the upstream provider via reqwest.
///
/// This function:
/// 1. Reads the request body from the Pingora session
/// 2. Parses the JSON body to extract model name and stream flag
/// 3. Selects a provider via the configured routing strategy
/// 4. Maps the model name if a model_map is configured
/// 5. Forwards the request to the provider's API
/// 6. Relays the response back to the client (streaming or non-streaming)
async fn handle_ai_proxy(
    session: &mut Session,
    config: &AiHandlerConfig,
    pipeline: &CompiledPipeline,
    hostname: &str,
    ctx: &mut RequestContext,
    origin_idx: Option<usize>,
) -> Result<()> {
    let method = session.req_header().method.clone();
    let path = session.req_header().uri.path().to_string();

    // Build a router for provider selection.
    let router = AiRouter::new(config.routing.clone(), config.providers.len());

    // Handle GET requests (e.g. /v1/models) by forwarding to first enabled provider.
    if method == http::Method::GET {
        let provider_idx = router.select(&config.providers).ok_or_else(|| {
            warn!("AI proxy: no enabled providers");
            Error::new(ErrorType::HTTPStatus(502))
        })?;
        let provider = &config.providers[provider_idx];

        let resp = AI_CLIENT
            .forward_get_request(provider, &path)
            .await
            .map_err(|e| {
                warn!(error = %e, "AI proxy: upstream GET request failed");
                Error::because(ErrorType::ConnectError, "AI upstream request failed", e)
            })?;

        // GET endpoints (e.g. /v1/models) aren't translated yet:
        // Anthropic's models listing has a different shape and most
        // OpenAI clients don't depend on it for routing decisions.
        let format = sbproxy_ai::client::provider_format(provider);
        return relay_ai_response(session, resp, format, config.max_body_size).await;
    }

    // POST requests: read the body, parse JSON, select provider, forward.
    let body_bytes = session.read_request_body().await?.unwrap_or_default();

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
                redactor.redact_json(&mut body);
                tracing::debug!("AI proxy: applied request-body PII redaction");
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
        match budget_preflight(budget_cfg, &keys, &config.providers) {
            BudgetGate::Allow => keys,
            BudgetGate::Block { status, body: err } => {
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

    if let Some(hook) = pipeline.hooks.prompt_classifier.as_ref().cloned() {
        if !extracted_prompt.is_empty() {
            let model_id = if model.is_empty() {
                None
            } else {
                Some(model.clone())
            };
            // TODO A20: richer prompt extraction strategies (tool use,
            // multimodal parts, system prompts). TODO: populate `headers`
            // with a snapshot of the request headers once downstream
            // consumers need them; empty map for now to avoid per-request
            // allocations in the common "no consumer" case.
            let classify_req = crate::hooks::ClassifyRequest {
                origin: hostname.to_string(),
                model_id,
                prompt: extracted_prompt.clone(),
                headers: std::collections::HashMap::new(),
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
                // TODO: snapshot real request headers when downstream
                // consumers (key templates with `{header.x}` placeholders)
                // need them. An empty map is safe for A21's default
                // key template (`{embedding_model}:{model_id}:{lsh_bucket}`).
                request_headers: std::collections::HashMap::new(),
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

    // --- Input guardrails: check messages before forwarding ---
    if let Some(ref guardrails_config) = config.guardrails {
        if let Some(pipeline) = cached_guardrails_pipeline(guardrails_config) {
            if pipeline.has_input() {
                // Parse messages from the body.
                let messages: Vec<sbproxy_ai::Message> = body
                    .get("messages")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();

                if let Some(block) = pipeline.check_input(&messages) {
                    warn!(
                        guardrail = %block.name,
                        reason = %block.reason,
                        "AI proxy: input guardrail blocked request"
                    );
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

    // Check if streaming is requested.
    let is_stream = body
        .get("stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Build a list of providers to try, in priority order for failover.
    let is_failover = matches!(config.routing, sbproxy_ai::RoutingStrategy::FallbackChain);
    // Default retry-on-status codes for failover.
    let retry_statuses: Vec<u16> = vec![500, 502, 503];

    // Parse retry config from the action config's routing.retry section.
    // This is done by inspecting the raw handler config.
    let max_attempts = if is_failover {
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
    if is_failover {
        provider_order.sort_by_key(|&i| config.providers[i].priority.unwrap_or(u32::MAX));
    }

    let mut last_resp: Option<reqwest::Response> = None;
    let mut last_format: sbproxy_ai::providers::ProviderFormat =
        sbproxy_ai::providers::ProviderFormat::OpenAi;
    let mut last_error: Option<anyhow::Error> = None;
    // Track the upstream URL host of the provider that produced
    // `last_resp`. Used by the streaming usage parser's `auto`
    // resolver so a Vertex / Bedrock / Cohere host picks the right
    // parser without operators having to override `usage_parser`.
    let mut last_upstream_host: Option<String> = None;

    for (attempt, &provider_idx) in provider_order.iter().enumerate() {
        if attempt >= max_attempts {
            break;
        }
        let provider = &config.providers[provider_idx];

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
        ctx.ai_provider = Some(provider.name.clone());
        if !resolved_model.is_empty() {
            ctx.ai_model = Some(resolved_model);
        }

        match AI_CLIENT
            .forward_request(provider, &path, &attempt_body)
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if is_failover
                    && status >= 500
                    && retry_statuses.contains(&status)
                    && attempt + 1 < max_attempts
                {
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
                last_format = sbproxy_ai::client::provider_format(provider);
                last_upstream_host = url::Url::parse(&provider.effective_base_url())
                    .ok()
                    .and_then(|u| u.host_str().map(|h| h.to_string()));
                last_resp = Some(resp);
                break;
            }
            Err(e) => {
                warn!(
                    error = %e,
                    provider = %provider.name,
                    attempt = %attempt,
                    "AI proxy: upstream request failed"
                );
                last_error = Some(e);
                if attempt + 1 >= max_attempts {
                    break;
                }
                continue;
            }
        }
    }

    if let Some(resp) = last_resp {
        if is_stream {
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
            if sbproxy_ai::translators::requires_translation(last_format) {
                warn!(
                    format = ?last_format,
                    "AI proxy: streaming SSE relay does not yet translate non-OpenAI event shapes"
                );
            }
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
            });
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
                StreamUsageParserArgs {
                    configured: usage_parser_cfg,
                    upstream_host,
                    content_type: resp_content_type,
                    x_provider: resp_x_provider,
                },
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
            });
            relay_ai_response_with_cache(
                session,
                resp,
                last_format,
                hostname,
                semcache_miss,
                config.max_body_size,
                recorder,
                Some(ctx),
            )
            .await
        }
    } else if let Some(e) = last_error {
        Err(Error::because(
            ErrorType::ConnectError,
            "AI upstream request failed (all providers)",
            e,
        ))
    } else {
        warn!("AI proxy: no enabled providers");
        Err(Error::new(ErrorType::HTTPStatus(502)))
    }
}

/// Relay a non-streaming AI response back to the client. When the
/// upstream provider speaks a non-OpenAI wire format, the response
/// body is translated back into OpenAI shape so OpenAI SDK clients
/// see a uniform interface. `max_body_size` caps the bytes read from
/// the upstream response; an oversized body is rejected with a 502 so
/// a misbehaving provider cannot exhaust gateway memory.
async fn relay_ai_response(
    session: &mut Session,
    resp: reqwest::Response,
    format: sbproxy_ai::providers::ProviderFormat,
    max_body_size: Option<usize>,
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
    send_response(session, status, &content_type, &translated).await
}

/// Read the upstream response body with an optional byte cap. When the
/// upstream advertises `Content-Length` larger than `max_body_size` we
/// short-circuit before any bytes are buffered. When the framed body
/// is unsized (chunked) we drain the byte stream but stop accumulating
/// once the cap is exceeded and surface a 502 to the caller so an
/// honest upstream cannot OOM the gateway.
async fn read_capped_response_body(
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
async fn relay_ai_response_with_cache(
    session: &mut Session,
    resp: reqwest::Response,
    format: sbproxy_ai::providers::ProviderFormat,
    hostname: &str,
    miss_info: Option<PendingSemcacheMiss>,
    max_body_size: Option<usize>,
    budget_recorder: Option<BudgetRecorderArgs<'_>>,
    ctx: Option<&mut RequestContext>,
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
            let (prompt_tokens, completion_tokens) = extract_usage(&resp_body);
            // Stamp the token counts onto the request context so the
            // access log records them alongside the rest of the AI
            // gateway envelope.
            if let Some(ctx) = ctx {
                ctx.ai_tokens_in = Some(prompt_tokens);
                ctx.ai_tokens_out = Some(completion_tokens);
            }
            record_budget_usage(
                args.config,
                args.keys,
                args.model,
                prompt_tokens,
                completion_tokens,
            );
        }
    } else if let Some(ctx) = ctx {
        // Even without a budget recorder we still want the access log
        // to capture token usage when the upstream returned a body.
        if (200..300).contains(&status) {
            let (prompt_tokens, completion_tokens) = extract_usage(&resp_body);
            if prompt_tokens != 0 || completion_tokens != 0 {
                ctx.ai_tokens_in = Some(prompt_tokens);
                ctx.ai_tokens_out = Some(completion_tokens);
            }
        }
    }

    send_response(session, status, &content_type, &resp_body).await
}

/// Bundled inputs for post-dispatch budget recording on a relayed AI
/// response. Carried through `relay_ai_response*` so the response
/// body can be parsed for `usage` and recorded against every scope
/// computed at pre-flight time.
struct BudgetRecorderArgs<'a> {
    /// Reference to the AI handler's `BudgetConfig`. Used to look up
    /// each fired limit's scope label for the utilization gauge.
    config: &'a sbproxy_ai::BudgetConfig,
    /// Pre-computed scope keys. One entry per limit that produced a
    /// usable key for this request.
    keys: &'a [(usize, String)],
    /// Model the request actually ran against (after any downgrade).
    /// Drives cost estimation via the embedded price catalog.
    model: &'a str,
}

/// Inputs to the streaming-cache recorder hook, bundled to keep
/// [`relay_ai_stream`]'s parameter list short.
///
/// The OSS proxy never inspects these fields beyond passing them to
/// [`crate::hooks::StreamCacheRecorderHook::start_session`]; all policy
/// decisions live in the enterprise impl.
struct StreamCacheRecorderArgs {
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
struct StreamUsageParserArgs {
    /// Operator-configured `usage_parser` value.
    configured: String,
    /// Effective upstream URL host (e.g. `api.openai.com`).
    upstream_host: Option<String>,
    /// Response `Content-Type` header.
    content_type: Option<String>,
    /// Response `X-Provider` header (when upstream sets one).
    x_provider: Option<String>,
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
#[allow(clippy::too_many_arguments)]
async fn relay_ai_stream(
    session: &mut Session,
    resp: reqwest::Response,
    pipeline: &CompiledPipeline,
    hostname: &str,
    model_id: Option<String>,
    origin_idx: Option<usize>,
    recorder_args: StreamCacheRecorderArgs,
    budget_recorder: Option<BudgetRecorderArgs<'_>>,
    parser_args: StreamUsageParserArgs,
) -> Result<()> {
    let status = resp.status().as_u16();

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
    loop {
        match stream.next().await {
            Some(Ok(chunk)) => {
                let chunk_bytes = Bytes::copy_from_slice(&chunk);

                // --- Per-chunk safety probe (fail-open) ---
                //
                // We push chunks into the classifier session channel and
                // drain any pending verdicts. Both sides are non-blocking:
                // if the sidecar is slow, we prefer delivering the user's
                // tokens over stalling on the verdict loop. Verdicts with
                // `allow=false` are logged but the chunk is still forwarded.
                if let Some(ch) = safety_channel.as_mut() {
                    if ch.tx.try_send(chunk_bytes.clone()).is_err() {
                        debug!("stream safety channel full; skipping verdict input");
                    }
                    while let Ok(v) = ch.rx.try_recv() {
                        if !v.allow {
                            warn!(
                                reason = ?v.reason,
                                "stream safety verdict rejected a chunk (fail-open: forwarded anyway)"
                            );
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
                session
                    .write_response_body(Some(chunk_bytes), false)
                    .await?;
            }
            Some(Err(e)) => {
                warn!(error = %e, "AI proxy: error reading SSE chunk from upstream");
                break;
            }
            None => {
                upstream_complete = true;
                break;
            }
        }
    }

    // Signal end of stream to the client. A failure here is treated
    // as a partial recording: we let the guard drop emit
    // `End { complete: false }`.
    session.write_response_body(None, true).await?;

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

// --- Non-proxy action handlers ---

/// Handle non-proxy actions directly in request_filter.
/// Returns Ok(true) if the action was handled (short-circuit), Ok(false) for Proxy.
async fn handle_action(
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
            handle_mcp_action(session, mcp).await?;
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
async fn handle_mcp_action(
    session: &mut Session,
    mcp: &sbproxy_modules::action::McpAction,
) -> Result<()> {
    use sbproxy_extension::mcp::types::{
        InitializeResult, JsonRpcRequest, JsonRpcResponse, ServerCapabilities, ServerInfo,
        INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST, METHOD_NOT_FOUND, PARSE_ERROR,
    };

    let method = session.req_header().method.clone();
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
            let result = InitializeResult {
                protocol_version: "2025-06-18".to_string(),
                capabilities: ServerCapabilities {
                    tools: Some(serde_json::json!({})),
                    resources: None,
                    prompts: None,
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
                        match mcp.federation.call_tool(&name, arguments).await {
                            Ok(value) => JsonRpcResponse::success(request.id.clone(), value),
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
        other => JsonRpcResponse::error(
            request.id.clone(),
            METHOD_NOT_FOUND,
            &format!("unknown method: {}", other),
        ),
    };

    write_jsonrpc(session, &response).await
}

/// Serialise a JSON-RPC response and write it to the session.
async fn write_jsonrpc(
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
            let cfg = &reload::current_pipeline().config.server.correlation_id;
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

        // Extract client IP from the downstream connection.
        ctx.client_ip = session
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .map(|addr| addr.ip());

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
            let pipeline = reload::current_pipeline();
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
            }
        }

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
        // wires the first signal into the bot-auth verifier (a
        // separate slice); this seam reads the resolved keyid off the
        // request context whenever that slice has run, otherwise
        // passes `None` so the chain falls through to UA matching.
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
                // `bot_auth_keyid` and `anonymous_bot_auth` will be wired
                // through once the bot-auth verifier slice lands; until
                // then the resolver is fed UA + client IP, which is
                // sufficient for the catalog match path the e2e suite
                // exercises.
                crate::agent_class::stamp_request_context(
                    ctx,
                    resolver,
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
        // forward-confirmed reverse DNS (step 2) per
        // `docs/adr-skyfire-kya-token.md`. The OSS pipeline owns the
        // header bag and the hostname; enterprise hooks (KYA verifier,
        // future identity providers) register through
        // `sbproxy_plugin::register_identity_hook`. Each registered
        // hook runs in registration order; the first hook returning a
        // verdict wins and the iteration short-circuits. Returning
        // `None` falls through to the next resolver step (rDNS, UA,
        // anonymous bot-auth, fallback).
        //
        // OSS-only builds register no identity hooks; the iteration is
        // a no-op. Enterprise builds install the KYA verifier at
        // startup (see `sbproxy_enterprise_modules::auth::kya_wiring`).
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
        // the header-stamped envelope alone. See
        // `docs/adr-a2a-protocol-envelope.md` § "Detection".
        {
            let detected = sbproxy_modules::detect_a2a(
                &session.req_header().headers,
                session.req_header().uri.path(),
                None, // operator route_glob is per-policy; consulted later
            );
            if let Some(signal) = detected {
                let spec = signal.to_spec();
                let mut a2a_ctx = sbproxy_modules::A2AContext::empty(spec);
                let h = &session.req_header().headers;
                if let Some(v) = h.get("x-a2a-caller-agent-id").and_then(|v| v.to_str().ok()) {
                    a2a_ctx.caller_agent_id = v.to_string();
                }
                if let Some(v) = h.get("x-a2a-callee-agent-id").and_then(|v| v.to_str().ok()) {
                    a2a_ctx.callee_agent_id = Some(v.to_string());
                }
                if let Some(v) = h.get("x-a2a-task-id").and_then(|v| v.to_str().ok()) {
                    a2a_ctx.task_id = v.to_string();
                }
                if let Some(v) = h
                    .get("x-a2a-parent-request-id")
                    .and_then(|v| v.to_str().ok())
                {
                    a2a_ctx.parent_request_id = Some(v.to_string());
                }
                if let Some(v) = h
                    .get("x-a2a-chain-depth")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u32>().ok())
                {
                    a2a_ctx.chain_depth = v.max(1);
                }
                if let Some(raw) = h.get("x-a2a-chain").and_then(|v| v.to_str().ok()) {
                    if let Ok(parsed) = serde_json::from_str::<Vec<sbproxy_modules::ChainHop>>(raw)
                    {
                        a2a_ctx.chain = parsed;
                    }
                }
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
        // `trustworthy` defaults to whatever
        // `sbproxy_tls::classify_trustworthy` returns against the
        // resolved client IP and the per-origin CIDR config; the
        // header-supplied value (when present) wins because the
        // sidecar is in a better position to know whether it actually
        // saw a direct client.
        #[cfg(feature = "tls-fingerprint")]
        if peer_trusted {
            // Wave 5 day-6 Item 3: read the typed TlsFingerprintConfig
            // and respect the `mode: disabled` short-circuit + the
            // operator's `sidecar_header_allowlist`. The canonical
            // `x-sbproxy-tls-*` family is always honoured for backward
            // compat with the day-5 wire shape.
            let pipeline = reload::current_pipeline();
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

                if ja3.is_some()
                    || ja4.is_some()
                    || ja4h_supplied.is_some()
                    || ja4s_supplied.is_some()
                {
                    // Resolve trustworthy: operator-configured CIDR
                    // sets win over the sidecar's hint when the
                    // resolved client IP falls in either set.
                    let mut trustworthy = trustworthy_override.unwrap_or(true);
                    if let Some(client_ip) = ctx.client_ip {
                        let untrusted = tls_cfg.untrusted_cidrs();
                        if untrusted.iter().any(|cidr| cidr.contains(client_ip)) {
                            trustworthy = false;
                        } else {
                            let trustworthy_set = tls_cfg.trustworthy_cidrs();
                            if !trustworthy_set.is_empty()
                                && trustworthy_set.iter().any(|cidr| cidr.contains(client_ip))
                            {
                                trustworthy = true;
                            } else if !trustworthy_set.is_empty() {
                                // No match in either set + operator
                                // explicitly configured a trust list:
                                // conservative default per A5.1.
                                trustworthy = false;
                            }
                        }
                    }
                    ctx.tls_fingerprint = Some(sbproxy_tls::TlsFingerprint {
                        ja3,
                        ja4,
                        ja4h: ja4h_supplied,
                        ja4s: ja4s_supplied,
                        trustworthy,
                    });
                }
            }
        }

        // --- Wave 5 / G5.3 wire: JA4H HTTP fingerprint ---
        //
        // The TLS-handshake-time JA3 / JA4 are stamped on
        // `ctx.tls_fingerprint` by the Pingora TLS lifecycle hook in
        // `sbproxy_tls`. JA4H requires the request headers, which are
        // not yet available at handshake time; compute it here, after
        // the trust-boundary header strip and the aipref parse, so the
        // hash reflects exactly the headers the upstream pipeline
        // sees. Skips entirely when the `tls-fingerprint` feature is
        // off, when no fingerprint was captured (plaintext HTTP), or
        // when the fingerprint already has a `ja4h` value (a
        // pre-stamped value from an enterprise hook).
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
                    let header_names: Vec<&str> =
                        req.headers.keys().map(|name| name.as_str()).collect();
                    fp.ja4h = Some(sbproxy_tls::compute_ja4h(
                        method,
                        version_label,
                        header_names.iter().copied(),
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

        // --- Wave 5 / A5.2 wire: ML classifier dispatch ---
        //
        // Run the registered ML classifier hooks after the rule-based
        // resolver chain has stamped its verdict so the snapshot's
        // `agent_id_source` reflects the rule-based outcome. The OSS
        // pipeline holds every input the enterprise feature builder
        // consumes: `agent_id` / `agent_id_source` (G1.4),
        // `tls_fingerprint` (G5.3), `headless_signal` (G5.4), plus the
        // request-shape and rate-limit telemetry.
        //
        // Each hook may run inference inline or already have done so;
        // the trait return type is the verdict, not a future. The
        // enterprise impl handles its own sync vs async dispatch via
        // `DispatchMode::from_config`. Returning `Some` writes the
        // verdict to `ctx.ml_classification`; the existing
        // `apply_ml_override` helper applies the A5.2 "Human override"
        // rule (Human at >= 0.9 confidence overrides the rule-based
        // verdict).
        #[cfg(feature = "agent-classifier")]
        {
            let hooks = sbproxy_plugin::ml_classifier_hooks();
            if !hooks.is_empty() {
                let req_header = session.req_header();
                let method_str = req_header.method.as_str();
                let path_str = req_header.uri.path();
                let query_str = req_header.uri.query().unwrap_or("");
                let header_count = req_header.headers.iter().count();
                let accept_hdr = req_header
                    .headers
                    .get("accept")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let user_agent_hdr = req_header
                    .headers
                    .get(http::header::USER_AGENT)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let cookie_present = req_header.headers.get("cookie").is_some();
                let agent_id_source_label = ctx.agent_id_source.map(|s| s.as_str());
                #[cfg(feature = "tls-fingerprint")]
                let (ja4_fp, ja4_trust) = match ctx.tls_fingerprint.as_ref() {
                    Some(fp) => (fp.ja4.as_deref(), fp.trustworthy),
                    None => (None, false),
                };
                #[cfg(not(feature = "tls-fingerprint"))]
                let (ja4_fp, ja4_trust): (Option<&str>, bool) = (None, false);
                #[cfg(feature = "tls-fingerprint")]
                let known_headless = matches!(
                    ctx.headless_signal,
                    Some(crate::context::HeadlessSignal::Detected { .. })
                );
                #[cfg(not(feature = "tls-fingerprint"))]
                let known_headless = false;
                let snap = sbproxy_plugin::RequestSnapshotView {
                    method: method_str,
                    path: path_str,
                    query: query_str,
                    header_count,
                    body_size_bytes: None,
                    accept_header: accept_hdr,
                    user_agent: user_agent_hdr,
                    cookie_present,
                    ja4_fingerprint: ja4_fp,
                    ja4_trustworthy: ja4_trust,
                    known_headless,
                    agent_id_source: agent_id_source_label,
                    client_ip: ctx.client_ip,
                };
                for hook in hooks.iter() {
                    if let Some(verdict) = hook.classify(&snap).await {
                        // Map back into the closed
                        // `sbproxy_classifiers::MlClassification`.
                        let class = match verdict.class {
                            "human" => sbproxy_classifiers::MlClass::Human,
                            "llm-agent" | "llm_agent" => sbproxy_classifiers::MlClass::LlmAgent,
                            "scraper" => sbproxy_classifiers::MlClass::Scraper,
                            _ => sbproxy_classifiers::MlClass::Unknown,
                        };
                        ctx.ml_classification = Some(sbproxy_classifiers::MlClassification {
                            class,
                            confidence: verdict.confidence,
                            model_version: verdict.model_version,
                            feature_schema_version: verdict.feature_schema_version,
                        });
                        break;
                    }
                }
                // Apply the A5.2 "Human override" rule if a verdict
                // was stamped. The helper is a no-op when
                // `ml_classification` is `None` or when the verdict
                // does not match Human at >= 0.9 confidence.
                crate::agent_class::apply_ml_override(ctx);
            }
        }

        // --- Distributed tracing: extract or generate W3C Trace Context ---
        {
            let headers = &session.req_header().headers;
            let traceparent = headers.get("traceparent").and_then(|v| v.to_str().ok());
            let tracestate = headers.get("tracestate").and_then(|v| v.to_str().ok());

            ctx.trace_ctx = if let Some(tp) = traceparent {
                // Try W3C traceparent first.
                sbproxy_observe::trace_ctx::w3c::TraceContext::parse_with_state(tp, tracestate)
                    .or_else(|| Some(sbproxy_observe::TraceContext::new_random()))
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
                            .or_else(|| Some(sbproxy_observe::TraceContext::new_random()))
                        }
                        _ => Some(sbproxy_observe::TraceContext::new_random()),
                    }
                }
            };
        }

        // --- ACME HTTP-01 challenge interception ---
        let path = session.req_header().uri.path();
        if let Some(token) = sbproxy_tls::challenges::extract_challenge_token(path) {
            if let Some(store) = reload::challenge_store() {
                if let Some(key_auth) = store.get(token) {
                    debug!(token = %token, "serving ACME HTTP-01 challenge response");
                    send_response(session, 200, "text/plain", key_auth.as_bytes()).await?;
                    return Ok(true);
                }
            }
        }

        // --- Health check endpoint ---
        if path == "/health" {
            send_response(session, 200, "application/json", b"{\"status\":\"ok\"}").await?;
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
            let raw_log_enabled = reload::current_pipeline().page_shield_raw_report_log;
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

        let pipeline = reload::current_pipeline();
        let origin_idx = match pipeline.resolve_origin(hostname) {
            Some(idx) => idx,
            None => {
                warn!(hostname = %hostname, "no origin configured for hostname");
                send_error(session, 404, "not found").await?;
                return Ok(true);
            }
        };
        ctx.origin_idx = Some(origin_idx);

        // Increment per-origin active connections after successful resolution.
        sbproxy_observe::metrics::inc_active(ctx.hostname.as_str());

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
                let mut header =
                    pingora_http::ResponseHeader::build(301, Some(1)).map_err(|e| {
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
                let content_type = session
                    .req_header()
                    .headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if content_type.contains("application/json") {
                    let body_bytes = session.read_request_body().await?;
                    if let Some(ref body) = body_bytes {
                        if let Err(msg) = threat.check_json_body(body) {
                            debug!(detail = %msg, "threat protection blocked request");
                            send_error(session, 413, "request entity too large").await?;
                            return Ok(true);
                        }
                    }
                }
            }
        }

        // --- Auth check ---
        if let Some(auth) = &pipeline.auths[origin_idx] {
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
                    Err((status, msg)) => {
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
                        send_error_with_pages(session, status, &msg, &origin.error_pages, &path)
                            .await?;
                        return Ok(true);
                    }
                }
            } else {
                let req_headers = &session.req_header().headers;
                let query = session.req_header().uri.query();
                let method = session.req_header().method.as_str();
                let path = session.req_header().uri.path();
                match check_auth(auth, req_headers, query, method, path).await {
                    AuthResult::Allow { sub, source } => {
                        ctx.auth_result = Some(sbproxy_plugin::AuthDecision::Allow { sub, source });
                        sbproxy_observe::metrics::record_auth(&origin_label, &auth_type, true);
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
                        send_error_with_pages(session, status, msg, &origin.error_pages, &path)
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
                        send_error_with_extra_headers(session, status, msg, extra_headers).await?;
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
                        let mut header = pingora_http::ResponseHeader::build(401, Some(3))
                            .map_err(|e| {
                                Error::because(
                                    ErrorType::InternalError,
                                    "digest challenge header",
                                    e,
                                )
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

        // --- Wave 8 P0 edge capture ---
        //
        // Stamp custom properties, session linkage, and end-user ID
        // onto the request context per docs/adr-event-envelope.md and
        // the three companion stream ADRs. Runs after auth so the
        // user-id resolution sees the JWT `sub` / forward-auth subject
        // pulled from `ctx.auth_result`. Per-origin overrides come
        // from the compiled origin (T1.3); when absent, the type's
        // `Default` applies (capture on, no echo, anonymous
        // auto-generate).
        {
            let headers_owned: http::HeaderMap = session
                .req_header()
                .headers
                .iter()
                .map(|(n, v)| (n.clone(), v.clone()))
                .collect();
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
            crate::wave8::capture_dimensions(
                ctx,
                &headers_owned,
                &properties_cfg,
                &sessions_cfg,
                &user_cfg,
                jwt_sub.as_deref(),
                forward_auth_user.as_deref(),
                &workspace_id,
            );
        }

        // --- Policy enforcement ---
        let policy_origin = ctx.hostname.to_string();
        match check_policies(&pipeline.policies[origin_idx], session, ctx).await {
            PolicyResult::Allow(rl_info) => {
                sbproxy_observe::metrics::record_policy(&policy_origin, "all", "allow");
                ctx.rate_limit_info = rl_info;
            }
            PolicyResult::Deny(status, msg, rl_info, policy_type) => {
                // The enforcing policy stamps its own stable label
                // (`waf`, `ip_filter`, `prompt_injection`, ...) so
                // dashboards and SIEM rules can break down by module
                // instead of inferring from the response status.
                sbproxy_observe::metrics::record_policy(&policy_origin, policy_type, "deny");
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
                .emit();
                if status == 429 && (policy_type == "rate_limit" || policy_type == "ddos") {
                    // Rate-limit + DDoS denial. Both emit 429 with a
                    // RateLimitInfo and want the same wrapped envelope
                    // and X-RateLimit-* + Retry-After headers. Other
                    // policies that emit 429 (e.g. a2a_chain_depth_exceeded)
                    // fall through to their own dedicated branches below
                    // so their spec-pinned bodies and headers survive
                    // intact.
                    let body = format!("{{\"error\":\"{msg}\"}}");
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
                        if info.headers_enabled {
                            let _ =
                                header.insert_header("X-RateLimit-Limit", info.limit.to_string());
                            let _ = header
                                .insert_header("X-RateLimit-Remaining", info.remaining.to_string());
                            let _ = header
                                .insert_header("X-RateLimit-Reset", info.reset_secs.to_string());
                        }
                        if info.include_retry_after {
                            let _ =
                                header.insert_header("Retry-After", info.reset_secs.to_string());
                        }
                    }
                    session
                        .write_response_header(Box::new(header), false)
                        .await?;
                    session
                        .write_response_body(
                            Some(bytes::Bytes::copy_from_slice(body.as_bytes())),
                            true,
                        )
                        .await?;
                } else if status == 402 {
                    // AI crawl control: 402 with the configured
                    // challenge header and a JSON body the crawler
                    // can introspect for price + retry instructions.
                    let (header_name, challenge, body) =
                        ctx.crawl_challenge.take().unwrap_or_else(|| {
                            (
                                "crawler-payment".to_string(),
                                "Crawler-Payment realm=\"ai-crawl\"".to_string(),
                                format!("{{\"error\":\"{msg}\"}}"),
                            )
                        });
                    let mut header =
                        pingora_http::ResponseHeader::build(status, Some(3)).map_err(|e| {
                            Error::because(
                                ErrorType::InternalError,
                                "failed to build response header",
                                e,
                            )
                        })?;
                    // G3.4 multi-rail emits the response via the same
                    // crawl_challenge slot but uses the sentinel
                    // header_name `Content-Type` to signal "stamp this
                    // value as Content-Type, skip the Crawler-Payment
                    // header". Wave 1 single-rail keeps the original
                    // behaviour: Content-Type is application/json and
                    // header_name carries the Crawler-Payment value.
                    if header_name.eq_ignore_ascii_case("content-type") {
                        let _ = header.insert_header("content-type", &challenge);
                    } else {
                        let _ = header.insert_header("content-type", "application/json");
                        let _ = header.insert_header(header_name, &challenge);
                    }
                    // Content-Length is required so HTTP/1.1 keep-alive
                    // clients know where the body ends without waiting
                    // for a connection close.
                    let _ = header.insert_header("content-length", body.len().to_string());
                    session
                        .write_response_header(Box::new(header), false)
                        .await?;
                    session
                        .write_response_body(
                            Some(bytes::Bytes::copy_from_slice(body.as_bytes())),
                            true,
                        )
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
                        .map(|(_, _, body)| body)
                        .unwrap_or_else(|| format!("{{\"error\":\"{msg}\"}}"));
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
                        .write_response_body(
                            Some(bytes::Bytes::copy_from_slice(body.as_bytes())),
                            true,
                        )
                        .await?;
                } else if status == 503 && policy_type == "ai_crawl_ledger_unavailable" {
                    // AI crawl control: ledger is transiently down. Emit
                    // the policy-supplied JSON body verbatim and stamp
                    // a Retry-After from the synthesized RateLimitInfo.
                    let body = ctx
                        .crawl_challenge
                        .take()
                        .map(|(_, _, body)| body)
                        .unwrap_or_else(|| format!("{{\"error\":\"{msg}\"}}"));
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
                            let _ =
                                header.insert_header("Retry-After", info.reset_secs.to_string());
                        }
                    }
                    session
                        .write_response_header(Box::new(header), false)
                        .await?;
                    session
                        .write_response_body(
                            Some(bytes::Bytes::copy_from_slice(body.as_bytes())),
                            true,
                        )
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
                        .unwrap_or_else(|| format!("{{\"error\":\"{msg}\"}}"));
                    let header_count = if policy_type == "a2a_chain_depth_exceeded" {
                        3
                    } else {
                        2
                    };
                    let mut header =
                        pingora_http::ResponseHeader::build(status, Some(header_count)).map_err(
                            |e| {
                                Error::because(
                                    ErrorType::InternalError,
                                    "failed to build response header",
                                    e,
                                )
                            },
                        )?;
                    let _ = header.insert_header("content-type", "application/json");
                    let _ = header.insert_header("content-length", body.len().to_string());
                    if policy_type == "a2a_chain_depth_exceeded" {
                        let _ = header.insert_header("Retry-After", "0");
                    }
                    session
                        .write_response_header(Box::new(header), false)
                        .await?;
                    session
                        .write_response_body(
                            Some(bytes::Bytes::copy_from_slice(body.as_bytes())),
                            true,
                        )
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
            pipeline.cache_store.as_ref(),
        ) {
            if cache_cfg.enabled {
                let req_method = session.req_header().method.as_str().to_string();

                // --- Mutation invalidation ---
                // Fire before any lookup so a `POST /x` followed by a
                // re-issued `GET /x` in the same flow sees the eviction.
                if cache_cfg.invalidate_on_mutation
                    && sbproxy_cache::is_mutation_method(&req_method)
                {
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
                                let mut header = pingora_http::ResponseHeader::build(
                                    entry.status,
                                    Some(entry.headers.len() + 1),
                                )
                                .map_err(|e| {
                                    Error::because(
                                        ErrorType::InternalError,
                                        "cache hit response header",
                                        e,
                                    )
                                })?;
                                for (name, value) in &entry.headers {
                                    let _ = header.insert_header(name.clone(), value.clone());
                                }
                                let _ = header.insert_header("x-sbproxy-cache", cache_marker);

                                session
                                    .write_response_header(Box::new(header), false)
                                    .await?;
                                session
                                    .write_response_body(
                                        Some(bytes::Bytes::copy_from_slice(&entry.body)),
                                        true,
                                    )
                                    .await?;
                                ctx.served_from_cache = true;

                                // --- SWR revalidation ---
                                // On a stale serve, kick off a background fetch
                                // of the upstream so the next request lands on
                                // a fresh entry. The task is tracked by
                                // CACHE_REVALIDATE_TASKS so graceful shutdown
                                // can drain in-flight refreshes.
                                if in_swr {
                                    let req = session.req_header();
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
                                    spawn_swr_revalidation(
                                        cache_store.clone(),
                                        key.clone(),
                                        new_ttl,
                                        origin.action_config.clone(),
                                        ctx.hostname.to_string(),
                                        path_and_query,
                                        cacheable_status,
                                    );
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
                                                let cached = sbproxy_cache::CachedResponse {
                                                    status: promote_meta.status,
                                                    headers: vec![],
                                                    body: promote_body.to_vec(),
                                                    cached_at: std::time::SystemTime::now()
                                                        .duration_since(std::time::UNIX_EPOCH)
                                                        .unwrap_or_default()
                                                        .as_secs(),
                                                    ttl_secs:
                                                        promote_meta
                                                            .expires_at
                                                            .duration_since(
                                                                std::time::SystemTime::now(),
                                                            )
                                                            .map(|d| d.as_secs())
                                                            .unwrap_or(60),
                                                };
                                                let _ = promote_store.put(&promote_key, &cached);
                                            })
                                            .await;
                                            // Serve.
                                            let mut header = pingora_http::ResponseHeader::build(
                                                metadata.status,
                                                Some(2),
                                            )
                                            .map_err(|e| {
                                                Error::because(
                                                    ErrorType::InternalError,
                                                    "reserve hit response header",
                                                    e,
                                                )
                                            })?;
                                            if let Some(ct) = metadata.content_type.as_ref() {
                                                let _ = header.insert_header("content-type", ct);
                                            }
                                            let _ = header
                                                .insert_header("x-sbproxy-cache", "HIT-RESERVE");
                                            session
                                                .write_response_header(Box::new(header), false)
                                                .await?;
                                            session.write_response_body(Some(body), true).await?;
                                            ctx.served_from_cache = true;
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

        // --- Forward rules: path/header/query routing to inline origins ---
        let request_path = session.req_header().uri.path().to_string();
        let request_query = session.req_header().uri.query().map(|q| q.to_string());
        let fwd_rules = &pipeline.forward_rules[origin_idx];
        if !fwd_rules.is_empty() {
            for (rule_idx, fwd_rule) in fwd_rules.iter().enumerate() {
                // Each `MatcherEntry` ANDs path/header/query; entries in the
                // list are ORed. `match_request` returns the captured path
                // params (possibly empty) when the entry fires.
                let request_headers = &session.req_header().headers;
                let captured = fwd_rule.matchers.iter().find_map(|m| {
                    m.match_request(&request_path, request_query.as_deref(), request_headers)
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
                let mut header =
                    pingora_http::ResponseHeader::build(status, Some(1)).map_err(|e| {
                        Error::because(
                            ErrorType::InternalError,
                            "failed to build response header",
                            e,
                        )
                    })?;
                header
                    .insert_header("content-type", "text/plain")
                    .map_err(|e| {
                        Error::because(ErrorType::InternalError, "failed to set header", e)
                    })?;
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

        {
            let pipeline = reload::current_pipeline();
            if let Some(idx) = ctx.origin_idx {
                let origin = &pipeline.config.origins[idx];

                // Extract the URL path from the proxy action so we can prepend it
                // to the upstream request path. This ensures that configs like
                // `url: http://backend:8080/api` proxy to /api/... not just /...
                let effective_action: &Action = if let Some(fwd_idx) = ctx.forward_rule_idx {
                    &pipeline.forward_rules[idx][fwd_idx].action
                } else {
                    &pipeline.actions[idx]
                };

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
        // --- Wave 5 / G5.6 wire: AnomalyDetectorHook dispatch ---
        //
        // Run every registered anomaly detector hook against the
        // per-request context now that all signals have been populated
        // (TLS fingerprint, ML classification, headless detection,
        // request rate). Verdicts are forwarded to whichever sink the
        // hook impl wires (audit log, tracing, reputation updater).
        // The OSS pipeline does not act on the verdicts directly; the
        // enterprise side is responsible for routing them through the
        // alert sink + reputation tally.
        //
        // OSS-only builds register no anomaly hooks; the iteration is
        // a no-op. Enterprise builds install the detector at startup
        // (see `sbproxy_enterprise_modules::anomaly::wiring`).
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
            // Per `docs/adr-content-negotiation-and-pricing.md` §
            // "Content-Signal response header" (G4.1): when the origin
            // sets a closed-enum `content_signal` value the proxy
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

        // 8. Wave 8 P0 session ID echo (per docs/adr-session-id.md).
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
                            let mutations = t.evaluate_headers(
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
                if let Some(m) = ctx.mirror_pending.as_mut() {
                    if m.mirror_body {
                        // Move the params + body to a spawned task.
                        let params = ctx.mirror_pending.take().unwrap();
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
                    }
                }
            }
            // Mid-stream chunks: hold off forwarding until end_of_stream.
            return Ok(());
        }

        // Mirror that doesn't need the body (mirror_body: false) -
        // fire on first body filter call so the shadow request is
        // not delayed by an upload it doesn't care about.
        if end_of_stream {
            if let Some(m) = ctx.mirror_pending.as_ref() {
                if !m.mirror_body {
                    let params = ctx.mirror_pending.take().unwrap();
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
                            if compiled_transform.fail_on_error {
                                warn!(
                                    hostname = %ctx.hostname,
                                    transform = compiled_transform.transform.transform_type(),
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
                                transform = compiled_transform.transform.transform_type(),
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

        // Default error handling (no fallback configured or fallback failed).
        let code = 502u16;
        let _ = send_error(session, code, "bad gateway").await;
        ctx.response_status = Some(code);
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    /// End-of-request callback for metrics, events, and connection tracking.
    ///
    /// Called when the response is fully sent or on fatal error. Records
    /// request metrics, emits events, and decrements load balancer counters.
    async fn logging(&self, session: &mut Session, _e: Option<&Error>, ctx: &mut Self::CTX)
    where
        Self::CTX: Send + Sync,
    {
        // Decrement active connections gauge (global + per-origin).
        metrics().active_connections.dec();

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
                .with_label_values(&[&hostname])
                .observe(duration);
        }

        // Per-origin active-connection bookkeeping. The actual request
        // counter + per-origin views were updated in the
        // `record_request_with_labels` call above, so we only need to
        // decrement the active gauge here.
        if !hostname.is_empty() {
            sbproxy_observe::metrics::dec_active(&hostname);
        }

        // Record errors.
        if _e.is_some() {
            metrics()
                .errors_total
                .with_label_values(&[&hostname, "proxy_error"])
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
        // the broker per docs/adr-event-ingest-pipeline.md.
        let latency_ms_envelope: Option<u32> = ctx.request_start.map(|s| {
            let ms = s.elapsed().as_millis();
            // Saturate at u32::MAX rather than overflow on the
            // (impossibly long) request that runs longer than ~49
            // days; log emission must not panic.
            u32::try_from(ms).unwrap_or(u32::MAX)
        });
        let error_class = if _e.is_some() {
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

// --- Access log emission helpers ---

/// Pull the per-agent label bundle off the request context.
///
/// Wave 3 / G1.6 wire: when the `agent-class` feature is on the
/// request pipeline runs the `AgentClassResolver` early in
/// `request_filter`, stamping `agent_id`, `agent_vendor`, etc. onto
/// the context. The hot-path `logging` callback feeds those values
/// into the per-agent metric labels via this helper.
///
/// When the feature is off, the helper returns the all-empty
/// `AgentLabels::unset()` and the cardinality limiter sees an empty
/// label set (no demotions, no overhead).
///
/// `payment_rail` and `content_shape` are intentionally left empty
/// here: payment-rail resolution is a Wave 3 follow-up (the rail is
/// known after the AI handler dispatches but before the response
/// completes; threading it through the logging hook is a separate
/// task). `content_shape` is observed at response-time and lives on
/// a follow-up label-stamping path.
fn build_agent_labels(ctx: &RequestContext) -> sbproxy_observe::AgentLabels<'_> {
    #[cfg(feature = "agent-class")]
    {
        sbproxy_observe::AgentLabels {
            agent_id: ctx.agent_id.as_ref().map(|id| id.as_str()).unwrap_or(""),
            agent_class: agent_class_label(ctx),
            agent_vendor: ctx.agent_vendor.as_deref().unwrap_or(""),
            payment_rail: "",
            content_shape: "",
        }
    }
    #[cfg(not(feature = "agent-class"))]
    {
        let _ = ctx;
        sbproxy_observe::AgentLabels::unset()
    }
}

/// Map the resolved `AgentPurpose` to the `agent_class` label vocabulary.
///
/// The metric label is the closed-string view from
/// `docs/adr-metric-cardinality.md`; the resolver carries the typed
/// `AgentPurpose` enum. This shim flattens to the metric vocabulary
/// without allocation.
///
/// When the resolver has not run, return `""` (the documented "no
/// classification" sentinel). When it has run but the catalog yields
/// `Unknown`, return `"unknown"` so dashboards can split untyped
/// traffic from explicitly unclassified traffic.
#[cfg(feature = "agent-class")]
fn agent_class_label(ctx: &RequestContext) -> &'static str {
    use sbproxy_classifiers::AgentPurpose;
    match ctx.agent_purpose {
        // Distinguish "no resolution" from "resolved to Unknown".
        Some(AgentPurpose::Unknown) if ctx.agent_id.is_some() => "unknown",
        Some(AgentPurpose::Unknown) => "",
        Some(p) => p.as_str(),
        None => "",
    }
}

// --- Wave 3 / G1.4 wire: agent-class resolver startup ---

/// Build the process-wide `AgentClassResolver` from the parsed
/// top-level `agent_classes:` block (or defaults when absent) and
/// install it in [`reload::set_agent_class_resolver`].
///
/// Catalog selection mirrors the YAML schema:
///
/// - `None` (no top-level block) or `catalog: builtin`: use
///   `AgentClassCatalog::defaults()`.
/// - `catalog: hosted-feed`: reserved for the registry fetcher landing
///   in G2.2; for now we log a warning and fall back to defaults so
///   YAML written against the larger schema still boots.
/// - `catalog: merged`: same as `hosted-feed` until G2.2 ships the
///   overlay path. Falls back to defaults with the same warning.
/// - Any other catalog string: warns and falls back to defaults.
///
/// DNS resolver: the OSS build does not pull `hickory-resolver`, so we
/// install [`sbproxy_security::agent_verify::SystemResolver`]. Its
/// `reverse()` returns an error verdict; the resolver chain treats
/// that as a transient miss and falls through to UA matching, matching
/// the documented "no working PTR" degradation path. Operators who
/// want forward-confirmed rDNS in production can flip
/// `agent_classes.resolver.rdns_enabled: false` to skip the lookup
/// entirely (saves a syscall) until a real resolver lands.
///
/// Cache size honours `agent_classes.resolver.cache_size`; the default
/// (10 000 entries) matches the OSS recommendation in the resolver
/// docs.
#[cfg(feature = "agent-class")]
fn install_agent_class_resolver(block: Option<&sbproxy_config::AgentClassesConfig>) {
    use std::sync::Arc;

    use sbproxy_classifiers::AgentClassCatalog;
    use sbproxy_modules::policy::agent_class::AgentClassResolver;
    use sbproxy_security::agent_verify::SystemResolver;

    let (catalog, cache_size) = match block {
        None => (AgentClassCatalog::defaults(), 10_000usize),
        Some(cfg) => {
            let catalog = match cfg.catalog.as_str() {
                "builtin" => AgentClassCatalog::defaults(),
                "hosted-feed" | "merged" => {
                    tracing::warn!(
                        catalog = %cfg.catalog,
                        "agent_classes.catalog '{}' selected but the registry fetcher \
                         (G2.2) has not landed yet; falling back to the built-in defaults",
                        cfg.catalog,
                    );
                    AgentClassCatalog::defaults()
                }
                other => {
                    tracing::warn!(
                        catalog = %other,
                        "agent_classes.catalog '{}' is not recognised; falling back to \
                         the built-in defaults",
                        other,
                    );
                    AgentClassCatalog::defaults()
                }
            };
            (catalog, cfg.resolver.cache_size)
        }
    };

    let dns_resolver = Arc::new(SystemResolver);
    let resolver = AgentClassResolver::new(Arc::new(catalog), dns_resolver, cache_size);
    reload::set_agent_class_resolver(Arc::new(resolver));
    tracing::info!(
        cache_size = %cache_size,
        "agent_class resolver installed",
    );
}

/// Cached default-rule PII redactor for access-log header capture.
/// Building the redactor compiles ~10 regexes plus an Aho-Corasick
/// prefilter, so we keep one instance for the whole process lifetime.
/// The scoped variant (`access_log.capture_headers.redact_pii_rules`)
/// is built per-emit because it depends on operator config; the cost
/// is bounded by the access-log sample rate in practice.
fn default_pii_redactor() -> &'static sbproxy_security::pii::PiiRedactor {
    static CELL: std::sync::OnceLock<sbproxy_security::pii::PiiRedactor> =
        std::sync::OnceLock::new();
    CELL.get_or_init(sbproxy_security::pii::PiiRedactor::defaults)
}

/// Build a PII redactor scoped to the named subset of the built-in
/// default rules. Case-insensitive name match. Returns `None` when no
/// names match, so the caller can fall back to no-redaction.
fn build_scoped_pii_redactor(rule_names: &[String]) -> Option<sbproxy_security::pii::PiiRedactor> {
    let scoped: Vec<sbproxy_security::pii::PiiRule> = sbproxy_security::pii::default_rules()
        .into_iter()
        .filter(|r| rule_names.iter().any(|n| n.eq_ignore_ascii_case(&r.name)))
        .collect();
    if scoped.is_empty() {
        return None;
    }
    let cfg = sbproxy_security::pii::PiiConfig {
        enabled: true,
        defaults: false,
        redact_request: true,
        redact_response: true,
        rules: scoped,
    };
    sbproxy_security::pii::PiiRedactor::from_config(&cfg).ok()
}

/// Capture the subset of `headers` that the compiled allowlist
/// accepts, applying the configured truncation and (optional)
/// PII redaction. Returns an empty map when the allowlist is empty
/// (the common case).
fn capture_headers_for_log(
    headers: &http::HeaderMap,
    allowlist: &sbproxy_config::CompiledHeaderAllowlist,
    max_value_bytes: usize,
    redact_pii: bool,
    redact_pii_rules: &[String],
) -> std::collections::BTreeMap<String, String> {
    if allowlist.is_empty() {
        return std::collections::BTreeMap::new();
    }
    if redact_pii {
        if redact_pii_rules.is_empty() {
            let redactor = default_pii_redactor();
            sbproxy_observe::capture::capture_headers(
                headers,
                |name| allowlist.matches(name),
                max_value_bytes,
                Some(|v: &str| redactor.redact(v).into_owned()),
            )
        } else if let Some(redactor) = build_scoped_pii_redactor(redact_pii_rules) {
            sbproxy_observe::capture::capture_headers(
                headers,
                |name| allowlist.matches(name),
                max_value_bytes,
                Some(|v: &str| redactor.redact(v).into_owned()),
            )
        } else {
            // No matching rules: fall through to no-redaction.
            sbproxy_observe::capture::capture_headers(
                headers,
                |name| allowlist.matches(name),
                max_value_bytes,
                None::<fn(&str) -> String>,
            )
        }
    } else {
        sbproxy_observe::capture::capture_headers(
            headers,
            |name| allowlist.matches(name),
            max_value_bytes,
            None::<fn(&str) -> String>,
        )
    }
}

/// Emit one-shot WARN lines for sensitive headers an operator opted
/// into capturing by exact name. Called from the config-load and
/// config-reload paths so the warning surfaces once per reload, not
/// per request.
fn log_capture_header_warnings(cfg: &sbproxy_config::AccessLogConfig) {
    let (_, req_warnings) =
        sbproxy_config::CompiledHeaderAllowlist::compile(&cfg.capture_headers.request);
    let (_, resp_warnings) =
        sbproxy_config::CompiledHeaderAllowlist::compile(&cfg.capture_headers.response);
    for header in &req_warnings {
        tracing::warn!(
            header = %header,
            "access_log.capture_headers.request includes a sensitive header by exact match; \
             values will be captured (redact_secrets still strips known token shapes)",
        );
    }
    for header in &resp_warnings {
        tracing::warn!(
            header = %header,
            "access_log.capture_headers.response includes a sensitive header by exact match; \
             values will be captured (redact_secrets still strips known token shapes)",
        );
    }
}

/// Build and emit an access-log entry when the active pipeline has
/// access-log emission enabled and the request passes the filter and
/// sampler. A no-op when access-log is unconfigured or disabled.
fn emit_access_log(
    session: &Session,
    ctx: &RequestContext,
    status: u16,
    method: &str,
    hostname: &str,
    duration_secs: f64,
) {
    let pipeline = reload::current_pipeline();
    let Some(cfg) = pipeline.config.access_log.as_ref() else {
        return;
    };

    let path = session.req_header().uri.path().to_string();
    let trace_id = ctx.trace_ctx.as_ref().map(|t| t.trace_id.clone());
    let request_id = if !ctx.request_id.is_empty() {
        ctx.request_id.to_string()
    } else {
        uuid::Uuid::new_v4().to_string()
    };
    let client_ip = ctx.client_ip.map(|ip| ip.to_string()).unwrap_or_default();

    let auth_type = ctx
        .origin_idx
        .and_then(|idx| pipeline.auths.get(idx))
        .and_then(|opt| opt.as_ref())
        .map(|auth| auth.auth_type().to_string());
    let workspace_id = ctx
        .origin_idx
        .and_then(|idx| pipeline.config.origins.get(idx))
        .map(|origin| origin.workspace_id.to_string())
        .unwrap_or_default();

    // The cache-result label comes from `ctx.cache_status` (set when
    // a cacheable response landed in the store) and
    // `ctx.served_from_cache` (set when the request hit the cache and
    // skipped the upstream). The two combine into the four canonical
    // labels the access log records.
    let cache_result = if ctx.served_from_cache {
        Some("hit".to_string())
    } else if ctx.cache_status.is_some() {
        Some("miss".to_string())
    } else {
        None
    };

    // --- Wave 6 / G6.2 access-log v1 stamping ---
    //
    // The body-shape transformer field (G4.3 / G4.4) lands as a
    // closed-enum string for the `shape` access-log field. The
    // pricing-pass shape is recorded separately via the existing
    // `content_shape` slot stamped by the agent-class wiring.
    let shape = ctx
        .content_shape_transform
        .as_ref()
        .map(|s| format!("{s:?}").to_ascii_lowercase());

    // --- G6.4 captured-header stamping ---
    //
    // Compile the allowlists per emit. The allowlist is small (a
    // handful of header names plus optional globs) so the compile cost
    // is negligible relative to the JSON serialisation that follows.
    // Caching the compiled form on the pipeline is a follow-up; doing
    // so requires plumbing through the `CompiledPipeline` build path
    // and is out of scope for the first cut.
    let (request_headers, response_headers) =
        if cfg.capture_headers.request.is_empty() && cfg.capture_headers.response.is_empty() {
            (
                std::collections::BTreeMap::new(),
                std::collections::BTreeMap::new(),
            )
        } else {
            let (req_allow, _) =
                sbproxy_config::CompiledHeaderAllowlist::compile(&cfg.capture_headers.request);
            let (resp_allow, _) =
                sbproxy_config::CompiledHeaderAllowlist::compile(&cfg.capture_headers.response);
            let req_headers = capture_headers_for_log(
                &session.req_header().headers,
                &req_allow,
                cfg.capture_headers.max_value_bytes,
                cfg.capture_headers.redact_pii,
                &cfg.capture_headers.redact_pii_rules,
            );
            let resp_headers = match session.response_written() {
                Some(written) => capture_headers_for_log(
                    &written.headers,
                    &resp_allow,
                    cfg.capture_headers.max_value_bytes,
                    cfg.capture_headers.redact_pii,
                    &cfg.capture_headers.redact_pii_rules,
                ),
                None => std::collections::BTreeMap::new(),
            };
            (req_headers, resp_headers)
        };

    let context = AccessLogContext {
        envelope_request_id: ctx.envelope_request_id.map(|u| u.to_string()),
        user_id: ctx.user_id.clone(),
        user_id_source: ctx.user_id_source,
        session_id: ctx.session_id.map(|u| u.to_string()),
        parent_session_id: ctx.parent_session_id.map(|u| u.to_string()),
        properties: ctx.properties.clone(),
        workspace_id,
        auth_type,
        served_from_cache: Some(ctx.served_from_cache),
        fallback_triggered: Some(ctx.fallback_triggered),
        retry_count: Some(ctx.retry_count),
        forward_rule_idx: ctx.forward_rule_idx,
        request_geo: ctx.request_geo.clone(),
        classifier_prompt: ctx.classifier_prompt.as_ref().map(classifier_label),
        classifier_intent: ctx.classifier_intent.map(intent_label),
        error_class: classify_error_class(status),
        bytes_in: ctx.request_body_bytes,
        bytes_out: ctx.response_body_bytes,
        provider: ctx.ai_provider.clone(),
        model: ctx.ai_model.clone(),
        tokens_in: ctx.ai_tokens_in,
        tokens_out: ctx.ai_tokens_out,
        cache_result,
        // Wave 6 / G6.2 access-log v1 fields. Most surface stamping
        // lands as the request flows through the pipeline (e.g.
        // `cap_token_id` from the CAP verifier in R6.1, `rail` /
        // `txhash` from the multi-rail 402 handler, `tier` from the
        // tier resolver). At this terminal site we copy whatever is
        // already on `RequestContext`; later waves widen the context
        // surface and this stamping layer follows.
        tier: None,
        shape,
        price: None,
        currency: None,
        rail: None,
        redeemed_token_id: None,
        txhash: None,
        license_token_id: None,
        cap_token_id: None,
        upstream_host: None,
        request_headers,
        response_headers,
    };

    emit_access_log_entry(
        cfg,
        status,
        method,
        hostname,
        &path,
        duration_secs,
        request_id,
        client_ip,
        trace_id,
        context,
    );
}

/// Bundle of `RequestContext`-derived fields that flow into the
/// access-log entry. Pulled out so the test entry-point and the
/// production path share the same shape, and so adding a field
/// doesn't churn every test fixture.
struct AccessLogContext {
    envelope_request_id: Option<String>,
    user_id: Option<String>,
    user_id_source: Option<sbproxy_observe::UserIdSource>,
    session_id: Option<String>,
    parent_session_id: Option<String>,
    properties: std::collections::BTreeMap<String, String>,
    workspace_id: String,
    auth_type: Option<String>,
    served_from_cache: Option<bool>,
    fallback_triggered: Option<bool>,
    retry_count: Option<u32>,
    forward_rule_idx: Option<usize>,
    request_geo: Option<String>,
    classifier_prompt: Option<String>,
    classifier_intent: Option<String>,
    error_class: Option<String>,
    /// Total request body bytes seen by `request_body_filter`.
    bytes_in: u64,
    /// Total response body bytes sent to the client by
    /// `response_body_filter`.
    bytes_out: u64,
    /// AI gateway provider name (`openai`, `anthropic`, ...) when
    /// the AI handler picked an upstream; `None` for non-AI traffic.
    provider: Option<String>,
    /// AI model identifier the request was routed to.
    model: Option<String>,
    /// Prompt / input tokens consumed (from the provider response).
    tokens_in: Option<u64>,
    /// Completion / output tokens generated.
    tokens_out: Option<u64>,
    /// Cache result label (`hit`, `miss`, `stale`, `bypass`) when
    /// the response cache ran.
    cache_result: Option<String>,
    // --- Wave 6 / G6.2 access-log v1 fields ---
    /// Pricing tier the request matched (`free`, `commercial`,
    /// operator-defined name).
    tier: Option<String>,
    /// Response body shape from the q-value-aware Accept resolver.
    shape: Option<String>,
    /// Quote price in micro-units of `currency`.
    price: Option<u64>,
    /// ISO 4217 fiat currency or rail-specific code.
    currency: Option<String>,
    /// Billing rail that settled the request.
    rail: Option<String>,
    /// `jti` of the redeemed quote token.
    redeemed_token_id: Option<String>,
    /// On-chain settlement hash for crypto rails.
    txhash: Option<String>,
    /// `jti` of the OLP license token presented.
    license_token_id: Option<String>,
    /// `jti` of the CAP token presented.
    cap_token_id: Option<String>,
    /// Resolved upstream host the request was proxied to.
    upstream_host: Option<String>,
    /// G6.4 captured request headers (lowercased keys, truncated and
    /// optionally PII-redacted values). Empty when capture is off or
    /// no allowlisted header was present on the request.
    request_headers: std::collections::BTreeMap<String, String>,
    /// G6.4 captured response headers; same semantics as
    /// `request_headers`. Empty when no response was written (early
    /// abort) or no allowlisted header was set on the response.
    response_headers: std::collections::BTreeMap<String, String>,
}

impl AccessLogContext {
    #[cfg(test)]
    fn empty() -> Self {
        Self {
            envelope_request_id: None,
            user_id: None,
            user_id_source: None,
            session_id: None,
            parent_session_id: None,
            properties: std::collections::BTreeMap::new(),
            workspace_id: String::new(),
            auth_type: None,
            served_from_cache: None,
            fallback_triggered: None,
            retry_count: None,
            forward_rule_idx: None,
            request_geo: None,
            classifier_prompt: None,
            classifier_intent: None,
            error_class: None,
            bytes_in: 0,
            bytes_out: 0,
            provider: None,
            model: None,
            tokens_in: None,
            tokens_out: None,
            cache_result: None,
            tier: None,
            shape: None,
            price: None,
            currency: None,
            rail: None,
            redeemed_token_id: None,
            txhash: None,
            license_token_id: None,
            cap_token_id: None,
            upstream_host: None,
            request_headers: std::collections::BTreeMap::new(),
            response_headers: std::collections::BTreeMap::new(),
        }
    }
}

/// Compact stable label for the prompt classifier verdict. The full
/// score map lives on the Wave 8 envelope event; the access log only
/// carries the top label so downstream ML pipelines have a bounded
/// feature dimension. Empty `labels` falls back to `"unknown"`.
fn classifier_label(verdict: &crate::hooks::ClassifyVerdict) -> String {
    verdict
        .labels
        .first()
        .cloned()
        .unwrap_or_else(|| "unknown".to_string())
}

fn intent_label(intent: crate::hooks::IntentCategory) -> String {
    format!("{intent:?}").to_ascii_lowercase()
}

/// Map a status code to a coarse failure label suitable for an ML
/// feature. `None` for 2xx; categorical strings otherwise. Specific
/// failure modes (waf_blocked, rate_limited, ...) are stamped at the
/// failure site via `ctx.short_circuit_status` paths; this fallback
/// only fires when no upstream classification ran.
fn classify_error_class(status: u16) -> Option<String> {
    match status {
        200..=299 => None,
        401 | 403 => Some("auth_denied".to_string()),
        404 => Some("not_found".to_string()),
        429 => Some("rate_limited".to_string()),
        408 | 504 => Some("upstream_timeout".to_string()),
        500..=599 => Some("upstream_5xx".to_string()),
        400..=499 => Some("client_error".to_string()),
        _ => Some("other".to_string()),
    }
}

/// Pure builder + sampler that the logging hook (and unit tests) call.
/// Splits cleanly off `emit_access_log` so we can drive the emission
/// pipeline without a Pingora `Session`.
#[allow(clippy::too_many_arguments)]
fn emit_access_log_entry(
    cfg: &sbproxy_config::AccessLogConfig,
    status: u16,
    method: &str,
    hostname: &str,
    path: &str,
    duration_secs: f64,
    request_id: String,
    client_ip: String,
    trace_id: Option<String>,
    context: AccessLogContext,
) {
    if !cfg.should_emit(status, method) {
        return;
    }
    if cfg.sample_rate < 1.0 && rand::random::<f64>() >= cfg.sample_rate {
        return;
    }

    let entry = sbproxy_observe::AccessLogEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        request_id,
        origin: hostname.to_string(),
        method: method.to_string(),
        path: path.to_string(),
        status,
        latency_ms: duration_secs * 1000.0,
        bytes_in: context.bytes_in,
        bytes_out: context.bytes_out,
        client_ip,
        provider: context.provider,
        model: context.model,
        tokens_in: context.tokens_in,
        tokens_out: context.tokens_out,
        trace_id,
        cache_result: context.cache_result,
        envelope_request_id: context.envelope_request_id,
        user_id: context.user_id,
        user_id_source: context.user_id_source,
        session_id: context.session_id,
        parent_session_id: context.parent_session_id,
        properties: context.properties,
        workspace_id: context.workspace_id,
        auth_type: context.auth_type,
        served_from_cache: context.served_from_cache,
        fallback_triggered: context.fallback_triggered,
        retry_count: context.retry_count,
        forward_rule_idx: context.forward_rule_idx,
        request_geo: context.request_geo,
        classifier_prompt: context.classifier_prompt,
        classifier_intent: context.classifier_intent,
        error_class: context.error_class,
        // Wave 1 / G1.6: per-agent dimensions. The agent-class
        // resolver (G1.4) lands the typed values on `context` in a
        // follow-up; until then the access log surfaces None and
        // dashboards keying on these fields treat the absence as
        // "unset".
        agent_id: None,
        agent_class: None,
        agent_vendor: None,
        payment_rail: None,
        content_shape: None,
        // Wave 6 / G6.2 access-log v1 fields. See the parent
        // `emit_access_log` for the per-field stamping commentary.
        tier: context.tier,
        shape: context.shape,
        price: context.price,
        currency: context.currency,
        rail: context.rail,
        redeemed_token_id: context.redeemed_token_id,
        txhash: context.txhash,
        license_token_id: context.license_token_id,
        cap_token_id: context.cap_token_id,
        upstream_host: context.upstream_host,
        request_headers: context.request_headers,
        response_headers: context.response_headers,
    };
    entry.emit();
}

/// Start a file watcher that reloads the config on changes.
///
/// Spawns a background thread that watches the config file for modifications.
/// On change, it re-reads, re-compiles, and hot-swaps the pipeline via
/// [`reload::load_pipeline`]. Parse or compile errors are logged but do not
/// crash the proxy - the previous valid config continues to serve traffic.
/// Reload the proxy pipeline from a YAML config file at `config_path`.
///
/// The single source of truth for reload semantics shared by:
///
/// - The notify-based file watcher (auto-reload on `sb.yml` change).
/// - The Wave 5 day-6 SIGHUP signal handler (operator-driven reload
///   via `kill -HUP $(pgrep sbproxy)`).
///
/// Reads the file, runs `compile_config` (which now also drives the
/// Wave 5 day-6 features.* migration in Item 2), constructs a fresh
/// [`CompiledPipeline`], invokes the enterprise reload hook
/// (best-effort), and atomically swaps the live pipeline. Returns
/// `Ok(())` on success; logs and returns `Err` on any step's failure
/// so the caller can decide whether to retry.
///
/// Idempotent: invoking back-to-back yields the same effect as one
/// invocation. Safe to call from any thread; the global pipeline
/// `ArcSwap` handles the publish.
pub fn reload_from_config_path(config_path: &str) -> anyhow::Result<()> {
    let yaml = std::fs::read_to_string(config_path)
        .map_err(|e| anyhow::anyhow!("failed to read config file '{config_path}': {e}"))?;
    let compiled = sbproxy_config::compile_config(&yaml)?;
    if let Some(al) = compiled.access_log.as_ref() {
        log_capture_header_warnings(al);
    }
    let mut new_pipeline = CompiledPipeline::from_config(compiled)?;

    // Invoke the enterprise reload hook (best-effort): the OSS reload
    // path must continue to swap the pipeline even if a downstream
    // hook errors, otherwise a failing enterprise extension would
    // permanently pin the operator on the old config. We spin up a
    // current-thread runtime when no ambient tokio runtime exists so
    // the file-watcher thread (plain std thread) can also call this.
    if let Some(startup) = new_pipeline.hooks.startup.clone() {
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    if let Err(e) = startup.on_reload(&mut new_pipeline).await {
                        tracing::warn!(
                            error = %e,
                            "enterprise reload hook failed; serving with prior hook state",
                        );
                    }
                });
            });
        } else {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(hook_rt) => {
                    if let Err(e) = hook_rt.block_on(startup.on_reload(&mut new_pipeline)) {
                        tracing::warn!(
                            error = %e,
                            "enterprise reload hook failed; serving with prior hook state",
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "failed to build reload-hook runtime; skipping reload hook",
                    );
                }
            }
        }
    }
    reload::load_pipeline(new_pipeline);
    tracing::info!("config reloaded successfully");
    Ok(())
}

fn start_config_watcher(config_path: String) {
    use notify::{RecursiveMode, Watcher};

    std::thread::spawn(move || {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = match notify::recommended_watcher(move |res| {
            let _ = tx.send(res);
        }) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!(error = %e, "failed to create config file watcher");
                return;
            }
        };

        if let Err(e) = watcher.watch(
            std::path::Path::new(&config_path),
            RecursiveMode::NonRecursive,
        ) {
            tracing::error!(error = %e, path = %config_path, "failed to watch config file");
            return;
        }

        tracing::info!(path = %config_path, "config file watcher started");

        for event in rx {
            match event {
                Ok(event) if event.kind.is_modify() => {
                    tracing::info!("config file changed, reloading...");
                    if let Err(e) = reload_from_config_path(&config_path) {
                        tracing::error!(error = %e, "reload failed; serving prior pipeline");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "config file watcher error");
                }
                _ => {}
            }
        }
    });
}

/// Install a SIGHUP signal handler that reloads the proxy pipeline
/// from `config_path` (Wave 5 day-6 Item 4).
///
/// SIGHUP is the canonical "rerun bootstrap" signal in traditional
/// reverse proxies (nginx, haproxy). This function spawns a tokio
/// task that listens on the OS signal and calls
/// [`reload_from_config_path`] for each delivery. Multiple SIGHUPs
/// arriving back-to-back coalesce into multiple reloads (last write
/// wins on the `ArcSwap` inside `reload::load_pipeline`).
///
/// On non-Unix targets this is a no-op (Windows et al. have no
/// SIGHUP equivalent).
#[cfg(unix)]
pub fn install_sighup_handler(config_path: String) {
    use tokio::signal::unix::{signal, SignalKind};
    if tokio::runtime::Handle::try_current().is_err() {
        tracing::warn!(
            "no tokio runtime in scope; SIGHUP handler not installed (call from inside the tokio runtime)",
        );
        return;
    }
    tokio::spawn(async move {
        let mut sig = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGHUP handler");
                return;
            }
        };
        tracing::info!("SIGHUP handler installed; send `kill -HUP <pid>` to reload");
        while sig.recv().await.is_some() {
            tracing::info!("SIGHUP received; reloading config...");
            if let Err(e) = reload_from_config_path(&config_path) {
                tracing::error!(error = %e, "SIGHUP reload failed; serving prior pipeline");
            }
        }
    });
}

/// SIGHUP handler is a no-op on non-Unix targets.
#[cfg(not(unix))]
pub fn install_sighup_handler(_config_path: String) {
    tracing::debug!("SIGHUP handler is unix-only; skipping on this target");
}

/// Create and start a Pingora server with the given config file path.
///
/// This function:
/// 1. Reads and compiles the YAML config
/// 2. Compiles it into a pipeline with module instances
/// 3. Loads it into the hot-reload store
/// 4. Starts a file watcher for config hot-reload
/// 5. Creates a Pingora server with an HTTP proxy service
/// 6. Starts the server (blocks forever)
///
/// Pingora handles SIGTERM/SIGINT for graceful shutdown internally.
/// The file watcher handles config reload on file change, which is
/// equivalent to SIGHUP-based reload in traditional servers.
pub fn run(config_path: &str) -> anyhow::Result<()> {
    use pingora_core::apps::HttpServerOptions;
    use pingora_core::server::configuration::ServerConf as PingoraServerConf;
    use pingora_core::server::Server;
    use pingora_proxy::http_proxy_service;

    // Load and compile the config.
    let yaml = std::fs::read_to_string(config_path)
        .map_err(|e| anyhow::anyhow!("failed to read config file '{}': {}", config_path, e))?;
    let compiled = sbproxy_config::compile_config(&yaml)?;
    if let Some(al) = compiled.access_log.as_ref() {
        log_capture_header_warnings(al);
    }
    let port = compiled.server.http_bind_port;

    // Extract TLS-relevant fields before compiled is consumed by from_config.
    let server_config = compiled.server.clone();
    let hostnames: Vec<String> = compiled.host_map.keys().map(|k| k.to_string()).collect();

    // Initialise the AI provider catalog from the embedded YAML, with
    // an optional override path from `proxy.ai_providers_file`: use
    // the override file when readable, fall back to the embedded
    // gzipped catalog otherwise. The init is idempotent so a config
    // hot-reload does not need to revisit it; reloads to swap the
    // catalog require a process restart.
    {
        let override_path = server_config
            .ai_providers_file
            .as_deref()
            .map(std::path::Path::new);
        if let Err(e) = sbproxy_ai::providers::init_provider_registry(override_path) {
            tracing::error!(
                error = %e,
                "failed to initialise AI provider registry; falling back to embedded defaults on first lookup"
            );
        }
    }

    // --- Wave 3 / G1.4 wire: agent-class resolver startup ---
    //
    // Build the process-wide `AgentClassResolver` from the parsed
    // top-level `agent_classes:` block (or from defaults when the block
    // is absent), then install it in the global slot the request
    // pipeline reads in `request_filter`. The catalog source toggles
    // between the embedded `builtin` defaults, an external `hosted-feed`
    // (placeholder until G2.2 lands the registry fetcher), or the two
    // `merged` (currently equivalent to defaults; the registry overlay
    // arrives in G2.2). All paths are infallible: a malformed
    // `hosted_feed` block degrades gracefully to defaults so a startup
    // misconfiguration does not block serving.
    #[cfg(feature = "agent-class")]
    {
        install_agent_class_resolver(compiled.agent_classes.as_ref());
    }

    // --- Wave 5 / G5.4: install TLS-fingerprint catalogue ---
    //
    // The catalogue lives behind an arc-swap so SIGHUP reloads can
    // refresh it without dropping in-flight detector reads. The
    // embedded JSON ships with the seed entries from A5.1; the
    // builder task (B5.x) refreshes the file via a monthly PR.
    // Failures degrade gracefully: an empty catalogue means the
    // detector never matches, which is the safe default.
    #[cfg(feature = "tls-fingerprint")]
    {
        use std::sync::Arc as TlsFingerprintArc;
        match sbproxy_security::TlsFingerprintCatalog::default_embedded() {
            Ok(catalog) => {
                // Also install the CEL matcher adapter so
                // `tls_fingerprint_matches(ja4, agent_class_id)`
                // resolves against the same catalogue.
                struct CatalogAdapter(sbproxy_security::TlsFingerprintCatalog);
                impl sbproxy_extension::cel::TlsFingerprintMatcher for CatalogAdapter {
                    fn matches(&self, ja4: &str, agent_class_id: &str) -> bool {
                        self.0.matches(ja4, agent_class_id)
                    }
                }
                let adapter: TlsFingerprintArc<dyn sbproxy_extension::cel::TlsFingerprintMatcher> =
                    TlsFingerprintArc::new(CatalogAdapter(catalog.clone()));
                sbproxy_extension::cel::set_tls_fingerprint_matcher(adapter);
                reload::set_tls_fingerprint_catalog(catalog);
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to load embedded TLS fingerprint catalogue; headless detection disabled"
                );
            }
        }
    }

    // Compile config into a pipeline with action/auth/policy module instances.
    let mut pipeline = CompiledPipeline::from_config(compiled)?;

    // Give enterprise code a chance to wire its hooks, construct clients,
    // and register origins. Failures here do NOT block serving: they log
    // and return None-hooks, so request paths fall through to OSS behavior.
    //
    // `pub fn run` is sync (called from `main` before Pingora's runtime
    // starts), so we drive the async hook on a short-lived current-thread
    // runtime. The cloned Arc avoids holding a borrow of `pipeline.hooks`
    // across the await, which would conflict with the `&mut pipeline` arg.
    if pipeline.hooks.startup.is_none() {
        pipeline.hooks.startup = crate::hook_registry::collect_startup_hook();
    }
    if let Some(startup) = pipeline.hooks.startup.clone() {
        let hook_rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build startup-hook runtime: {}", e))?;
        if let Err(e) = hook_rt.block_on(startup.on_startup(&mut pipeline)) {
            tracing::warn!(
                error = %e,
                "enterprise startup hook failed; continuing without enterprise features"
            );
        }
    }

    // Store in hot-reload slot.
    reload::load_pipeline(pipeline);

    // Start file watcher for config hot-reload.
    start_config_watcher(config_path.to_string());

    // --- Wave 5 day-6 Item 4: SIGHUP re-bootstrap handler ---
    //
    // Pingora's `Server::run_forever` owns its own tokio runtime, but
    // it neither installs a SIGHUP handler nor re-runs our bootstrap
    // on receipt. Spawn a dedicated single-threaded runtime on a
    // background std thread so an operator-driven `kill -HUP $(pgrep
    // sbproxy)` re-runs `reload_from_config_path` (which threads
    // through compile_config + the day-6 features.* migration + the
    // enterprise reload hook). Idempotent: each delivery atomically
    // swaps the live pipeline; multiple back-to-back SIGHUPs coalesce.
    {
        let cfg_path = config_path.to_string();
        std::thread::Builder::new()
            .name("sbproxy-sighup".to_string())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to build SIGHUP runtime");
                        return;
                    }
                };
                rt.block_on(async {
                    install_sighup_handler(cfg_path);
                    // Park forever; the spawned task holds the runtime
                    // alive. A future shutdown signal will tear this
                    // down alongside Pingora's main runtime.
                    std::future::pending::<()>().await;
                });
            })
            .ok();
    }

    // --- TLS setup ---
    let tls_state = if server_config.https_bind_port.is_some()
        || server_config.tls_cert_file.is_some()
        || server_config.acme.as_ref().is_some_and(|a| a.enabled)
    {
        match sbproxy_tls::TlsState::init(&server_config, hostnames) {
            Ok(state) => Some(state),
            Err(e) => {
                tracing::error!(error = %e, "failed to initialize TLS");
                return Err(e);
            }
        }
    } else {
        None
    };

    // Create Pingora server with zero grace period for instant shutdown.
    // The Go e2e runner sends SIGTERM between test cases and immediately
    // tries to bind the same port for the next case. Any grace period
    // causes the port to stay busy and the next case fails to start.
    //
    // Performance tuning (see sbproxy-bench/docs/TUNING.md):
    //   * threads: Pingora's default is 1 (single-threaded). Match Go's
    //     GOMAXPROCS behaviour by using all logical cores.
    //   * upstream_keepalive_pool_size: bump from 128 to 256 to match the
    //     Go http.Transport MaxIdleConnsPerHost we set on the Go side.
    // Offload upstream DNS + connect() onto a dedicated threadpool so worker
    // threads don't block on syscalls. Tier-2 tuning from
    // sbproxy-bench/docs/TUNING.md. Two pools is the Pingora-recommended
    // starting point for 8+ core machines.
    let conf = PingoraServerConf {
        threads: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        upstream_keepalive_pool_size: 256,
        upstream_connect_offload_threadpools: Some(2),
        grace_period_seconds: Some(0),
        graceful_shutdown_timeout_seconds: Some(0),
        ..PingoraServerConf::default()
    };
    tracing::info!(
        threads = %conf.threads,
        upstream_pool = %conf.upstream_keepalive_pool_size,
        connect_offload = ?conf.upstream_connect_offload_threadpools,
        "pingora server config"
    );
    let mut server = Server::new_with_opt_and_conf(None, conf);

    // Create the HTTP proxy service.
    let mut proxy_service = http_proxy_service(&server.configuration, SbProxy);
    proxy_service.add_tcp(&format!("0.0.0.0:{port}"));

    // --- HTTP/2 cleartext (h2c) ---
    //
    // When the operator opts in via `proxy.http2_cleartext: true`,
    // enable Pingora's `HttpServerOptions::h2c` flag so the plain TCP
    // listener peeks for the HTTP/2 connection preface and upgrades
    // matching connections to h2 transparently. Plaintext gRPC
    // clients (and any tonic Channel that has not negotiated TLS+ALPN)
    // depend on this; without it the proxy parses the h2 preface as
    // an HTTP/1.1 request line and tears the connection down with
    // `FRAME_SIZE_ERROR`. TLS+ALPN h2 on `https_bind_port` is a
    // separate path and does not need this flag.
    if server_config.http2_cleartext {
        if let Some(app) = proxy_service.app_logic_mut() {
            // `HttpServerOptions` is `#[non_exhaustive]`, so build via
            // `Default::default()` and then flip the `h2c` flag.
            let mut opts = HttpServerOptions::default();
            opts.h2c = true;
            app.server_options = Some(opts);
            tracing::info!(port = %port, "h2c enabled on plain HTTP listener");
        }
    }

    tracing::info!(port = %port, "starting sbproxy on 0.0.0.0:{}", port);

    // Add HTTPS listener if TLS configured.
    if let Some(ref tls) = tls_state {
        if let Some(https_port) = server_config.https_bind_port {
            if let (Some(cert_path), Some(key_path)) =
                (&server_config.tls_cert_file, &server_config.tls_key_file)
            {
                // Manual cert files provided.
                if let Some(mtls_cfg) = server_config.mtls.as_ref() {
                    // mTLS path: build TlsSettings, configure the
                    // rustls ClientCertVerifier wrapper that captures
                    // CN+SAN into the process-wide cert cache, then
                    // delegate chain validation to WebPkiClientVerifier.
                    let cache = crate::identity::mtls_cert_cache();
                    match build_mtls_tls_settings(cert_path, key_path, mtls_cfg, cache) {
                        Ok(settings) => {
                            proxy_service.add_tls_with_settings(
                                &format!("0.0.0.0:{https_port}"),
                                None,
                                settings,
                            );
                            tracing::info!(
                                port = %https_port,
                                require = %mtls_cfg.require,
                                "HTTPS listener added (manual certs + mTLS)"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "mTLS setup failed; falling back to non-mTLS HTTPS"
                            );
                            proxy_service
                                .add_tls(&format!("0.0.0.0:{https_port}"), cert_path, key_path)
                                .map_err(|e| {
                                    anyhow::anyhow!("failed to add TLS listener: {}", e)
                                })?;
                        }
                    }
                } else {
                    proxy_service
                        .add_tls(&format!("0.0.0.0:{https_port}"), cert_path, key_path)
                        .map_err(|e| anyhow::anyhow!("failed to add TLS listener: {}", e))?;
                    tracing::info!(port = %https_port, "HTTPS listener added (manual certs)");
                }
            } else if server_config.acme.as_ref().is_some_and(|a| a.enabled) {
                // ACME-only mode: generate a self-signed bootstrap cert so the
                // HTTPS listener can start immediately. ACME will replace it with
                // a real cert once issuance completes.
                match tls.generate_self_signed_bootstrap_cert() {
                    Ok((cert_path, key_path)) => {
                        proxy_service
                            .add_tls(&format!("0.0.0.0:{https_port}"), &cert_path, &key_path)
                            .map_err(|e| anyhow::anyhow!("failed to add TLS listener: {}", e))?;
                        tracing::info!(
                            port = %https_port,
                            "HTTPS listener added (self-signed bootstrap, ACME will replace)"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "failed to generate bootstrap cert, HTTPS listener not started"
                        );
                    }
                }
            }
        }
    }

    server.add_service(proxy_service);

    // Spawn the embedded admin HTTP server on `proxy.admin.port`
    // when `admin.enabled: true`. The admin server lives outside
    // Pingora's service tree because its routing semantics
    // (authoritative, basic-auth gated, no upstream forwarding)
    // do not fit Pingora's reverse-proxy shape. Pingora installs
    // its own tokio runtime; we hand the admin task to that
    // runtime when it starts via `tokio::spawn` below the run-loop
    // setup.
    if server_config.admin.as_ref().is_some_and(|a| a.enabled) {
        let admin_cfg = crate::admin::AdminConfig {
            enabled: true,
            port: server_config.admin.as_ref().map(|a| a.port).unwrap_or(9090),
            username: server_config
                .admin
                .as_ref()
                .map(|a| a.username.clone())
                .unwrap_or_else(|| "admin".to_string()),
            password: server_config
                .admin
                .as_ref()
                .map(|a| a.password.clone())
                .unwrap_or_else(|| "changeme".to_string()),
            max_log_entries: server_config
                .admin
                .as_ref()
                .map(|a| a.max_log_entries)
                .unwrap_or(1000),
        };
        // Pass the same on-disk config path the file watcher uses
        // so `POST /admin/reload` re-reads the same file. The two
        // reload paths share the in-process single-flight guard on
        // the AdminState so a manual reload during a watcher reload
        // serialises cleanly.
        let admin_state = std::sync::Arc::new(
            crate::admin::AdminState::new(admin_cfg).with_config_path(config_path),
        );
        // Pingora's `Server::run_forever` builds its own multi-thread
        // tokio runtime; spawning before run_forever installs the
        // task on that runtime via the global handle once Pingora
        // initialises it. We use a small bootstrap task that grabs
        // the runtime handle as soon as it is available.
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("admin runtime");
            rt.block_on(async move {
                // The admin server's listener task lives forever;
                // run it inline on this dedicated thread.
                if let Some(handle) = crate::admin::spawn_admin_server(admin_state) {
                    let _ = handle.await;
                }
            });
        });
    }

    // Register ACME challenge store and Alt-Svc header globally.
    if let Some(ref tls) = tls_state {
        reload::set_challenge_store(std::sync::Arc::clone(&tls.challenge_store));
    }
    if server_config.http3.as_ref().is_some_and(|h| h.enabled) {
        if let Some(https_port) = server_config.https_bind_port {
            reload::set_alt_svc(sbproxy_tls::alt_svc::h3_alt_svc_value(https_port));
            tracing::info!(
                "Alt-Svc header will advertise HTTP/3 on port {}",
                https_port
            );
        }
    }

    // Start ACME renewal task if enabled.
    if let Some(ref tls) = tls_state {
        tls.start_acme_renewal_task();
    }

    // Start HTTP/3 listener if enabled.
    if let Some(ref tls) = tls_state {
        if server_config.http3.as_ref().is_some_and(|h| h.enabled) {
            // Wire the real pipeline dispatch into the H3 listener.
            let dispatch_fn: sbproxy_tls::h3_listener::DispatchFn =
                std::sync::Arc::new(|method, uri, headers, body, client_ip| {
                    Box::pin(crate::dispatch::dispatch_h3_request(
                        method, uri, headers, body, client_ip,
                    ))
                });
            match tls.start_h3_listener(&server_config, dispatch_fn) {
                Ok(Some(_handle)) => {
                    tracing::info!("HTTP/3 listener started");
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "failed to start HTTP/3 listener, continuing without it");
                }
            }
        }
    }

    server.bootstrap();
    server.run_forever();
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- resolve_override parsing ---

    #[test]
    fn resolve_override_ipv4_only_uses_default_port() {
        assert_eq!(resolve_addr_override("203.0.113.7", 443), "203.0.113.7:443");
    }

    #[test]
    fn resolve_override_ipv4_with_port_pins_both() {
        assert_eq!(
            resolve_addr_override("203.0.113.7:8443", 443),
            "203.0.113.7:8443"
        );
    }

    #[test]
    fn resolve_override_ipv6_bracketed_with_port() {
        assert_eq!(
            resolve_addr_override("[2001:db8::1]:8443", 443),
            "[2001:db8::1]:8443"
        );
    }

    #[test]
    fn resolve_override_ipv6_bracketed_without_port() {
        assert_eq!(
            resolve_addr_override("[2001:db8::1]", 443),
            "[2001:db8::1]:443"
        );
    }

    #[test]
    fn resolve_override_ipv6_unbracketed_is_bracketed_at_default_port() {
        assert_eq!(
            resolve_addr_override("2001:db8::1", 443),
            "[2001:db8::1]:443"
        );
    }

    #[test]
    fn resolve_override_hostname_with_port() {
        assert_eq!(
            resolve_addr_override("internal.svc:9000", 443),
            "internal.svc:9000"
        );
    }

    #[test]
    fn resolve_override_hostname_only_uses_default_port() {
        assert_eq!(
            resolve_addr_override("internal.svc", 443),
            "internal.svc:443"
        );
    }

    // --- RFC 7239 Forwarded `for=`/`by=` IPv6 bracketing ---

    #[test]
    fn forwarded_node_ipv4_is_bare() {
        assert_eq!(forwarded_node("203.0.113.7"), "203.0.113.7");
    }

    #[test]
    fn forwarded_node_ipv6_is_quoted_and_bracketed() {
        // RFC 7239 §6: IPv6 addresses must be enclosed in square brackets
        // and the whole token quoted because the brackets are not allowed
        // in an unquoted token.
        assert_eq!(forwarded_node("2001:db8::1"), "\"[2001:db8::1]\"");
    }

    #[test]
    fn forwarded_node_ipv6_loopback() {
        assert_eq!(forwarded_node("::1"), "\"[::1]\"");
    }

    #[test]
    fn forwarded_node_ipv4_mapped_ipv6() {
        // ::ffff:192.0.2.1 contains a colon so we treat it as v6 and bracket.
        assert_eq!(forwarded_node("::ffff:192.0.2.1"), "\"[::ffff:192.0.2.1]\"");
    }

    // --- Webhook envelope shape ---

    #[test]
    fn webhook_envelope_includes_proxy_and_request() {
        let env = webhook_envelope(
            "on_request",
            "test-req-id",
            "abc123",
            serde_json::json!({"host": "api.example.com"}),
        );
        assert_eq!(env["event"], "on_request");
        assert_eq!(env["proxy"]["config_revision"], "abc123");
        assert_eq!(env["request"]["id"], "test-req-id");
        assert_eq!(env["host"], "api.example.com");
        // Identity fields must be populated, not empty.
        assert!(!env["proxy"]["instance_id"].as_str().unwrap().is_empty());
        assert!(!env["proxy"]["version"].as_str().unwrap().is_empty());
    }

    #[test]
    fn webhook_signature_is_stable_per_input() {
        let s1 = sign_webhook("secret", b"hello", 1700000000).unwrap();
        let s2 = sign_webhook("secret", b"hello", 1700000000).unwrap();
        assert_eq!(s1, s2);
        assert!(s1.starts_with("v1="));
        // Different timestamp -> different signature (replay protection).
        let s3 = sign_webhook("secret", b"hello", 1700000001).unwrap();
        assert_ne!(s1, s3);
    }

    #[test]
    fn csrf_token_is_stable_for_same_inputs() {
        let t1 = csrf_token("secret", 1_700_000_000_000_000_000u128, "example.com").unwrap();
        let t2 = csrf_token("secret", 1_700_000_000_000_000_000u128, "example.com").unwrap();
        assert_eq!(t1, t2);
        // SHA-256 hex output is 64 chars.
        assert_eq!(t1.len(), 64);
        // Different secret -> different token.
        let t3 = csrf_token("other", 1_700_000_000_000_000_000u128, "example.com").unwrap();
        assert_ne!(t1, t3);
        // Different hostname -> different token (binds to host).
        let t4 = csrf_token("secret", 1_700_000_000_000_000_000u128, "other.com").unwrap();
        assert_ne!(t1, t4);
    }

    // --- BotAuth target-uri propagation tests ---
    //
    // These tests guard the F1.6 fix where `check_auth` reconstructs
    // `@target-uri` from the live request path-and-query. Before the
    // fix, BotAuth used a hardcoded `/`, which let signatures bound to
    // a path other than `/` slip through (or, conversely, let valid
    // signatures over the real path get rejected when they covered
    // `@target-uri`).

    fn build_bot_auth_provider(key_id: &str, secret_hex: &str) -> sbproxy_modules::Auth {
        let provider = sbproxy_modules::auth::BotAuthProvider::from_config(serde_json::json!({
            "agents": [
                {
                    "name": "test-agent",
                    "key_id": key_id,
                    "algorithm": "hmac_sha256",
                    "public_key": secret_hex,
                    "required_components": ["@method", "@target-uri"],
                }
            ]
        }))
        .expect("provider builds");
        sbproxy_modules::Auth::BotAuth(provider)
    }

    fn sign_for_path(secret_hex: &str, key_id: &str, target_uri: &str) -> (String, String) {
        use base64::Engine;
        use hmac::{KeyInit, Mac};
        use sha2::Sha256;
        type HmacSha256 = hmac::Hmac<Sha256>;

        let raw_input = format!(
            "sig1=(\"@method\" \"@target-uri\");created=1700000000;keyid=\"{key_id}\";alg=\"hmac-sha256\""
        );
        let entry = sbproxy_middleware::signatures::parse_signature_input(&raw_input)
            .unwrap()
            .pop()
            .unwrap()
            .1;
        let req_for_signing = http::Request::builder()
            .method("GET")
            .uri(target_uri)
            .body(bytes::Bytes::new())
            .unwrap();
        let base =
            sbproxy_middleware::signatures::build_signature_base(&req_for_signing, &entry).unwrap();
        let key_bytes = hex::decode(secret_hex).unwrap();
        let mut mac = HmacSha256::new_from_slice(&key_bytes).unwrap();
        mac.update(base.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig);
        (raw_input, format!("sig1=:{}:", sig_b64))
    }

    #[tokio::test]
    async fn bot_auth_accepts_signature_bound_to_real_request_path() {
        // Sign for "/api/foo", then ask check_auth to verify a request
        // whose path is "/api/foo". The reconstructed @target-uri must
        // match what the signer covered.
        let secret_hex = "00112233445566778899aabbccddeeff";
        let key_id = "test-bot-key";
        let auth = build_bot_auth_provider(key_id, secret_hex);
        let (sig_input, sig_value) = sign_for_path(secret_hex, key_id, "/api/foo");

        let mut headers = http::HeaderMap::new();
        headers.insert("signature-input", sig_input.parse().unwrap());
        headers.insert("signature", sig_value.parse().unwrap());

        let result = check_auth(&auth, &headers, None, "GET", "/api/foo").await;
        assert!(
            matches!(result, AuthResult::Allow { .. }),
            "expected Allow when path matches signed @target-uri"
        );
    }

    #[tokio::test]
    async fn bot_auth_rejects_signature_bound_to_different_path() {
        // Sign for "/", but the live request path is "/api/foo". The
        // verifier must reject because @target-uri changed under it.
        // Before the fix this passed because check_auth always
        // reconstructed the URI as "/".
        let secret_hex = "00112233445566778899aabbccddeeff";
        let key_id = "test-bot-key";
        let auth = build_bot_auth_provider(key_id, secret_hex);
        let (sig_input, sig_value) = sign_for_path(secret_hex, key_id, "/");

        let mut headers = http::HeaderMap::new();
        headers.insert("signature-input", sig_input.parse().unwrap());
        headers.insert("signature", sig_value.parse().unwrap());

        let result = check_auth(&auth, &headers, None, "GET", "/api/foo").await;
        assert!(
            matches!(result, AuthResult::Deny(401, _)),
            "expected Deny(401) when @target-uri does not match signed path; got {:?}",
            match result {
                AuthResult::Allow { .. } => "Allow",
                AuthResult::Deny(s, _) => Box::leak(format!("Deny({s})").into_boxed_str()),
                AuthResult::DenyWithHeaders(s, _, _) => {
                    Box::leak(format!("DenyWithHeaders({s})").into_boxed_str())
                }
                AuthResult::DigestChallenge(_) => "DigestChallenge",
            }
        );
    }

    #[tokio::test]
    async fn bot_auth_includes_query_string_in_target_uri() {
        // Sign for "/api/foo?x=1"; verify that check_auth assembles the
        // same path-and-query when the query is passed in.
        let secret_hex = "00112233445566778899aabbccddeeff";
        let key_id = "test-bot-key";
        let auth = build_bot_auth_provider(key_id, secret_hex);
        let (sig_input, sig_value) = sign_for_path(secret_hex, key_id, "/api/foo?x=1");

        let mut headers = http::HeaderMap::new();
        headers.insert("signature-input", sig_input.parse().unwrap());
        headers.insert("signature", sig_value.parse().unwrap());

        let result = check_auth(&auth, &headers, Some("x=1"), "GET", "/api/foo").await;
        assert!(
            matches!(result, AuthResult::Allow { .. }),
            "expected Allow when path+query matches signed @target-uri"
        );
    }

    // --- Auth plugin dispatch tests ---
    //
    // These guard the OSS gap fixed in this commit: the
    // `Auth::Plugin(_)` arm of `check_auth` previously short-circuited
    // to `AuthResult::Allow`, which made every enterprise auth provider
    // (oauth jwks/introspection, biscuit, saml, ext_authz,
    // mcp_resource_server, ...) inert at request time. The arm now
    // dispatches into the boxed `AuthProvider` and translates the
    // returned `AuthDecision` into an `AuthResult`.

    use sbproxy_plugin::{AuthDecision, AuthProvider};
    use std::future::Future;
    use std::pin::Pin;

    /// Test double that records every authenticate call and returns a
    /// configured [`AuthDecision`].
    struct StubAuthProvider {
        type_name: &'static str,
        decision: AuthDecision,
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl AuthProvider for StubAuthProvider {
        fn auth_type(&self) -> &'static str {
            self.type_name
        }

        fn authenticate(
            &self,
            _req: &http::Request<bytes::Bytes>,
            _ctx: &mut dyn std::any::Any,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<AuthDecision>> + Send + '_>> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let d = self.decision.clone();
            Box::pin(async move { Ok(d) })
        }
    }

    /// Provider that always returns an error from authenticate(). Used
    /// to verify the engine treats a misbehaving plugin as a 500 deny
    /// rather than letting the request through.
    struct ErrorAuthProvider;

    impl AuthProvider for ErrorAuthProvider {
        fn auth_type(&self) -> &'static str {
            "stub-error"
        }

        fn authenticate(
            &self,
            _req: &http::Request<bytes::Bytes>,
            _ctx: &mut dyn std::any::Any,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<AuthDecision>> + Send + '_>> {
            Box::pin(async move { Err(anyhow::anyhow!("upstream auth server unreachable")) })
        }
    }

    fn auth_result_label(r: &AuthResult) -> String {
        match r {
            AuthResult::Allow { .. } => "Allow".to_string(),
            AuthResult::Deny(s, m) => format!("Deny({s}, {m:?})"),
            AuthResult::DenyWithHeaders(s, m, h) => {
                format!("DenyWithHeaders({s}, {m:?}, {} headers)", h.len())
            }
            AuthResult::DigestChallenge(_) => "DigestChallenge".to_string(),
        }
    }

    #[tokio::test]
    async fn plugin_allow_decision_maps_to_auth_result_allow() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let provider = StubAuthProvider {
            type_name: "stub-allow",
            decision: AuthDecision::allow_anonymous(),
            calls: calls.clone(),
        };
        let auth = sbproxy_modules::Auth::Plugin(Box::new(provider));
        let headers = http::HeaderMap::new();

        let result = check_auth(&auth, &headers, None, "GET", "/").await;
        assert!(
            matches!(result, AuthResult::Allow { .. }),
            "Allow decision must map to AuthResult::Allow; got {}",
            auth_result_label(&result)
        );
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "provider must be invoked exactly once"
        );
    }

    #[tokio::test]
    async fn plugin_deny_decision_maps_to_auth_result_deny() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let provider = StubAuthProvider {
            type_name: "stub-deny",
            decision: AuthDecision::Deny {
                status: 403,
                message: "policy says no".to_string(),
            },
            calls: calls.clone(),
        };
        let auth = sbproxy_modules::Auth::Plugin(Box::new(provider));
        let headers = http::HeaderMap::new();

        let result = check_auth(&auth, &headers, None, "POST", "/api/x").await;
        match result {
            AuthResult::Deny(status, msg) => {
                assert_eq!(status, 403);
                assert_eq!(msg, "policy says no");
            }
            other => panic!("expected Deny(403,...); got {}", auth_result_label(&other)),
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn plugin_deny_with_headers_propagates_custom_response_headers() {
        // Simulates the RFC 9728 path: an MCP resource server denies
        // with a 401 plus a `WWW-Authenticate: Bearer
        // resource_metadata="..."` header so clients can discover the
        // authorization server.
        let www_auth =
            "Bearer resource_metadata=\"https://example.com/.well-known/oauth-protected-resource\"";
        let provider = StubAuthProvider {
            type_name: "stub-deny-headers",
            decision: AuthDecision::DenyWithHeaders {
                status: 401,
                message: "missing token".to_string(),
                headers: vec![("WWW-Authenticate".to_string(), www_auth.to_string())],
            },
            calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        let auth = sbproxy_modules::Auth::Plugin(Box::new(provider));
        let headers = http::HeaderMap::new();

        let result = check_auth(&auth, &headers, None, "GET", "/").await;
        match result {
            AuthResult::DenyWithHeaders(status, msg, hdrs) => {
                assert_eq!(status, 401);
                assert_eq!(msg, "missing token");
                assert_eq!(hdrs.len(), 1);
                assert_eq!(hdrs[0].0, "WWW-Authenticate");
                assert_eq!(hdrs[0].1, www_auth);
            }
            other => panic!(
                "expected DenyWithHeaders; got {}",
                auth_result_label(&other)
            ),
        }
    }

    #[tokio::test]
    async fn plugin_authenticate_error_denies_with_500() {
        // A plugin that returns Err must NOT fall through to Allow;
        // the engine must surface a generic 500 deny so a flaky
        // enterprise auth provider can never silently pass requests.
        let auth = sbproxy_modules::Auth::Plugin(Box::new(ErrorAuthProvider));
        let headers = http::HeaderMap::new();

        let result = check_auth(&auth, &headers, None, "GET", "/").await;
        match result {
            AuthResult::Deny(status, msg) => {
                assert_eq!(status, 500);
                assert!(
                    msg.contains("stub-error"),
                    "expected message to mention plugin name; got {msg:?}"
                );
            }
            other => panic!("expected Deny(500,...); got {}", auth_result_label(&other)),
        }
    }

    #[tokio::test]
    async fn plugin_receives_method_path_query_and_headers() {
        // Provider that records the request handed to it so we can
        // assert the engine reconstructed the URI components.
        struct RecordingProvider {
            captured: std::sync::Mutex<Option<(String, String, http::HeaderMap)>>,
        }

        impl AuthProvider for RecordingProvider {
            fn auth_type(&self) -> &'static str {
                "recording"
            }

            fn authenticate(
                &self,
                req: &http::Request<bytes::Bytes>,
                _ctx: &mut dyn std::any::Any,
            ) -> Pin<Box<dyn Future<Output = anyhow::Result<AuthDecision>> + Send + '_>>
            {
                let method = req.method().as_str().to_string();
                let uri = req.uri().to_string();
                let hdrs = req.headers().clone();
                *self.captured.lock().unwrap() = Some((method, uri, hdrs));
                Box::pin(async move { Ok(AuthDecision::allow_anonymous()) })
            }
        }

        // Newtype shim so the recording provider can be both stored in
        // an Arc (for assertion access) and registered as a
        // `Box<dyn AuthProvider>` inside `Auth::Plugin`.
        struct RecordingProviderShim {
            inner: std::sync::Arc<RecordingProvider>,
        }

        impl AuthProvider for RecordingProviderShim {
            fn auth_type(&self) -> &'static str {
                self.inner.auth_type()
            }

            fn authenticate(
                &self,
                req: &http::Request<bytes::Bytes>,
                ctx: &mut dyn std::any::Any,
            ) -> Pin<Box<dyn Future<Output = anyhow::Result<AuthDecision>> + Send + '_>>
            {
                self.inner.authenticate(req, ctx)
            }
        }

        let provider = std::sync::Arc::new(RecordingProvider {
            captured: std::sync::Mutex::new(None),
        });
        let auth = sbproxy_modules::Auth::Plugin(Box::new(RecordingProviderShim {
            inner: provider.clone(),
        }));

        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", "Bearer test-token".parse().unwrap());
        headers.insert("x-trace-id", "abc123".parse().unwrap());

        let _ = check_auth(&auth, &headers, Some("foo=bar&baz=1"), "POST", "/api/v1/x").await;

        let guard = provider.captured.lock().unwrap();
        let (method, uri, hdrs) = guard.as_ref().expect("provider was invoked");
        assert_eq!(method, "POST");
        assert_eq!(uri, "/api/v1/x?foo=bar&baz=1");
        assert_eq!(
            hdrs.get("authorization").and_then(|v| v.to_str().ok()),
            Some("Bearer test-token")
        );
        assert_eq!(
            hdrs.get("x-trace-id").and_then(|v| v.to_str().ok()),
            Some("abc123")
        );
    }

    // --- Auth plugin registry tests ---
    //
    // Smoke-test the inventory-based registration channel that
    // `compile_auth` uses to build `Auth::Plugin(...)` from a config
    // type name. Registers a stub provider via `inventory::submit!`
    // and verifies it round-trips through `build_auth_plugin`.

    inventory::submit! {
        sbproxy_plugin::AuthPluginRegistration {
            name: "test-dispatch-plugin",
            factory: |_config| Ok(Box::new(StubAuthProvider {
                type_name: "test-dispatch-plugin",
                decision: AuthDecision::allow_anonymous(),
                calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            })),
        }
    }

    #[tokio::test]
    async fn registered_auth_plugin_is_discoverable_by_name() {
        let names = sbproxy_plugin::list_auth_plugins();
        assert!(
            names.contains(&"test-dispatch-plugin"),
            "test plugin must be visible via list_auth_plugins; got {names:?}",
        );

        let built =
            sbproxy_plugin::build_auth_plugin("test-dispatch-plugin", serde_json::Value::Null)
                .expect("plugin name resolves")
                .expect("factory succeeds");

        // Wrap in Auth::Plugin and verify dispatch works end to end.
        let auth = sbproxy_modules::Auth::Plugin(built);
        let headers = http::HeaderMap::new();
        let result = check_auth(&auth, &headers, None, "GET", "/").await;
        assert!(
            matches!(result, AuthResult::Allow { .. }),
            "registered plugin must dispatch to Allow; got {}",
            auth_result_label(&result)
        );
    }

    #[test]
    fn unknown_auth_plugin_name_is_rejected_at_compile_time() {
        // Belt-and-braces check on the OSS guarantee: an unknown
        // `type:` value never produces an `Auth::Plugin(...)` at
        // request time. compile_auth errors before the pipeline ever
        // sees it, so `Auth::Plugin(name="<not registered>")` is
        // unreachable in production. This pins that property so a
        // future refactor cannot regress it.
        let json = serde_json::json!({"type": "this-plugin-does-not-exist"});
        let err = sbproxy_modules::compile::compile_auth(&json)
            .expect_err("unknown plugin name must error at compile time");
        let msg = err.to_string();
        assert!(
            msg.contains("unknown auth type") || msg.contains("this-plugin-does-not-exist"),
            "error message must mention the unknown type; got {msg:?}",
        );
    }

    // --- SSE usage scanner tests ---
    //
    // These cover the deprecated `SseUsageScanner` shim (a thin
    // wrapper over the generic parser). The pluggable parser family
    // has its own tests under `sbproxy-ai/src/usage_parser/` and
    // `e2e/tests/ai_streaming_usage.rs`.

    #[allow(deprecated)]
    #[test]
    fn sse_scanner_captures_openai_terminal_usage() {
        let mut s = SseUsageScanner::new();
        let body = b"data: {\"id\":\"x\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n\
                     data: {\"id\":\"x\",\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":34,\"total_tokens\":46}}\n\n\
                     data: [DONE]\n\n";
        s.feed(body);
        assert_eq!(s.totals(), (12, 34));
    }

    #[allow(deprecated)]
    #[test]
    fn sse_scanner_captures_anthropic_message_delta_usage() {
        // Anthropic emits a partial usage on `message_start` and the
        // final usage on `message_delta`. The scanner must surface
        // the larger output_tokens from the second event.
        let mut s = SseUsageScanner::new();
        let body = b"event: message_start\n\
                     data: {\"type\":\"message_start\",\"usage\":{\"input_tokens\":7,\"output_tokens\":0}}\n\n\
                     event: content_block_delta\n\
                     data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\n\
                     event: message_delta\n\
                     data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":42}}\n\n";
        s.feed(body);
        assert_eq!(s.totals(), (7, 42));
    }

    #[allow(deprecated)]
    #[test]
    fn sse_scanner_handles_chunks_split_mid_line() {
        // Real upstreams flush chunks at TCP boundaries; the scanner
        // must rejoin partial JSON across `feed` calls.
        let mut s = SseUsageScanner::new();
        s.feed(b"data: {\"usage\":{\"prompt_tokens\":");
        // Mid-line: nothing recorded yet.
        assert_eq!(s.totals(), (0, 0));
        s.feed(b"5,\"completion_tokens\":9}}\n\n");
        assert_eq!(s.totals(), (5, 9));
    }

    #[allow(deprecated)]
    #[test]
    fn sse_scanner_ignores_done_and_keepalive() {
        let mut s = SseUsageScanner::new();
        s.feed(b": ping\n\ndata: [DONE]\n\ndata: not-json\n\n");
        assert_eq!(s.totals(), (0, 0));
    }

    // --- Error page content negotiation tests ---

    fn page(status: u16, ct: &str, body: &str) -> serde_json::Value {
        serde_json::json!({ "status": [status], "content_type": ct, "body": body })
    }

    #[test]
    fn accept_parse_simple() {
        let ranges = parse_accept_ranges("text/html");
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].typ, "text");
        assert_eq!(ranges[0].subtype, "html");
        assert!((ranges[0].q - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn accept_parse_with_q_and_wildcards() {
        let ranges = parse_accept_ranges("text/html;q=0.9, application/json;q=1.0, */*;q=0.1");
        assert_eq!(ranges.len(), 3);
        assert!((ranges[0].q - 0.9).abs() < f32::EPSILON);
        assert!((ranges[1].q - 1.0).abs() < f32::EPSILON);
        assert_eq!(ranges[2].typ, "*");
        assert_eq!(ranges[2].subtype, "*");
    }

    #[test]
    fn match_accept_q_respects_wildcards() {
        let ranges = parse_accept_ranges("text/*;q=0.5, application/json");
        assert!((match_accept_q(&ranges, "application/json") - 1.0).abs() < f32::EPSILON);
        assert!((match_accept_q(&ranges, "text/html") - 0.5).abs() < f32::EPSILON);
        assert_eq!(match_accept_q(&ranges, "image/png"), 0.0);
    }

    #[test]
    fn match_accept_q_ignores_charset_suffix() {
        let ranges = parse_accept_ranges("text/html");
        assert!((match_accept_q(&ranges, "text/html; charset=utf-8") - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn select_prefers_higher_q_match() {
        let html = page(404, "text/html", "<h1>nope</h1>");
        let json = page(404, "application/json", r#"{"e":"nope"}"#);
        let candidates = vec![&html, &json];

        // Browser-style Accept: HTML wins.
        let chosen = select_error_page(
            &candidates,
            "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        );
        assert_eq!(chosen.get("content_type").unwrap(), "text/html");

        // API-style Accept: JSON wins.
        let chosen = select_error_page(&candidates, "application/json");
        assert_eq!(chosen.get("content_type").unwrap(), "application/json");
    }

    #[test]
    fn select_falls_back_to_json_when_accept_is_silent() {
        // `*/*` with no preference, or no Accept header: JSON preferred.
        let html = page(404, "text/html", "<h1>nope</h1>");
        let json = page(404, "application/json", r#"{"e":"nope"}"#);
        let candidates = vec![&html, &json];

        let chosen = select_error_page(&candidates, "*/*");
        assert_eq!(chosen.get("content_type").unwrap(), "application/json");

        let chosen = select_error_page(&candidates, "");
        assert_eq!(chosen.get("content_type").unwrap(), "application/json");
    }

    #[test]
    fn select_falls_back_to_html_when_no_json() {
        // No JSON entry; HTML preferred when Accept doesn't match anything.
        let html = page(404, "text/html", "<h1>nope</h1>");
        let plain = page(404, "text/plain", "nope");
        let candidates = vec![&plain, &html];

        let chosen = select_error_page(&candidates, "image/png");
        assert_eq!(chosen.get("content_type").unwrap(), "text/html");
    }

    #[test]
    fn page_matches_status_both_shapes() {
        let single = serde_json::json!({"status": 404});
        let list = serde_json::json!({"status": [401, 403, 404]});
        let none = serde_json::json!({"status": [500]});
        assert!(page_matches_status(&single, 404));
        assert!(page_matches_status(&list, 403));
        assert!(!page_matches_status(&none, 404));
    }

    // --- Session cookie format tests ---

    #[test]
    fn session_cookie_default_config() {
        let config = sbproxy_config::SessionConfig {
            cookie_name: Some("sbproxy_sid".to_string()),
            max_age: Some(3600),
            http_only: false,
            secure: false,
            same_site: Some("Lax".to_string()),
            allow_non_ssl: true,
        };
        let cookie = build_session_cookie(&config, "test-uuid-123");
        assert!(cookie.starts_with("sbproxy_sid=test-uuid-123"));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Max-Age=3600"));
        assert!(cookie.contains("SameSite=Lax"));
        // allow_non_ssl=true and http_only=false, so no HttpOnly
        assert!(!cookie.contains("HttpOnly"));
        assert!(!cookie.contains("Secure"));
    }

    #[test]
    fn session_cookie_httponly_when_not_allow_non_ssl() {
        let config = sbproxy_config::SessionConfig {
            cookie_name: Some("sid".to_string()),
            max_age: Some(7200),
            http_only: false,
            secure: false,
            same_site: None,
            allow_non_ssl: false,
        };
        let cookie = build_session_cookie(&config, "abc");
        assert!(cookie.starts_with("sid=abc"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax")); // default
    }

    #[test]
    fn session_cookie_secure_flag() {
        let config = sbproxy_config::SessionConfig {
            cookie_name: None,
            max_age: None,
            http_only: true,
            secure: true,
            same_site: Some("Strict".to_string()),
            allow_non_ssl: false,
        };
        let cookie = build_session_cookie(&config, "xyz");
        assert!(cookie.starts_with("sbproxy_sid=xyz")); // default name
        assert!(cookie.contains("Max-Age=3600")); // default max_age
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
    }

    #[test]
    fn session_cookie_uuid_format() {
        let sid = uuid::Uuid::new_v4().to_string();
        // UUID v4 format: 8-4-4-4-12 hex chars
        assert_eq!(sid.len(), 36);
        assert_eq!(sid.chars().filter(|c| *c == '-').count(), 4);
    }

    // --- Callback URL parsing tests ---

    #[test]
    fn callback_url_extraction_from_go_format() {
        let configs = vec![
            serde_json::json!({
                "url": "http://127.0.0.1:18888/callback/on-request",
                "method": "POST",
                "timeout": 5,
                "on_error": "ignore"
            }),
            serde_json::json!({
                "url": "http://127.0.0.1:18888/callback/on-response",
                "method": "POST",
                "timeout": 5,
                "async": true,
                "on_error": "ignore"
            }),
        ];
        for cfg in &configs {
            let url = cfg.get("url").and_then(|v| v.as_str());
            assert!(url.is_some());
            assert!(url.unwrap().starts_with("http://"));
        }
    }

    #[test]
    fn callback_method_defaults_to_post() {
        let cfg = serde_json::json!({
            "url": "http://example.com/callback"
        });
        let method = cfg.get("method").and_then(|v| v.as_str()).unwrap_or("POST");
        assert_eq!(method, "POST");
    }

    // --- Prompt extraction tests ---

    #[test]
    fn extract_prompt_text_openai_chat() {
        let body = serde_json::json!({
            "messages": [
                {"role": "system", "content": "be helpful"},
                {"role": "user", "content": "hello world"},
            ]
        });
        let out = extract_prompt_text(&body);
        assert!(out.contains("hello world"));
        assert!(out.contains("be helpful"));
    }

    #[test]
    fn extract_prompt_text_multimodal_parts() {
        let body = serde_json::json!({
            "messages": [
                {"role": "user", "content": [
                    {"type": "text", "text": "describe this"},
                    {"type": "image_url", "image_url": {"url": "..."}},
                    {"type": "text", "text": "please"},
                ]},
            ]
        });
        let out = extract_prompt_text(&body);
        assert!(out.contains("describe this"));
        assert!(out.contains("please"));
    }

    #[test]
    fn extract_prompt_text_legacy_prompt_field() {
        let body = serde_json::json!({ "prompt": "once upon a time" });
        assert_eq!(extract_prompt_text(&body), "once upon a time");
    }

    #[test]
    fn extract_prompt_text_anthropic_system_string() {
        let body = serde_json::json!({
            "system": "you are an expert",
            "messages": [{"role": "user", "content": "hi"}]
        });
        let out = extract_prompt_text(&body);
        assert!(out.contains("you are an expert"), "{out}");
        assert!(out.contains("hi"), "{out}");
    }

    #[test]
    fn extract_prompt_text_anthropic_system_block_array() {
        let body = serde_json::json!({
            "system": [
                {"type": "text", "text": "follow the rules"},
                {"type": "text", "text": "stay terse"}
            ],
            "messages": []
        });
        let out = extract_prompt_text(&body);
        assert!(out.contains("follow the rules"), "{out}");
        assert!(out.contains("stay terse"), "{out}");
    }

    #[test]
    fn extract_prompt_text_image_block_emits_placeholder() {
        let body = serde_json::json!({
            "messages": [{"role": "user", "content": [
                {"type": "image_url", "image_url": {"url": "data:..."}},
                {"type": "text", "text": "what is this"}
            ]}]
        });
        let out = extract_prompt_text(&body);
        assert!(out.contains("[image]"), "{out}");
        assert!(out.contains("what is this"), "{out}");
    }

    #[test]
    fn extract_prompt_text_anthropic_tool_use_serialises_input() {
        let body = serde_json::json!({
            "messages": [{"role": "assistant", "content": [
                {"type": "tool_use", "name": "search", "input": {"q": "rust async"}}
            ]}]
        });
        let out = extract_prompt_text(&body);
        // The tool's input JSON should be present so classifiers see it.
        assert!(out.contains("rust async"), "{out}");
    }

    #[test]
    fn extract_prompt_text_anthropic_tool_result_extracts_content() {
        let body = serde_json::json!({
            "messages": [{"role": "user", "content": [
                {"type": "tool_result", "content": "search returned 3 hits"}
            ]}]
        });
        let out = extract_prompt_text(&body);
        assert!(out.contains("search returned 3 hits"), "{out}");
    }

    #[test]
    fn extract_prompt_text_openai_tool_calls_arguments() {
        let body = serde_json::json!({
            "messages": [{
                "role": "assistant",
                "tool_calls": [{
                    "id": "1",
                    "type": "function",
                    "function": {"name": "lookup", "arguments": "{\"sku\":\"A123\"}"}
                }]
            }]
        });
        let out = extract_prompt_text(&body);
        assert!(out.contains("A123"), "tool_call args missing: {out}");
    }

    #[test]
    fn extract_prompt_text_responses_api_input_string() {
        let body = serde_json::json!({ "input": "responses api prompt" });
        assert_eq!(extract_prompt_text(&body), "responses api prompt");
    }

    #[test]
    fn extract_prompt_text_responses_api_input_array() {
        let body = serde_json::json!({
            "input": [
                {"type": "text", "text": "first"},
                {"type": "text", "text": "second"}
            ]
        });
        let out = extract_prompt_text(&body);
        assert!(out.contains("first") && out.contains("second"), "{out}");
    }

    #[test]
    fn extract_prompt_text_empty_body_returns_empty() {
        let body = serde_json::json!({});
        assert_eq!(extract_prompt_text(&body), "");
    }

    // --- Access log emission tests ---
    //
    // These exercise `emit_access_log_entry` (the pure builder + sampler)
    // under a minimal `tracing::Subscriber` that captures lines targeted
    // at `access_log`. Avoids a Pingora `Session` and avoids the full
    // `tracing-subscriber` dependency surface, so the test stays a unit
    // test and ships nothing new through the dependency tree.

    use std::sync::{Arc, Mutex};

    /// Captures `access_log`-targeted events into a shared vec. Implements
    /// `tracing::Subscriber` directly so this stays in `[dev-dependencies]`
    /// without the `tracing-subscriber` crate.
    struct CapturingSubscriber {
        lines: Arc<Mutex<Vec<String>>>,
    }

    impl CapturingSubscriber {
        fn new() -> (Self, Arc<Mutex<Vec<String>>>) {
            let lines = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    lines: lines.clone(),
                },
                lines,
            )
        }
    }

    impl tracing::Subscriber for CapturingSubscriber {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            metadata.target() == "access_log"
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if event.metadata().target() != "access_log" {
                return;
            }
            struct Visitor<'a>(&'a mut Option<String>);
            impl tracing::field::Visit for Visitor<'_> {
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    if field.name() == "message" {
                        *self.0 = Some(value.to_string());
                    }
                }
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        *self.0 = Some(format!("{value:?}"));
                    }
                }
            }
            let mut msg: Option<String> = None;
            event.record(&mut Visitor(&mut msg));
            if let Some(m) = msg {
                // The redactor wraps unknown payload in quotes via Debug; strip
                // a single surrounding pair if present so callers see the raw
                // JSON line they expect.
                let trimmed = if m.starts_with('"') && m.ends_with('"') {
                    m[1..m.len() - 1].replace("\\\"", "\"")
                } else {
                    m
                };
                self.lines.lock().unwrap().push(trimmed);
            }
        }
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    fn make_cfg(sample_rate: f64) -> sbproxy_config::AccessLogConfig {
        sbproxy_config::AccessLogConfig {
            enabled: true,
            sample_rate,
            status_codes: vec![],
            methods: vec![],
            capture_headers: sbproxy_config::CaptureHeadersConfig::default(),
        }
    }

    /// Drive the emit path under a captured subscriber and return the
    /// recorded lines. Helper keeps each test focused on its assertion.
    fn run_with_capture<F: FnOnce()>(f: F) -> Vec<String> {
        let (sub, lines) = CapturingSubscriber::new();
        tracing::subscriber::with_default(sub, f);
        let v = lines.lock().unwrap().clone();
        v
    }

    #[test]
    fn access_log_emits_json_line_when_enabled() {
        let cfg = make_cfg(1.0);
        let lines = run_with_capture(|| {
            emit_access_log_entry(
                &cfg,
                200,
                "GET",
                "api.example.com",
                "/health",
                0.012,
                "req-001".to_string(),
                "10.0.0.1".to_string(),
                None,
                AccessLogContext::empty(),
            );
        });
        assert_eq!(lines.len(), 1, "expected one line, got: {lines:?}");
        let parsed: serde_json::Value = serde_json::from_str(&lines[0])
            .unwrap_or_else(|e| panic!("emitted line not JSON: {e}: {}", lines[0]));
        assert_eq!(parsed["request_id"], "req-001");
        assert_eq!(parsed["origin"], "api.example.com");
        assert_eq!(parsed["method"], "GET");
        assert_eq!(parsed["path"], "/health");
        assert_eq!(parsed["status"], 200);
        assert_eq!(parsed["client_ip"], "10.0.0.1");
        assert!((parsed["latency_ms"].as_f64().unwrap() - 12.0).abs() < 1e-6);
    }

    #[test]
    fn access_log_skips_when_disabled() {
        let cfg = sbproxy_config::AccessLogConfig {
            enabled: false,
            sample_rate: 1.0,
            status_codes: vec![],
            methods: vec![],
            capture_headers: sbproxy_config::CaptureHeadersConfig::default(),
        };
        let lines = run_with_capture(|| {
            emit_access_log_entry(
                &cfg,
                200,
                "GET",
                "api.example.com",
                "/",
                0.001,
                "req".to_string(),
                "1.1.1.1".to_string(),
                None,
                AccessLogContext::empty(),
            );
        });
        assert!(lines.is_empty(), "no line should be emitted when disabled");
    }

    #[test]
    fn access_log_status_filter_drops_unmatched() {
        let cfg = sbproxy_config::AccessLogConfig {
            enabled: true,
            sample_rate: 1.0,
            status_codes: vec![500],
            methods: vec![],
            capture_headers: sbproxy_config::CaptureHeadersConfig::default(),
        };
        let lines = run_with_capture(|| {
            emit_access_log_entry(
                &cfg,
                200,
                "GET",
                "api.example.com",
                "/",
                0.001,
                "r1".to_string(),
                "1.1.1.1".to_string(),
                None,
                AccessLogContext::empty(),
            );
            emit_access_log_entry(
                &cfg,
                500,
                "GET",
                "api.example.com",
                "/",
                0.001,
                "r2".to_string(),
                "1.1.1.1".to_string(),
                None,
                AccessLogContext::empty(),
            );
        });
        assert_eq!(lines.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(parsed["request_id"], "r2");
    }

    #[test]
    fn access_log_method_filter_drops_unmatched() {
        let cfg = sbproxy_config::AccessLogConfig {
            enabled: true,
            sample_rate: 1.0,
            status_codes: vec![],
            methods: vec!["POST".to_string()],
            capture_headers: sbproxy_config::CaptureHeadersConfig::default(),
        };
        let lines = run_with_capture(|| {
            emit_access_log_entry(
                &cfg,
                200,
                "GET",
                "api.example.com",
                "/",
                0.001,
                "r1".to_string(),
                "1.1.1.1".to_string(),
                None,
                AccessLogContext::empty(),
            );
            emit_access_log_entry(
                &cfg,
                201,
                "post",
                "api.example.com",
                "/",
                0.001,
                "r2".to_string(),
                "1.1.1.1".to_string(),
                None,
                AccessLogContext::empty(),
            );
        });
        assert_eq!(lines.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(parsed["request_id"], "r2");
    }

    #[test]
    fn access_log_sampling_emits_roughly_target_fraction() {
        // Drive 1000 calls at sample_rate=0.9. Expected ~900 lines; allow a
        // healthy margin so this stays stable across rand seeds.
        let cfg = make_cfg(0.9);
        let lines = run_with_capture(|| {
            for i in 0..1000 {
                emit_access_log_entry(
                    &cfg,
                    200,
                    "GET",
                    "api.example.com",
                    "/",
                    0.001,
                    format!("r{i}"),
                    "1.1.1.1".to_string(),
                    None,
                    AccessLogContext::empty(),
                );
            }
        });
        let n = lines.len();
        assert!(
            (820..=970).contains(&n),
            "expected ~900 lines at sample_rate=0.9, got {n}"
        );
    }

    #[test]
    fn access_log_zero_sample_rate_drops_all() {
        let cfg = make_cfg(0.0);
        let lines = run_with_capture(|| {
            for i in 0..50 {
                emit_access_log_entry(
                    &cfg,
                    200,
                    "GET",
                    "api.example.com",
                    "/",
                    0.001,
                    format!("r{i}"),
                    "1.1.1.1".to_string(),
                    None,
                    AccessLogContext::empty(),
                );
            }
        });
        assert!(lines.is_empty(), "sample_rate=0.0 should drop everything");
    }

    #[test]
    fn access_log_propagates_trace_id_when_present() {
        let cfg = make_cfg(1.0);
        let lines = run_with_capture(|| {
            emit_access_log_entry(
                &cfg,
                200,
                "GET",
                "api.example.com",
                "/",
                0.001,
                "req".to_string(),
                "1.1.1.1".to_string(),
                Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
                AccessLogContext::empty(),
            );
        });
        assert_eq!(lines.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(parsed["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736");
    }

    // --- Wave 4 day-5: stamp_content_negotiation ---

    #[test]
    fn stamp_content_negotiation_with_markdown_accept_picks_markdown() {
        // auto_content_negotiate set, agent prefers markdown.
        let cfg = serde_json::json!({"type": "content_negotiate"});
        let mut ctx = RequestContext::new();
        stamp_content_negotiation(&mut ctx, Some(&cfg), Some("text/markdown"));
        assert_eq!(
            ctx.content_shape_transform,
            Some(sbproxy_modules::ContentShape::Markdown)
        );
        assert_eq!(
            ctx.content_shape_pricing,
            Some(sbproxy_modules::ContentShape::Markdown)
        );
    }

    #[test]
    fn stamp_content_negotiation_wildcard_accept_uses_default_shape() {
        // Default shape is Json; wildcard Accept falls back to it.
        let cfg = serde_json::json!({
            "type": "content_negotiate",
            "default_content_shape": "json"
        });
        let mut ctx = RequestContext::new();
        stamp_content_negotiation(&mut ctx, Some(&cfg), Some("*/*"));
        assert_eq!(
            ctx.content_shape_transform,
            Some(sbproxy_modules::ContentShape::Json)
        );
    }

    #[test]
    fn stamp_content_negotiation_legacy_origin_leaves_ctx_alone() {
        // No auto_content_negotiate => no-op; ctx fields stay None.
        let mut ctx = RequestContext::new();
        stamp_content_negotiation(&mut ctx, None, Some("text/markdown"));
        assert!(ctx.content_shape_pricing.is_none());
        assert!(ctx.content_shape_transform.is_none());
    }

    // --- Wave 4 day-5: apply_transform_with_ctx (Item 2 gating) ---

    fn compiled_html_to_markdown() -> sbproxy_modules::CompiledTransform {
        let inner =
            sbproxy_modules::transform::HtmlToMarkdownTransform::from_config(serde_json::json!({}))
                .expect("default html_to_markdown");
        sbproxy_modules::CompiledTransform {
            transform: sbproxy_modules::Transform::HtmlToMarkdown(inner),
            content_types: vec![],
            fail_on_error: false,
            max_body_size: 10 * 1024 * 1024,
        }
    }

    fn compiled_boilerplate() -> sbproxy_modules::CompiledTransform {
        sbproxy_modules::CompiledTransform {
            transform: sbproxy_modules::Transform::Boilerplate(
                sbproxy_modules::BoilerplateTransform::default(),
            ),
            content_types: vec![],
            fail_on_error: false,
            max_body_size: 10 * 1024 * 1024,
        }
    }

    #[test]
    fn apply_transform_html_pass_through_when_shape_is_html() {
        // Agent asked for text/html on an ai_crawl_control origin.
        // The Markdown projection must NOT run; body stays as raw HTML.
        let html = b"<html><body><h1>Hi</h1><p>Body</p></body></html>";
        let mut buf = bytes::BytesMut::from(&html[..]);
        let mut ctx = RequestContext::new();
        ctx.content_shape_transform = Some(sbproxy_modules::ContentShape::Html);

        let compiled = compiled_html_to_markdown();
        apply_transform_with_ctx(&compiled, &mut buf, Some("text/html"), &mut ctx).unwrap();

        // Body unchanged.
        assert_eq!(&buf[..], html);
        // Projection NOT stamped.
        assert!(ctx.markdown_projection.is_none());
        assert!(ctx.markdown_token_estimate.is_none());
    }

    #[test]
    fn apply_transform_html_to_markdown_runs_when_shape_is_markdown() {
        let html = b"<html><body><h1>Hi</h1><p>Body</p></body></html>";
        let mut buf = bytes::BytesMut::from(&html[..]);
        let mut ctx = RequestContext::new();
        ctx.content_shape_transform = Some(sbproxy_modules::ContentShape::Markdown);

        let compiled = compiled_html_to_markdown();
        apply_transform_with_ctx(&compiled, &mut buf, Some("text/html"), &mut ctx).unwrap();

        // Projection stamped.
        assert!(ctx.markdown_projection.is_some());
        assert!(ctx.markdown_token_estimate.is_some());
        // Body is now Markdown (no HTML tags).
        let body_str = std::str::from_utf8(&buf).unwrap();
        assert!(!body_str.contains("<html>"));
        assert!(body_str.contains("Body"));
    }

    #[test]
    fn apply_transform_legacy_origin_runs_html_to_markdown() {
        // Legacy origin: shape == None. Operator may have explicitly
        // wired `html_to_markdown` so we still run it.
        let html = b"<p>Hello</p>";
        let mut buf = bytes::BytesMut::from(&html[..]);
        let mut ctx = RequestContext::new();
        // ctx.content_shape_transform stays None.

        let compiled = compiled_html_to_markdown();
        apply_transform_with_ctx(&compiled, &mut buf, Some("text/html"), &mut ctx).unwrap();

        assert!(ctx.markdown_projection.is_some());
    }

    #[test]
    fn apply_transform_boilerplate_stamps_stripped_bytes() {
        // Boilerplate stripping reports the byte count it removed.
        let html = br#"<html><body><nav>nav stuff</nav><main>real content</main></body></html>"#;
        let mut buf = bytes::BytesMut::from(&html[..]);
        let mut ctx = RequestContext::new();

        let compiled = compiled_boilerplate();
        apply_transform_with_ctx(&compiled, &mut buf, Some("text/html"), &mut ctx).unwrap();

        // The boilerplate transform removes nav/footer/aside chrome.
        assert!(
            ctx.metrics.stripped_bytes > 0,
            "boilerplate.apply should report stripped bytes onto ctx.metrics"
        );
    }

    // --- Wave 4 day-5 Item 3: JsonEnvelope typed dispatch ---

    fn compiled_json_envelope() -> sbproxy_modules::CompiledTransform {
        sbproxy_modules::CompiledTransform {
            transform: sbproxy_modules::Transform::JsonEnvelope(
                sbproxy_modules::JsonEnvelopeTransform::default(),
            ),
            content_types: vec![],
            fail_on_error: false,
            max_body_size: 10 * 1024 * 1024,
        }
    }

    #[test]
    fn apply_transform_json_envelope_writes_v1_envelope() {
        // Shape=Json + projection set => transform writes envelope.
        let mut buf = bytes::BytesMut::from(&b"<p>upstream html</p>"[..]);
        let mut ctx = RequestContext::new();
        ctx.content_shape_transform = Some(sbproxy_modules::ContentShape::Json);
        ctx.markdown_projection = Some(sbproxy_modules::MarkdownProjection {
            body: "# Hi\n\nBody.".to_string(),
            title: Some("Hi".to_string()),
            token_estimate: 5,
        });
        ctx.canonical_url = Some("https://example.com/foo".to_string());
        ctx.citation_required = Some(true);

        let compiled = compiled_json_envelope();
        apply_transform_with_ctx(&compiled, &mut buf, Some("text/html"), &mut ctx).unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(parsed["schema_version"], "1");
        assert_eq!(parsed["title"], "Hi");
        assert_eq!(parsed["url"], "https://example.com/foo");
        assert_eq!(parsed["citation_required"], true);
    }

    #[test]
    fn apply_transform_json_envelope_falls_through_when_projection_missing() {
        // Shape=Json but no projection => transform falls through;
        // body unchanged.
        let original = b"<p>upstream</p>";
        let mut buf = bytes::BytesMut::from(&original[..]);
        let mut ctx = RequestContext::new();
        ctx.content_shape_transform = Some(sbproxy_modules::ContentShape::Json);
        // ctx.markdown_projection stays None.

        let compiled = compiled_json_envelope();
        apply_transform_with_ctx(&compiled, &mut buf, Some("text/html"), &mut ctx).unwrap();

        assert_eq!(&buf[..], original);
    }

    // --- Wave 4 day-5 Item 4: CitationBlock typed dispatch ---

    fn compiled_citation_block() -> sbproxy_modules::CompiledTransform {
        sbproxy_modules::CompiledTransform {
            transform: sbproxy_modules::Transform::CitationBlock(
                sbproxy_modules::CitationBlockTransform::default(),
            ),
            content_types: vec![],
            fail_on_error: false,
            max_body_size: 10 * 1024 * 1024,
        }
    }

    #[test]
    fn apply_transform_citation_block_prepends_when_required() {
        let original = b"# Title\n\nBody.";
        let mut buf = bytes::BytesMut::from(&original[..]);
        let mut ctx = RequestContext::new();
        ctx.content_shape_transform = Some(sbproxy_modules::ContentShape::Markdown);
        ctx.canonical_url = Some("https://example.com/x".to_string());
        ctx.citation_required = Some(true);

        let compiled = compiled_citation_block();
        apply_transform_with_ctx(&compiled, &mut buf, Some("text/markdown"), &mut ctx).unwrap();

        let s = std::str::from_utf8(&buf).unwrap();
        assert!(
            s.starts_with("> Citation required for AI training and inference."),
            "expected citation prefix; got: {s}"
        );
        assert!(s.contains("# Title"));
    }

    #[test]
    fn apply_transform_citation_block_skipped_when_not_required() {
        let original = b"# Title\n\nBody.";
        let mut buf = bytes::BytesMut::from(&original[..]);
        let mut ctx = RequestContext::new();
        ctx.content_shape_transform = Some(sbproxy_modules::ContentShape::Markdown);
        ctx.citation_required = Some(false);

        let compiled = compiled_citation_block();
        apply_transform_with_ctx(&compiled, &mut buf, Some("text/markdown"), &mut ctx).unwrap();

        // Body unchanged.
        assert_eq!(&buf[..], original);
    }

    // --- Wave 4 day-5 Item 5: x-markdown-tokens header ---

    #[test]
    fn x_markdown_tokens_uses_cached_estimate_when_available() {
        let n = x_markdown_tokens_header_value(
            Some(sbproxy_modules::ContentShape::Markdown),
            Some(42),
            Some(800),
        );
        // Cached estimate wins over the body-len fallback.
        assert_eq!(n, Some(42));
    }

    #[test]
    fn x_markdown_tokens_uses_body_len_fallback_when_no_estimate() {
        // 400 bytes * 0.25 ratio = 100 tokens.
        let n = x_markdown_tokens_header_value(
            Some(sbproxy_modules::ContentShape::Markdown),
            None,
            Some(400),
        );
        assert_eq!(n, Some(100));
    }

    #[test]
    fn x_markdown_tokens_skipped_for_html_shape() {
        let n = x_markdown_tokens_header_value(
            Some(sbproxy_modules::ContentShape::Html),
            Some(42),
            Some(800),
        );
        assert_eq!(n, None);
    }

    #[test]
    fn x_markdown_tokens_skipped_for_legacy_origin() {
        // Shape == None => legacy origin, no header.
        let n = x_markdown_tokens_header_value(None, Some(42), Some(800));
        assert_eq!(n, None);
    }

    // --- Content-Signal decision matrix (Wave 4 / G4.5) ---

    #[test]
    fn content_signal_ai_train_stamps_when_origin_sets_value() {
        let decision = resolve_content_signal_decision(true, Some("ai-train"), None);
        assert_eq!(decision, ContentSignalDecision::Stamp("ai-train".into()));
    }

    #[test]
    fn content_signal_absent_origin_no_projection_skips() {
        // Legacy origin with neither the validated field nor the
        // projection cache enrolment: no header stamped.
        let decision = resolve_content_signal_decision(true, None, None);
        assert_eq!(decision, ContentSignalDecision::Skip);
    }

    #[test]
    fn content_signal_skipped_for_non_2xx_responses() {
        // 402/406/etc. negotiation failures must not advertise the
        // signal because the body the agent sees may not be the
        // licensed content.
        let decision = resolve_content_signal_decision(false, Some("ai-train"), None);
        assert_eq!(decision, ContentSignalDecision::Skip);
    }

    #[test]
    fn content_signal_falls_back_to_tdm_reservation_when_projection_enrolled_no_signal() {
        // Origin is enrolled (has ai_crawl_control) but asserts no
        // signal: TDM-Reservation: 1 fallback per A4.1 § "tdmrep.json".
        let decision = resolve_content_signal_decision(true, None, Some(None));
        assert_eq!(decision, ContentSignalDecision::TdmReservationFallback);
    }

    #[test]
    fn content_signal_legacy_extensions_path_still_stamps() {
        // Older configs set content_signal via the projection cache
        // (extensions["content_signal"]). The fallback path resolves
        // the value when CompiledOrigin.content_signal is None.
        let decision = resolve_content_signal_decision(true, None, Some(Some("search")));
        assert_eq!(decision, ContentSignalDecision::Stamp("search".into()));
    }

    // --- G4.5..G4.8 follow-up: projection routes ---

    #[test]
    fn projection_kind_recognises_all_four_well_known_paths() {
        assert_eq!(projection_kind_for_path("/robots.txt"), Some("robots"));
        assert_eq!(projection_kind_for_path("/llms.txt"), Some("llms"));
        assert_eq!(
            projection_kind_for_path("/llms-full.txt"),
            Some("llms-full")
        );
        assert_eq!(projection_kind_for_path("/licenses.xml"), Some("licenses"));
        assert_eq!(
            projection_kind_for_path("/.well-known/tdmrep.json"),
            Some("tdmrep"),
        );
    }

    #[test]
    fn projection_kind_returns_none_for_unrelated_paths() {
        assert_eq!(projection_kind_for_path("/"), None);
        assert_eq!(projection_kind_for_path("/articles/foo"), None);
        // Trailing slash, query, or capitalisation are not the
        // canonical paths and must not match.
        assert_eq!(projection_kind_for_path("/robots.txt/"), None);
        assert_eq!(projection_kind_for_path("/Robots.txt"), None);
    }

    #[test]
    fn projection_content_type_matches_each_kind() {
        // Robots / llms: text/plain per IETF draft-koster-rep-ai +
        // Anthropic / Mistral convention.
        assert_eq!(
            projection_content_type("robots"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(projection_content_type("llms"), "text/plain; charset=utf-8");
        assert_eq!(
            projection_content_type("llms-full"),
            "text/plain; charset=utf-8"
        );
        // Licenses: application/xml per RSL 1.0.
        assert_eq!(projection_content_type("licenses"), "application/xml");
        // Tdmrep: application/json per W3C TDMRep.
        assert_eq!(projection_content_type("tdmrep"), "application/json");
    }

    #[test]
    fn projection_content_type_unknown_kind_falls_back_to_text_plain() {
        // Defensive default: unrecognised kinds (only possible from a
        // future code path that adds a new kind without a Content-Type
        // mapping) get a safe text/plain fallback.
        assert_eq!(projection_content_type("future-kind"), "text/plain");
    }

    // --- A4.2 follow-up: token_bytes_ratio override threading ---

    #[test]
    fn x_markdown_tokens_uses_per_origin_ratio_when_overriden() {
        // Cached estimate absent -> fallback uses the per-origin
        // ratio. Doubled ratio (0.5) over a 1000-byte body should
        // produce 500 tokens; default 0.25 produces 250.
        let with_override = x_markdown_tokens_header_value_with_ratio(
            Some(sbproxy_modules::ContentShape::Markdown),
            None,
            Some(1000),
            Some(0.5),
        );
        assert_eq!(with_override, Some(500));

        let without_override = x_markdown_tokens_header_value_with_ratio(
            Some(sbproxy_modules::ContentShape::Markdown),
            None,
            Some(1000),
            None,
        );
        assert_eq!(without_override, Some(250));
    }

    // --- Wave 5 day-4 plugin-trait wiring tests ---
    //
    // Pin the per-call-site contract for the IdentityResolverHook,
    // MlClassifierHook, and AnomalyDetectorHook trait wires. These do
    // not exercise the request_filter end-to-end (that lives in the
    // e2e suite); they pin the small mapping helpers and the registry
    // iteration semantics so a future refactor of the call site cannot
    // silently regress the contract.

    #[cfg(feature = "agent-class")]
    #[test]
    fn agent_id_source_label_round_trips_for_kya() {
        // Compile-time guard: the label string the IdentityResolverHook
        // emits must round-trip back to the closed
        // `sbproxy_classifiers::AgentIdSource::Kya` variant. The wire
        // does this mapping inline; this test pins the canonical
        // string.
        let src = sbproxy_classifiers::AgentIdSource::Kya;
        assert_eq!(src.as_str(), "kya");
    }

    #[cfg(feature = "agent-class")]
    #[test]
    fn agent_id_source_label_round_trips_for_ml_override() {
        let src = sbproxy_classifiers::AgentIdSource::MlOverride;
        assert_eq!(src.as_str(), "ml_override");
    }

    #[tokio::test]
    async fn identity_hook_registry_iterates_registered_hooks() {
        use std::collections::HashMap;
        use std::future::Future;
        use std::pin::Pin;
        use std::sync::Arc;
        use std::sync::Mutex;

        struct CountingHook {
            calls: Arc<Mutex<u32>>,
        }
        impl sbproxy_plugin::IdentityResolverHook for CountingHook {
            fn resolve<'a>(
                &'a self,
                _req: &'a sbproxy_plugin::IdentityRequest<'a>,
            ) -> Pin<Box<dyn Future<Output = Option<sbproxy_plugin::IdentityVerdict>> + Send + 'a>>
            {
                *self.calls.lock().unwrap() += 1;
                Box::pin(async move { None })
            }
        }

        let calls = Arc::new(Mutex::new(0_u32));
        sbproxy_plugin::register_identity_hook(Arc::new(CountingHook {
            calls: calls.clone(),
        }));

        // Drive the iteration through the same registry the wire uses.
        struct EmptyHeaders;
        impl sbproxy_plugin::IdentityHeaderLookup for EmptyHeaders {
            fn get(&self, _name: &str) -> Option<&str> {
                None
            }
        }
        let headers = EmptyHeaders;
        let req = sbproxy_plugin::IdentityRequest {
            headers: &headers,
            hostname: "test.example.com",
            prior_agent_id: None,
        };
        let hooks = sbproxy_plugin::identity_hooks();
        for hook in hooks.iter() {
            let _ = hook.resolve(&req).await;
        }
        // Our hook ran at least once.
        assert!(*calls.lock().unwrap() >= 1);
        // Suppress unused import warning.
        let _ = HashMap::<&str, &str>::new();
    }

    #[cfg(feature = "agent-classifier")]
    #[tokio::test]
    async fn ml_classifier_hook_registry_iterates_registered_hooks() {
        use std::future::Future;
        use std::pin::Pin;
        use std::sync::Arc;
        use std::sync::Mutex;

        struct CountingHook {
            calls: Arc<Mutex<u32>>,
        }
        impl sbproxy_plugin::MlClassifierHook for CountingHook {
            fn classify<'a>(
                &'a self,
                _snap: &'a sbproxy_plugin::RequestSnapshotView<'a>,
            ) -> Pin<
                Box<
                    dyn Future<Output = Option<sbproxy_plugin::MlClassificationResult>> + Send + 'a,
                >,
            > {
                *self.calls.lock().unwrap() += 1;
                Box::pin(async move { None })
            }
        }

        let calls = Arc::new(Mutex::new(0_u32));
        sbproxy_plugin::register_ml_classifier_hook(Arc::new(CountingHook {
            calls: calls.clone(),
        }));
        let snap = sbproxy_plugin::RequestSnapshotView {
            method: "GET",
            path: "/",
            query: "",
            header_count: 0,
            body_size_bytes: None,
            accept_header: "",
            user_agent: "",
            cookie_present: false,
            ja4_fingerprint: None,
            ja4_trustworthy: false,
            known_headless: false,
            agent_id_source: None,
            client_ip: None,
        };
        for hook in sbproxy_plugin::ml_classifier_hooks().iter() {
            let _ = hook.classify(&snap).await;
        }
        assert!(*calls.lock().unwrap() >= 1);
    }

    #[tokio::test]
    async fn anomaly_hook_registry_iterates_registered_hooks() {
        use std::future::Future;
        use std::pin::Pin;
        use std::sync::Arc;
        use std::sync::Mutex;

        struct CountingHook {
            calls: Arc<Mutex<u32>>,
        }
        impl sbproxy_plugin::AnomalyDetectorHook for CountingHook {
            fn analyze<'a>(
                &'a self,
                _ctx: &'a sbproxy_plugin::RequestContextView<'a>,
            ) -> Pin<Box<dyn Future<Output = Vec<sbproxy_plugin::AnomalyVerdict>> + Send + 'a>>
            {
                *self.calls.lock().unwrap() += 1;
                Box::pin(async move { Vec::new() })
            }
        }

        let calls = Arc::new(Mutex::new(0_u32));
        sbproxy_plugin::register_anomaly_hook(Arc::new(CountingHook {
            calls: calls.clone(),
        }));
        let view = sbproxy_plugin::RequestContextView {
            hostname: "test.example.com",
            method: "GET",
            path: "/",
            query: "",
            agent_id: None,
            agent_id_source: None,
            ja4_fingerprint: None,
            ja4_trustworthy: false,
            headless_library: None,
            client_ip: None,
        };
        for hook in sbproxy_plugin::anomaly_hooks().iter() {
            let _ = hook.analyze(&view).await;
        }
        assert!(*calls.lock().unwrap() >= 1);
    }

    #[test]
    fn missing_hooks_are_no_op() {
        // The pipeline already runs without registered hooks (the OSS
        // build registers none). This test pins the contract: an empty
        // registry returns Vec::new() / None and never panics.
        // Iteration over an empty Vec is a no-op.
        let identity = sbproxy_plugin::identity_hooks();
        let _: Vec<_> = identity.iter().collect();
        let ml = sbproxy_plugin::ml_classifier_hooks();
        let _: Vec<_> = ml.iter().collect();
        let anomaly = sbproxy_plugin::anomaly_hooks();
        let _: Vec<_> = anomaly.iter().collect();
    }

    // --- Wave 5 day-6 Item 4: reload_from_config_path idempotence ---

    #[test]
    fn reload_from_config_path_is_idempotent_under_repeat_invocation() {
        use std::io::Write as _;
        // Bootstrap install function must produce the same observable
        // pipeline state when invoked multiple times against the same
        // unchanged config file. This pins the day-6 SIGHUP contract:
        // an operator who fires `kill -HUP` twice in a row gets the
        // same active pipeline as a single call (the second swap is
        // a no-op functionally; the ArcSwap accepts a fresh Arc but
        // the contents are equivalent).
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "reload.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
"#;
        tmp.write_all(yaml.as_bytes()).unwrap();
        tmp.flush().unwrap();

        // First reload populates the pipeline.
        reload_from_config_path(tmp.path().to_str().unwrap()).expect("first reload");
        let revision_one = reload::current_pipeline().config_revision.clone();

        // Second reload against the same file MUST succeed and MUST
        // produce the same revision (the revision is derived from
        // the host_map content so it is byte-stable for an unchanged
        // config).
        reload_from_config_path(tmp.path().to_str().unwrap()).expect("second reload");
        let revision_two = reload::current_pipeline().config_revision.clone();
        assert_eq!(
            revision_one, revision_two,
            "two reloads against the same config must yield the same revision",
        );

        // Third reload after a config rewrite must produce a DIFFERENT
        // revision so the operator-driven SIGHUP path is observable.
        let yaml_two = r#"
proxy:
  http_bind_port: 0
origins:
  "reload.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
  "second.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok-2"
"#;
        std::fs::write(tmp.path(), yaml_two).unwrap();
        reload_from_config_path(tmp.path().to_str().unwrap()).expect("third reload");
        let revision_three = reload::current_pipeline().config_revision.clone();
        assert_ne!(
            revision_two, revision_three,
            "a reload after a config change must yield a fresh revision",
        );
    }

    #[test]
    fn reload_from_config_path_propagates_compile_errors() {
        use std::io::Write as _;
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        // Hard-broken YAML: missing colon, bad indent.
        tmp.write_all(b"proxy: !! no\n  origins ....\n").unwrap();
        tmp.flush().unwrap();
        let err = reload_from_config_path(tmp.path().to_str().unwrap()).expect_err("expected err");
        let _ = format!("{err}");
    }

    // --- WOR-43: CSP report redaction ---

    #[test]
    fn csp_report_redacts_query_string_in_document_uri() {
        let body = br#"{
            "csp-report": {
                "document-uri": "https://example.com/page?token=abc&user=42",
                "violated-directive": "script-src 'self'",
                "blocked-uri": "https://evil.example/inject.js?session=xyz",
                "effective-directive": "script-src",
                "original-policy": "default-src 'self'; script-src 'self'"
            }
        }"#;
        let r = redact_csp_report(body);
        let doc = r.document_uri.expect("document_uri");
        assert!(
            doc.contains("?[redacted]"),
            "query string must be redacted, got: {doc}"
        );
        assert!(!doc.contains("token=abc"), "token must not appear: {doc}");
        let blocked = r.blocked_uri.expect("blocked_uri");
        assert!(
            blocked.contains("?[redacted]"),
            "blocked_uri query must be redacted, got: {blocked}"
        );
        assert!(!blocked.contains("session=xyz"));
        assert_eq!(r.violated_directive.as_deref(), Some("script-src 'self'"));
        assert_eq!(r.effective_directive.as_deref(), Some("script-src"));
    }

    #[test]
    fn csp_report_handles_reporting_api_envelope() {
        let body = br#"[{
            "type": "csp-violation",
            "body": {
                "documentURL": "https://example.com/page?id=abc",
                "blockedURL": "https://cdn.example/script.js"
            }
        }]"#;
        let r = redact_csp_report(body);
        let doc = r.document_uri.expect("document_uri");
        assert!(doc.contains("?[redacted]"), "got: {doc}");
        assert_eq!(
            r.blocked_uri.as_deref(),
            Some("https://cdn.example/script.js"),
        );
    }

    #[test]
    fn csp_report_caps_long_field_values() {
        // Build a directive value longer than the redaction cap.
        let long = "a".repeat(1024);
        let body = format!(
            r#"{{"csp-report":{{"violated-directive":"{long}"}}}}"#,
            long = long
        );
        let r = redact_csp_report(body.as_bytes());
        let v = r.violated_directive.expect("violated_directive");
        assert!(
            v.len() <= REDACTED_FIELD_CAP + 3, // "..." suffix
            "expected truncation, got len {}",
            v.len()
        );
        assert!(v.ends_with("..."));
    }

    #[test]
    fn csp_report_unknown_fields_are_dropped() {
        let body = br#"{
            "csp-report": {
                "secret-field": "should not appear",
                "violated-directive": "script-src"
            }
        }"#;
        let r = redact_csp_report(body);
        // Only the known allowlist comes through.
        assert!(r.violated_directive.is_some());
        assert!(r.document_uri.is_none());
        assert!(r.blocked_uri.is_none());
    }

    #[test]
    fn csp_report_invalid_json_returns_empty() {
        let r = redact_csp_report(b"not json {");
        assert_eq!(r, RedactedCspReport::default());
    }

    // --- WOR-45: SSRF guard ---

    #[test]
    fn ssrf_guard_rejects_metadata_ip_literal() {
        let err = guard_upstream("169.254.169.254", 80, false, &[])
            .expect_err("metadata endpoint must be blocked");
        let s = format!("{err}");
        assert!(s.contains("SSRF") || s.contains("private"), "got: {s}");
    }

    #[test]
    fn ssrf_guard_allows_public_ip() {
        // 1.1.1.1 is a global anycast address; the validator's
        // private/loopback/link-local checks must not flag it.
        guard_upstream("1.1.1.1", 443, true, &[]).expect("public ip ok");
    }

    #[test]
    fn ssrf_guard_allowlist_permits_metadata_range() {
        // Operator opted in to 169.254.0.0/16 (e.g. for a trusted IMDS
        // sidecar). The same URL that fails the default check now
        // passes when the resolved IP falls inside the allowlist.
        let allow: Vec<ipnetwork::IpNetwork> = vec!["169.254.0.0/16".parse().expect("cidr")];
        guard_upstream("169.254.169.254", 80, false, &allow)
            .expect("allowlisted private IP must pass");
    }

    #[test]
    fn ssrf_guard_rejects_loopback_v6() {
        let err = guard_upstream("::1", 80, false, &[]).expect_err("loopback v6 blocked");
        let _ = format!("{err}");
    }

    // --- WOR-46: trust-bounded X-Forwarded-Proto ---

    #[test]
    fn https_decision_listener_tls_wins() {
        // Direct TLS handshake: HTTPS regardless of XFP or peer trust.
        assert!(is_request_https(true, false, None));
        assert!(is_request_https(true, false, Some("http")));
        assert!(is_request_https(true, true, Some("https")));
    }

    #[test]
    fn https_decision_xfp_ignored_from_untrusted_peer() {
        // Direct HTTP client claiming X-Forwarded-Proto: https must
        // NOT bypass the force_ssl redirect. This is the regression
        // test for WOR-46.
        assert!(!is_request_https(false, false, Some("https")));
        assert!(!is_request_https(false, false, Some("HTTPS")));
        assert!(!is_request_https(false, false, None));
    }

    #[test]
    fn https_decision_xfp_honoured_from_trusted_peer() {
        // Peer is in trusted_proxies (CDN, ALB, sidecar): we honour
        // the forwarded scheme.
        assert!(is_request_https(false, true, Some("https")));
        assert!(is_request_https(false, true, Some("HTTPS")));
        assert!(!is_request_https(false, true, Some("http")));
        assert!(!is_request_https(false, true, None));
    }
}
