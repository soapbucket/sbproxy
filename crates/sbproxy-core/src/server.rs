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
use tracing::{debug, info, warn};

use crate::context::RequestContext;
use crate::pipeline::CompiledPipeline;
use crate::reload;
use sbproxy_ai::{AiClient, AiHandlerConfig};
use sbproxy_modules::action::ForwardingHeaderControls;
use sbproxy_modules::{Action, Auth, Policy};
use sbproxy_observe::metrics;

/// Lazily-initialized, hot-reloadable AI client.
///
/// Wrapped in `ArcSwap` so the SIGHUP / file-watcher / admin reload
/// path can rebuild the client alongside the AI provider registry
/// (see [`reload_ai_client`] and `sbproxy_ai::reload_provider_registry`).
/// In-flight requests that already cloned the previous `Arc<AiClient>`
/// continue against their snapshot until they complete; subsequent
/// requests pick up the new client transparently.
static AI_CLIENT: std::sync::LazyLock<arc_swap::ArcSwap<AiClient>> =
    std::sync::LazyLock::new(|| arc_swap::ArcSwap::from_pointee(AiClient::new()));

/// Atomically replace the live AI client with a freshly built one.
///
/// Called from the reload paths in tandem with
/// `sbproxy_ai::reload_provider_registry` so a SIGHUP that adds or
/// edits providers picks up the new catalog without a process
/// restart. In-flight requests are unaffected; the next request after
/// the swap sees the new client.
pub fn reload_ai_client() {
    AI_CLIENT.store(std::sync::Arc::new(AiClient::new()));
}

/// Process-wide AI budget tracker.
///
/// Accumulates token and cost usage across every AI proxy request
/// and is consulted before each upstream dispatch to enforce the
/// configured budget limits. Deliberately a `LazyLock` (and not an
/// `ArcSwap`) so SIGHUP / file-watcher / admin reload do *not* reset
/// the tracker: budget windows are wall-clock-relative (e.g. daily,
/// monthly) and must survive config reloads. A reload that wiped the
/// tracker would silently roll the counters back to zero and let
/// already-spent budget through a second time. See WOR-173.
static BUDGET_TRACKER: std::sync::LazyLock<sbproxy_ai::BudgetTracker> =
    std::sync::LazyLock::new(sbproxy_ai::BudgetTracker::new);

/// Process-wide per-surface rate limiter shared across all AI origins.
///
/// State is keyed by `AiSurface::label()` so that per-surface caps
/// are enforced globally, not per-origin. Operators configure caps
/// via `ai_handler_config.per_surface_rate_limits`; surfaces without
/// an entry are uncapped.
static AI_SURFACE_RATE_LIMITER: std::sync::LazyLock<sbproxy_ai::ratelimit::SurfaceRateLimiter> =
    std::sync::LazyLock::new(sbproxy_ai::ratelimit::SurfaceRateLimiter::new);

/// Process-wide per-model rate limiter for the AI gateway (WOR-223,
/// WOR-232). One bucket per `(apikey, model)` pair, sized to the
/// `model_rate_limits` entry on the matching `AiHandlerConfig`. The
/// limiter is consulted at the entry of `handle_ai_proxy` with a
/// real tiktoken-derived prompt-token estimate so TPM rejections
/// happen before any byte goes upstream.
static AI_MODEL_RATE_LIMITER: std::sync::LazyLock<sbproxy_ai::ratelimit::ModelRateLimiter> =
    std::sync::LazyLock::new(sbproxy_ai::ratelimit::ModelRateLimiter::new);

/// Borrow the process-wide AI budget tracker.
///
/// Exposed so reload-path integration tests (and any future admin
/// surface that needs to inspect per-scope accumulators) can read
/// the live counters without a second source of truth. Hot path
/// callers inside this crate use the static directly.
pub fn budget_tracker() -> &'static sbproxy_ai::BudgetTracker {
    &BUDGET_TRACKER
}

fn cel_response_request_view(
    ctx: &RequestContext,
) -> sbproxy_modules::transform::CelResponseRequestView<'_> {
    let tls =
        ctx.tls_fingerprint
            .as_ref()
            .map(|fp| sbproxy_modules::transform::TlsFingerprintView {
                ja3: fp.ja3.as_deref(),
                ja4: fp.ja4.as_deref(),
                ja4h: fp.ja4h.as_deref(),
                trustworthy: fp.trustworthy,
            });

    #[cfg(feature = "agent-class")]
    let agent = Some(sbproxy_modules::transform::AgentClassView {
        agent_id: ctx.agent_id.as_ref().map(|id| id.0.as_str()),
        agent_vendor: ctx.agent_vendor.as_deref(),
        agent_purpose: ctx.agent_purpose.map(|p| p.as_str()),
        agent_id_source: ctx.agent_id_source.map(|s| s.as_str()),
        agent_rdns_hostname: ctx.agent_rdns_hostname.as_deref(),
    });
    #[cfg(not(feature = "agent-class"))]
    let agent = None;

    let headless = Some(match ctx.headless_signal.as_ref() {
        Some(crate::context::HeadlessSignal::Detected {
            library,
            confidence,
        }) => sbproxy_modules::transform::HeadlessSignalView {
            detected: true,
            library: Some(library.as_str()),
            confidence: *confidence,
        },
        Some(crate::context::HeadlessSignal::NotDetected) | None => {
            sbproxy_modules::transform::HeadlessSignalView::default()
        }
    });

    sbproxy_modules::transform::CelResponseRequestView {
        tls,
        agent,
        headless,
    }
}

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

/// Pending OSS embedding-cache write produced by a semantic miss
/// (WOR-796). Tuple components: (cache handle, prompt key, the prompt's
/// embedding vector). When populated, the AI relay stores the upstream
/// response under this key + vector after a successful (200) response.
/// Mutually exclusive with [`PendingSemcacheMiss`]: the OSS cache only
/// runs when the enterprise `SemanticLookupHook` is absent.
type PendingEmbedMiss = (
    std::sync::Arc<sbproxy_ai::EmbeddingCache>,
    String,
    Vec<f32>,
    // WOR-1142: per-caller cache scope (hashed tenant + credential) so
    // the write-on-miss store records the same scope the lookup filtered
    // on.
    String,
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
    let verifier = sbproxy_tls::mtls::build_client_cert_verifier(
        &mtls.client_ca_file,
        mtls.require,
        &mtls.allowed_cn_patterns,
        cache,
    )?;
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
/// did not author `ai_crawl_control` or any content-shaping
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

/// Apply a single compiled transform with typed dispatch.
///
/// The standard `CompiledTransform::apply` entry point in
/// `sbproxy-modules` is content-type and (`body`, `content_type`)
/// based. The typed dispatch here needs to override two cases:
///
/// - `Boilerplate` reports the byte-count it stripped; surface the
///   number on `ctx.metrics.stripped_bytes` so the audit and
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
        Transform::LuaJson(t) => t.apply_with_context(body, script_modifier_context(ctx)),
        Transform::JavaScript(t) => t.apply_with_context(body, script_modifier_context(ctx)),
        Transform::JsJson(t) => t.apply_with_context(body, script_modifier_context(ctx)),
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
            let request_view = cel_response_request_view(ctx);
            // WOR-168: `evaluate_headers` now returns
            // `TransformError::InvariantViolated` instead of panicking
            // when the inner Remove arm is reached. Propagate as
            // `anyhow::Error` so the body-buffer pipeline's `fail_on_error`
            // path takes over and synthesises a 500 with attribution.
            match t.evaluate_headers_with_request(
                body.as_ref(),
                status,
                &http::HeaderMap::new(),
                request_view,
            ) {
                Ok(mutations) => {
                    ctx.cel_response_header_mutations.extend(mutations);
                }
                Err(e) => {
                    return Err(anyhow::Error::new(e));
                }
            }
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
/// explicit per-origin tokens-per-byte ratio. When
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
/// projection URLs. The five recognised paths are the four
/// projection documents plus the `llms-full.txt` extended variant.
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
        // AGENTS.md is Markdown (agents.md convention); ai.txt is a
        // plain-text robots-like file (Spawning ai.txt).
        "agents-md" => "text/markdown; charset=utf-8",
        "ai-txt" => "text/plain; charset=utf-8",
        "agents-json" => "application/json; charset=utf-8",
        _ => "text/plain",
    }
}

/// Resolve the tokens-per-byte ratio the proxy uses for a given
/// origin's Markdown projection.
///
/// The ratio is a per-origin knob defaulting to
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

/// Outcome of the Content-Signal / TDM-Reservation header decision.
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
/// `is_2xx` gates the entire decision ("on 200 responses
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

fn script_modifier_context(ctx: &RequestContext) -> serde_json::Value {
    let aipref = ctx.aipref.unwrap_or_default();
    serde_json::json!({
        "request": {
            "aipref": {
                "train": aipref.train,
                "search": aipref.search,
                "ai_input": aipref.ai_input,
                "ai-input": aipref.ai_input,
            }
        }
    })
}

fn insert_json_header(
    headers: &mut serde_json::Map<String, serde_json::Value>,
    key: impl AsRef<str>,
    value: impl AsRef<str>,
) {
    headers.insert(
        key.as_ref().to_string(),
        serde_json::Value::String(value.as_ref().to_string()),
    );
}

fn response_headers_from_header_map(
    headers: &http::HeaderMap,
) -> serde_json::Map<String, serde_json::Value> {
    let mut out = serde_json::Map::new();
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            insert_json_header(&mut out, name.as_str(), v);
        }
    }
    out
}

fn response_headers_for_static_action(
    content_type: &str,
    headers: &std::collections::HashMap<String, String>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut out = serde_json::Map::new();
    insert_json_header(&mut out, "content-type", content_type);
    for (name, value) in headers {
        insert_json_header(&mut out, name, value);
    }
    out
}

fn response_modifier_headers(
    result: &serde_json::Value,
    original_headers: &serde_json::Map<String, serde_json::Value>,
) -> Vec<(String, String)> {
    let mut headers = Vec::new();

    if let Some(set_headers) = result.get("set_headers").and_then(|h| h.as_object()) {
        for (key, value) in set_headers {
            if let Some(v) = value.as_str() {
                headers.push((key.clone(), v.to_string()));
            }
        }
    }

    if let Some(returned_headers) = result.get("headers").and_then(|h| h.as_object()) {
        for (key, value) in returned_headers {
            let Some(v) = value.as_str() else {
                continue;
            };
            let changed = original_headers
                .get(key)
                .and_then(|original| original.as_str())
                != Some(v);
            if changed {
                headers.push((key.clone(), v.to_string()));
            }
        }
    }

    headers
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
/// across origins. The client is built lazily on first use from the
/// `proxy.http_client_timeouts.swr_client_secs` config key (default
/// 30s, matching the conservative ceiling the rest of the proxy uses
/// for outbound HTTP). Hot-reloading the timeout requires a process
/// restart; pooled connections are kept across reloads.
static SWR_CLIENT: std::sync::OnceLock<Option<reqwest::Client>> = std::sync::OnceLock::new();

/// Lazily-built shared client for stale-while-revalidate background
/// refreshes. WOR-619: a `reqwest::Client::builder().build()` failure (a
/// systemic TLS-init problem) must not panic the first request that needs
/// SWR. The client is built once; on failure the error is logged and SWR is
/// disabled (callers skip revalidation and keep serving cached entries)
/// instead of `.expect()`-ing per use.
fn swr_client() -> Option<&'static reqwest::Client> {
    SWR_CLIENT
        .get_or_init(|| {
            let secs = reload::current_pipeline()
                .config
                .server
                .http_client_timeouts
                .swr_client_secs;
            match reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(secs))
                .build()
            {
                Ok(client) => Some(client),
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "swr: failed to build revalidation HTTP client; stale-while-revalidate disabled"
                    );
                    None
                }
            }
        })
        .as_ref()
}

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
        let Some(client) = swr_client() else {
            // The revalidation client could not be built (logged once at
            // init). SWR is best-effort, so skip the refresh and keep
            // serving the cached entry.
            return;
        };
        let resp = match client.get(&full_url).header("host", &hostname).send().await {
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

// --- WOR-87 fake-sink capture helper ---

/// Build a synthetic event JSON for the inbound request and capture
/// it into every fake sink (after per-sink redaction).
///
/// Test-only: only invoked when
/// `sbproxy_observe::fake_sinks::enabled()` is true. The function
/// reads request headers and an optional small request body, writes
/// them into a JSON envelope alongside a placeholder for every
/// known env-var-typed redaction target, then routes the JSON
/// through the per-sink redaction profile so the buffer reflects
/// what a real sink would emit.
///
/// Body capture is best-effort: when the inbound carries a body, we
/// take up to 64 KiB so the redactor sees the planted secret. The
/// bytes are discarded after capture rather than re-injected into
/// the upstream stream because every test fixture targets a non-
/// existent host (`redact.localhost`) and short-circuits at origin
/// resolution; no real upstream consumes the body. A future fixture
/// that wants a real upstream after capture would need the bytes
/// re-written via Pingora's body-mirroring API (out of scope here).
async fn capture_fake_sink_event(session: &mut pingora_proxy::Session) {
    use serde_json::{json, Map, Value};

    let req = session.req_header();
    let method = req.method.as_str().to_string();
    let path_owned = req.uri.path().to_string();

    // Headers map. Lowercase the names and normalise hyphens to
    // underscores so the typed-marker matcher in
    // `sbproxy_observe::logging::match_denylist` recognises shapes
    // like `x-stripe-key` (-> `x_stripe_key`).
    let mut headers = Map::new();
    for (name, value) in req.headers.iter() {
        let key = name.as_str().to_ascii_lowercase().replace('-', "_");
        let v = value.to_str().unwrap_or("").to_string();
        headers.insert(key, Value::String(v));
    }

    // Body: read up to 64 KiB. Some fixtures plant the secret in the
    // body (`messages.0.content` / `oauth_client_secret`). We try to
    // parse it as JSON so the typed-key matcher fires on the inner
    // structure; on parse failure we fall back to the raw string.
    const MAX_BODY: usize = 64 * 1024;
    let mut body_bytes: Vec<u8> = Vec::new();
    while let Ok(Some(chunk)) = session.read_request_body().await {
        let remaining = MAX_BODY.saturating_sub(body_bytes.len());
        if remaining == 0 {
            break;
        }
        let take = std::cmp::min(chunk.len(), remaining);
        body_bytes.extend_from_slice(&chunk[..take]);
        if body_bytes.len() >= MAX_BODY {
            break;
        }
    }
    let body_value: Value = if body_bytes.is_empty() {
        Value::Null
    } else {
        match serde_json::from_slice::<Value>(&body_bytes) {
            Ok(v) => v,
            Err(_) => Value::String(String::from_utf8_lossy(&body_bytes).into_owned()),
        }
    };

    // Env-var snapshot. Always include placeholders for the known
    // env-typed redaction targets so the typed marker fires even
    // when the operator did not actually set the variable. The
    // placeholder strings are deliberately not secret-shaped; the
    // typed-key matcher swaps the field value for the marker
    // regardless of what was there.
    let env_block = json!({
        "sbproxy_ledger_hmac_key": "PLACEHOLDER_LEDGER_HMAC_KEY",
    });

    let envelope = json!({
        "event_type": "request_started",
        "method": method,
        "path": path_owned,
        "headers": headers,
        "body": body_value,
        "env": env_block,
    });

    let json_str = match serde_json::to_string(&envelope) {
        Ok(s) => s,
        Err(_) => return,
    };
    sbproxy_observe::fake_sinks::capture_all_sinks(&json_str);
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

/// Send an error response, choosing the body in this order:
/// 1. Operator-authored [`sbproxy_config::ErrorPageEntry`] matching
///    the status code, content-negotiated against the request's
///    `Accept` header.
/// 2. RFC 9457 `application/problem+json` when
///    [`sbproxy_config::ProblemDetailsConfig`] is enabled on the
///    origin.
/// 3. Plain-text default (`send_error`).
///
/// When multiple custom pages match a status and the client expresses
/// no concrete preference, JSON is preferred, then HTML, then the
/// first authored entry.
async fn send_error_with_pages(
    session: &mut Session,
    status: u16,
    message: &str,
    error_pages: Option<&[sbproxy_config::ErrorPageEntry]>,
    problem_details: Option<&sbproxy_config::ProblemDetailsConfig>,
    request_path: &str,
) -> Result<()> {
    if let Some(pages) = error_pages {
        let candidates: Vec<&sbproxy_config::ErrorPageEntry> =
            pages.iter().filter(|p| p.status.matches(status)).collect();

        if !candidates.is_empty() {
            let accept = session
                .req_header()
                .headers
                .get("accept")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let chosen = select_error_page(&candidates, accept);

            let body = if chosen.template {
                chosen
                    .body
                    .replace("{{ status_code }}", &status.to_string())
                    .replace("{{status_code}}", &status.to_string())
                    .replace("{{ request.path }}", request_path)
                    .replace("{{request.path}}", request_path)
            } else {
                chosen.body.clone()
            };

            return send_response(session, status, &chosen.content_type, body.as_bytes()).await;
        }
    }

    // No custom page matched. Fall through to problem-details when enabled.
    if let Some(pd) = problem_details {
        if pd.enabled {
            let body = render_problem_details(status, message, pd, request_path);
            return send_response(session, status, "application/problem+json", body.as_bytes())
                .await;
        }
    }

    // No matching error page, no problem-details: plain-text default.
    send_error(session, status, message).await
}

/// Render an RFC 9457 `application/problem+json` body. The `type` field
/// is derived from `pd.type_base_uri`; when unset the renderer emits
/// the RFC default `about:blank`. The `detail` field is suppressed
/// when `pd.include_detail` is false.
fn render_problem_details(
    status: u16,
    message: &str,
    pd: &sbproxy_config::ProblemDetailsConfig,
    request_path: &str,
) -> String {
    let type_uri = match &pd.type_base_uri {
        Some(base) => {
            let trimmed = base.trim_end_matches('/');
            format!("{}/{}", trimmed, status)
        }
        None => "about:blank".to_string(),
    };
    let title = http::StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("Error")
        .to_string();
    let mut body = serde_json::Map::new();
    body.insert("type".into(), serde_json::Value::String(type_uri));
    body.insert("title".into(), serde_json::Value::String(title));
    body.insert("status".into(), serde_json::Value::from(status));
    if pd.include_detail {
        body.insert(
            "detail".into(),
            serde_json::Value::String(message.to_string()),
        );
    }
    body.insert(
        "instance".into(),
        serde_json::Value::String(request_path.to_string()),
    );
    serde_json::Value::Object(body).to_string()
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
    candidates: &[&'a sbproxy_config::ErrorPageEntry],
    accept_header: &str,
) -> &'a sbproxy_config::ErrorPageEntry {
    let ranges = parse_accept_ranges(accept_header);

    // If the client expresses a concrete preference (anything other than
    // a wildcard `*/*`), honor it: score each candidate by its best-matching
    // q-value, higher wins, ties break on candidate order.
    let has_concrete_pref = ranges.iter().any(|r| r.typ != "*" || r.subtype != "*");
    if has_concrete_pref {
        let mut best_idx: usize = 0;
        let mut best_q: f32 = 0.0;
        for (i, cand) in candidates.iter().enumerate() {
            let q = match_accept_q(&ranges, &cand.content_type);
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
        if let Some(c) = candidates.iter().find(|c| c.content_type.starts_with(pref)) {
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

/// Upper bound on the number of `Accept` header entries parsed per request.
/// Content negotiation only ever needs a handful of media types; capping the
/// parse stops an attacker from forcing a large per-request allocation (and the
/// CPU to build it) by sending tens of thousands of comma-separated entries
///.
const MAX_ACCEPT_RANGES: usize = 32;

fn parse_accept_ranges(header: &str) -> Vec<AcceptRange> {
    if header.is_empty() {
        return Vec::new();
    }
    header
        .split(',')
        .take(MAX_ACCEPT_RANGES)
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
#[derive(Debug)]
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

/// WOR-892 PR1 step 3/3: OIDC Relying-Party request-time check.
///
/// Two outcomes:
///
/// 1. The request carries a valid, unexpired session cookie sealed
///    under the operator's `cookie_secret`. The session's `sub`
///    becomes the authenticated subject; the request is allowed.
/// 2. No session cookie (or one that fails to decrypt / has
///    expired). The proxy generates a PKCE verifier, state, nonce,
///    seals a tx cookie carrying them plus the caller's intended
///    URL, and returns a 302 redirect to the IdP's
///    `authorization_endpoint`. Set-Cookie on the tx cookie ships
///    in the same response.
///
/// Token-endpoint exchange + ID-token validation live in the
/// `/oidc/callback` synthetic endpoint (request_phase.rs). When the
/// IdP redirects back, that handler mints the session cookie and
/// redirects to the caller's original target.
fn oidc_check(
    cfg: &sbproxy_modules::auth::oidc::OidcAuth,
    headers: &http::HeaderMap,
) -> AuthResult {
    use sbproxy_modules::auth::oidc::{callback, pkce, session};

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // --- session cookie check (happy path) ---
    if let Some(cookie_value) = read_cookie(headers, &cfg.session_cookie_name) {
        if let Ok(claims) = session::open_session(&cookie_value, cfg.cookie_secret.as_bytes(), now)
        {
            // The session was issued for this proxy's client_id +
            // issuer; reject a cookie cross-pollinated from a
            // sibling OIDC origin whose iss / aud differs.
            if claims.iss == cfg.issuer && claims.aud == cfg.client_id {
                return AuthResult::Allow {
                    sub: Some(claims.sub),
                    source: Some(sbproxy_plugin::AuthSubjectSource::Cookie),
                };
            }
        }
    }

    // --- no valid session: build the IdP redirect challenge ---
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if host.is_empty() {
        return AuthResult::Deny(400, "oidc: missing Host header".to_string());
    }
    let redirect_uri = format!("https://{host}{}", cfg.redirect_path);

    let verifier = pkce::generate_code_verifier();
    let challenge = pkce::derive_code_challenge(&verifier);
    let state = pkce::generate_code_verifier(); // 43-char base64url is fine for state too
    let nonce = pkce::generate_code_verifier(); // same shape for nonce

    let tx = session::TxClaims {
        state: state.clone(),
        nonce: nonce.clone(),
        pkce_verifier: verifier,
        return_to: "/".to_string(),
        exp: now + cfg.tx_ttl_secs,
    };
    let sealed_tx = match session::seal_tx(&tx, cfg.cookie_secret.as_bytes()) {
        Ok(s) => s,
        Err(e) => {
            return AuthResult::Deny(500, format!("oidc: tx cookie seal failed: {e}"));
        }
    };

    let redirect =
        callback::build_authorize_redirect_url(cfg, &redirect_uri, &challenge, &state, &nonce);
    // RFC 6265bis __Host- prefix forces Secure + Path=/ + no Domain.
    // SameSite=Lax lets the cookie survive the cross-site redirect
    // back from the IdP (Strict would drop it on the callback hop
    // and break the entire login). HttpOnly because no client JS
    // should touch the tx cookie.
    let set_cookie = format!(
        "{}={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
        cfg.tx_cookie_name, sealed_tx, cfg.tx_ttl_secs
    );
    AuthResult::DenyWithHeaders(
        302,
        String::new(),
        vec![
            ("Location".to_string(), redirect),
            ("Set-Cookie".to_string(), set_cookie),
        ],
    )
}

/// Look up `name` in the request's `Cookie` header. Cookie syntax
/// is `name=value; name2=value2`; we split on `;`, trim each pair,
/// and return the first matching value. Returns None when the
/// header is missing or no pair matches.
fn read_cookie(headers: &http::HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get("cookie").and_then(|v| v.to_str().ok())?;
    for pair in raw.split(';') {
        let trimmed = pair.trim();
        if let Some(rest) = trimmed.strip_prefix(&format!("{name}=")) {
            return Some(rest.to_string());
        }
    }
    None
}

/// Run the auth check for a given origin. Returns the legacy
/// `AuthResult` plus the matched `Principal` (when the result is an
/// `Allow`). `path` is the request-line path (no scheme/authority);
/// for BotAuth it reconstructs `@target-uri` so the verifier sees
/// the same canonical component the signer covered.
///
/// The `tenant_id` is stamped onto every returned principal. Pass
/// the resolved tenant for the matched origin (clone from
/// `RequestContext.tenant_id` at the call site); WOR-1047 PR2 keeps
/// the legacy `AuthResult` alongside the new principal carrier so
/// the migration to a principal-only return type can happen in a
/// follow-up.
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
    tenant_id: sbproxy_plugin::TenantId,
    // WOR-1149: the request's resolved agent identity (from the
    // agent-class resolver chain), threaded into CAP `sub` binding.
    // `None` when no resolver ran.
    resolved_agent_id: Option<&str>,
) -> (AuthResult, Option<sbproxy_plugin::Principal>) {
    // WOR-1074: Stage 2 calls `check_auth_with_tls` with the
    // resolved TLS-cert thumbprint from `sbproxy_tls::mtls::ClientCertInfo`.
    // Existing callers that have not yet been plumbed pass `None`
    // here, which keeps the legacy behaviour: any auth provider
    // configured with `require_mtls_bound = true` rejects when no
    // thumbprint is available (the verifier treats `None` as
    // "no TLS binding"). The DPoP wire-up does not need a
    // thumbprint and works through the `None` path unchanged.
    check_auth_with_tls(
        auth,
        headers,
        query,
        method,
        path,
        tenant_id,
        None,
        resolved_agent_id,
    )
    .await
}

/// WOR-1074: build the `htu` claim value the DPoP verifier
/// compares against. RFC 9449 §4.2 mandates the verifier match
/// `htu` against the request's resource URI, ignoring query +
/// fragment. The function reads the inbound `Host` header (Pingora
/// surfaces it as a regular header) and prepends `https://`; that
/// matches what a DPoP-aware client typically signs. Deployments
/// terminating TLS upstream of the proxy can layer a follow-up
/// helper that reads `X-Forwarded-Proto` if needed.
fn format_htu(headers: &http::HeaderMap, path: &str) -> String {
    let host = headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    format!("https://{host}{path}")
}

/// WOR-1074: extended `check_auth` that threads the inbound TLS
/// client cert's SHA-256 thumbprint through to the
/// [`MtlsBoundVerifier`](sbproxy_modules::auth::mtls_bound::MtlsBoundVerifier) when a Bearer / JWT provider has
/// `require_mtls_bound = true` set. Production callers eventually
/// pass `tls_cert_thumbprint = Some(<base64url-no-pad SHA-256>)`;
/// today the request-phase shim passes `None` so a misconfigured
/// `require_mtls_bound = true` deployment fails closed (every
/// request rejected) instead of silently allowing.
#[allow(clippy::too_many_arguments)]
async fn check_auth_with_tls(
    auth: &Auth,
    headers: &http::HeaderMap,
    query: Option<&str>,
    method: &str,
    path: &str,
    tenant_id: sbproxy_plugin::TenantId,
    tls_cert_thumbprint: Option<&str>,
    // WOR-1149: resolved agent id for CAP `sub` binding (see `check_auth`).
    resolved_agent_id: Option<&str>,
) -> (AuthResult, Option<sbproxy_plugin::Principal>) {
    use sbproxy_modules::auth::dpop::DpopVerifier;
    use sbproxy_modules::auth::mtls_bound::{MtlsBoundVerifier, MtlsBoundVerifierConfig};
    // WOR-1136: the DPoP verifier owns the (jkt, jti) replay cache that
    // rejects a reused proof (RFC 9449). That cache MUST persist across
    // requests, so the verifier lives in a process-wide `OnceLock`
    // rather than being rebuilt per call. A fresh per-request verifier
    // has an empty cache and never detects a replay. Mirrors the
    // `jwks::REGISTRY` singleton pattern.
    static DPOP_VERIFIER: std::sync::OnceLock<DpopVerifier> = std::sync::OnceLock::new();
    let dpop_verifier = DPOP_VERIFIER.get_or_init(DpopVerifier::default);
    match auth {
        Auth::ApiKey(a) => {
            match a.check_request_with_principal(headers, query, tenant_id.clone()) {
                Some(principal) => (AuthResult::allow_anonymous(), Some(principal)),
                None => (AuthResult::Deny(401, "unauthorized".to_string()), None),
            }
        }
        Auth::BasicAuth(a) => match a.check_request_with_principal(headers, tenant_id.clone()) {
            Some(principal) => {
                let sub = principal.sub.clone();
                (
                    AuthResult::Allow {
                        sub: Some(sub),
                        source: Some(sbproxy_plugin::AuthSubjectSource::Header),
                    },
                    Some(principal),
                )
            }
            None => (AuthResult::Deny(401, "unauthorized".to_string()), None),
        },
        Auth::Bearer(a) => match a.check_request_with_token(headers, tenant_id.clone()) {
            Some((principal, token)) => {
                // WOR-1074 Stage 2: if the provider has
                // `require_dpop = true`, the matched bearer token
                // MUST come with a valid RFC 9449 DPoP proof whose
                // jkt matches the operator-stamped
                // `attrs.metadata["dpop_jkt"]`. Without the
                // metadata, the provider is misconfigured and we
                // fail closed.
                if a.require_dpop {
                    let dpop_header = headers
                        .get("dpop")
                        .or_else(|| headers.get("DPoP"))
                        .and_then(|v| v.to_str().ok());
                    let expected_jkt = token.attrs.metadata.get("dpop_jkt").map(|s| s.as_str());
                    let Some(expected_jkt) = expected_jkt else {
                        return (
                            AuthResult::Deny(
                                401,
                                "bearer token requires DPoP binding but `attrs.metadata.dpop_jkt` is unset"
                                    .to_string(),
                            ),
                            None,
                        );
                    };
                    let htu = format_htu(headers, path);
                    if let Err(err) = dpop_verifier.verify(
                        dpop_header,
                        method,
                        &htu,
                        expected_jkt,
                        std::time::SystemTime::now(),
                    ) {
                        return (
                            AuthResult::Deny(401, format!("DPoP verification failed: {err}")),
                            None,
                        );
                    }
                }
                (AuthResult::allow_anonymous(), Some(principal))
            }
            None => (AuthResult::Deny(401, "unauthorized".to_string()), None),
        },
        Auth::Jwt(a) => match a.check_request_with_claims(headers, tenant_id.clone()) {
            Some((principal, claims)) => {
                // WOR-1074 Stage 2: DPoP first (the JWT's
                // `cnf.jkt` claim binds the access token to a
                // proof-of-possession key), then mTLS-bound
                // (the `cnf.x5t#S256` claim binds the access
                // token to a TLS client cert). The two checks
                // can both be enabled; both must pass.
                if a.require_dpop {
                    let dpop_header = headers
                        .get("dpop")
                        .or_else(|| headers.get("DPoP"))
                        .and_then(|v| v.to_str().ok());
                    let expected_jkt = claims
                        .get("cnf")
                        .and_then(|c| c.get("jkt"))
                        .and_then(|v| v.as_str());
                    let Some(expected_jkt) = expected_jkt else {
                        return (
                            AuthResult::Deny(
                                401,
                                "JWT requires DPoP binding but `cnf.jkt` claim is missing"
                                    .to_string(),
                            ),
                            None,
                        );
                    };
                    let htu = format_htu(headers, path);
                    if let Err(err) = dpop_verifier.verify(
                        dpop_header,
                        method,
                        &htu,
                        expected_jkt,
                        std::time::SystemTime::now(),
                    ) {
                        return (
                            AuthResult::Deny(401, format!("DPoP verification failed: {err}")),
                            None,
                        );
                    }
                }
                if a.require_mtls_bound {
                    // WOR-1137: when the operator requires mTLS binding,
                    // a token with no `cnf` claim must be rejected, not
                    // allowed. The default verifier has `require_cnf =
                    // false`, which let a plain bearer JWT (no cnf) pass
                    // through; build it with `require_cnf = true` so a
                    // missing cnf is a `MissingCnfClaim` denial.
                    let mtls_verifier =
                        MtlsBoundVerifier::new(MtlsBoundVerifierConfig { require_cnf: true });
                    if let Err(err) = mtls_verifier.verify(&claims, tls_cert_thumbprint) {
                        return (
                            AuthResult::Deny(
                                401,
                                format!("mTLS-bound token verification failed: {err}"),
                            ),
                            None,
                        );
                    }
                }
                let sub = principal.sub.clone();
                let auth_result = if sub.is_empty() {
                    // Token validated but carried no `sub` claim:
                    // still authenticated, just without an
                    // identifiable subject. Keep the legacy
                    // `AuthResult` anonymous; the principal still
                    // carries the JWT source + provider attrs.
                    AuthResult::allow_anonymous()
                } else {
                    AuthResult::Allow {
                        sub: Some(sub),
                        source: Some(sbproxy_plugin::AuthSubjectSource::Jwt),
                    }
                };
                (auth_result, Some(principal))
            }
            None => (AuthResult::Deny(401, "unauthorized".to_string()), None),
        },
        Auth::Digest(d) => {
            if headers.get(http::header::AUTHORIZATION).is_some() {
                match d.check_request_with_subject(headers, method) {
                    Some(username) => {
                        let principal = sbproxy_plugin::Principal {
                            tenant_id: tenant_id.clone(),
                            sub: username.clone(),
                            source: sbproxy_plugin::PrincipalSource::Basic,
                            virtual_key: None,
                            attrs: sbproxy_plugin::PrincipalAttrs::default(),
                        };
                        (
                            AuthResult::Allow {
                                sub: Some(username),
                                source: Some(sbproxy_plugin::AuthSubjectSource::Header),
                            },
                            Some(principal),
                        )
                    }
                    None => {
                        let nonce = sbproxy_modules::auth::DigestAuth::generate_nonce();
                        (AuthResult::DigestChallenge(d.challenge(&nonce)), None)
                    }
                }
            } else {
                let nonce = sbproxy_modules::auth::DigestAuth::generate_nonce();
                (AuthResult::DigestChallenge(d.challenge(&nonce)), None)
            }
        }
        // ForwardAuth runs as a separate async subrequest in the
        // calling site; the result, including any trust headers
        // carrying the resolved user, lands on `ctx` after this
        // function returns. Treat it as an anonymous allow at the
        // dispatch layer; the post-auth capture step picks the user
        // out of `ctx.trust_headers` instead.
        Auth::ForwardAuth(_) => (
            AuthResult::allow_anonymous(),
            Some(sbproxy_plugin::Principal::anonymous_for(tenant_id.clone())),
        ),
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
                Err(_) => {
                    return (
                        AuthResult::Deny(500, "bot_auth: bad request".to_string()),
                        None,
                    );
                }
            };
            *req.headers_mut() = headers.clone();
            let verdict = if b.has_directory()
                && req
                    .headers()
                    .get("signature-agent")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| !v.trim().is_empty())
                    .unwrap_or(false)
            {
                b.verify_async(&req, bot_auth_directory_client()).await
            } else {
                b.verify(&req)
            };

            match verdict {
                BotAuthVerdict::Verified { agent_name, key_id } => {
                    tracing::info!(agent = %agent_name, key_id = %key_id, "bot_auth verified");
                    let mut metadata = std::collections::BTreeMap::new();
                    metadata.insert("bot_auth_keyid".to_string(), key_id);
                    let principal = sbproxy_plugin::Principal {
                        tenant_id: tenant_id.clone(),
                        sub: agent_name,
                        source: sbproxy_plugin::PrincipalSource::BotAuth,
                        virtual_key: None,
                        attrs: sbproxy_plugin::PrincipalAttrs {
                            metadata,
                            ..sbproxy_plugin::PrincipalAttrs::default()
                        },
                    };
                    (AuthResult::allow_anonymous(), Some(principal))
                }
                BotAuthVerdict::Missing => (
                    AuthResult::Deny(401, "bot_auth: signature required".to_string()),
                    None,
                ),
                BotAuthVerdict::UnknownAgent { key_id } => (
                    AuthResult::Deny(401, format!("bot_auth: unknown agent keyid {}", key_id)),
                    None,
                ),
                BotAuthVerdict::Failed { agent_name, reason } => {
                    let agent = agent_name.unwrap_or_else(|| "<unknown>".to_string());
                    tracing::warn!(agent = %agent, reason = %reason, "bot_auth verification failed");
                    (
                        AuthResult::Deny(401, "bot_auth: verification failed".to_string()),
                        None,
                    )
                }
                BotAuthVerdict::DirectoryUnavailable { reason } => {
                    // Wave 1 / G1.7: directory-side failure (HTTPS
                    // violation, allowlist mismatch, fetch deadline,
                    // self-signature failure, stale grace exceeded).
                    // Map to 401 like the other unsigned variants;
                    // the deny message stays generic so it does not
                    // leak directory state to a probing client.
                    tracing::warn!(reason = %reason, "bot_auth directory unavailable");
                    (
                        AuthResult::Deny(401, "bot_auth: directory unavailable".to_string()),
                        None,
                    )
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
                Err(_) => {
                    return (AuthResult::Deny(500, "cap: bad request".to_string()), None);
                }
            };
            *req.headers_mut() = headers.clone();
            // WOR-1149: the resolved agent id from the agent-class
            // resolver chain is now threaded in, so the verifier
            // enforces the CAP `sub` binding (and fails closed when
            // `require_agent_binding` is set but no id resolved).
            // WOR-808: emit RSL 1.0 CAP `WWW-Authenticate: License`
            // challenge on 401/403 so a crawler discovers the auth
            // scheme + the specific error code. The challenge mirrors
            // RFC 6750's bearer format: a bare `License` on a missing
            // token; `License error="<code>"` on an invalid one, with
            // the code coming from `CapError::www_auth_code()` (e.g.
            // `invalid_token`, `path_not_authorized`).
            match verifier.verify(&req, &host, path, resolved_agent_id) {
                CapVerdict::Verified(_view) => {
                    let principal = sbproxy_plugin::Principal {
                        tenant_id: tenant_id.clone(),
                        sub: String::new(),
                        source: sbproxy_plugin::PrincipalSource::Cap,
                        virtual_key: None,
                        attrs: sbproxy_plugin::PrincipalAttrs::default(),
                    };
                    (AuthResult::allow_anonymous(), Some(principal))
                }
                CapVerdict::Missing => (
                    AuthResult::DenyWithHeaders(
                        401,
                        "cap: token required".to_string(),
                        vec![("WWW-Authenticate".to_string(), "License".to_string())],
                    ),
                    None,
                ),
                CapVerdict::Invalid(err) => {
                    let status = err.http_status();
                    let code = err.www_auth_code();
                    (
                        AuthResult::DenyWithHeaders(
                            status,
                            format!("cap: {}", code),
                            vec![(
                                "WWW-Authenticate".to_string(),
                                format!("License error=\"{code}\""),
                            )],
                        ),
                        None,
                    )
                }
            }
        }
        Auth::Noop => (
            AuthResult::allow_anonymous(),
            Some(sbproxy_plugin::Principal::anonymous_for(tenant_id.clone())),
        ),
        Auth::Oidc(cfg) => {
            let result = oidc_check(cfg.as_ref(), headers);
            // The OIDC happy path stamps the principal on `Allow`;
            // pull the sub off the AuthResult before we return so
            // the call site can copy the full principal onto ctx.
            let principal = if let AuthResult::Allow { sub: Some(sub), .. } = &result {
                Some(cfg.to_principal(sub.clone(), tenant_id.clone()))
            } else {
                None
            };
            (result, principal)
        }
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
                    return (
                        AuthResult::Deny(
                            500,
                            format!(
                                "auth plugin {:?}: failed to build request",
                                provider.auth_type()
                            ),
                        ),
                        None,
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
                    // WOR-1047 PR2: build a minimal Principal for
                    // out-of-tree plugins so the access-log + policy
                    // pipeline sees the same shape every built-in
                    // provider produces. Plugins that want richer
                    // attribution will move to the principal-only
                    // return type in the final PR of the credentials
                    // epic; until then `attrs` is empty.
                    let principal = sbproxy_plugin::Principal {
                        tenant_id: tenant_id.clone(),
                        sub: sub.clone().unwrap_or_default(),
                        source: sbproxy_plugin::PrincipalSource::Plugin,
                        virtual_key: None,
                        attrs: sbproxy_plugin::PrincipalAttrs::default(),
                    };
                    (AuthResult::Allow { sub, source }, Some(principal))
                }
                Ok(sbproxy_plugin::AuthDecision::Deny { status, message }) => {
                    (AuthResult::Deny(status, message), None)
                }
                Ok(sbproxy_plugin::AuthDecision::DenyWithHeaders {
                    status,
                    message,
                    headers,
                }) => (AuthResult::DenyWithHeaders(status, message, headers), None),
                Err(err) => {
                    tracing::warn!(
                        plugin = %provider.auth_type(),
                        error = %err,
                        "auth plugin returned error; denying request",
                    );
                    (
                        AuthResult::Deny(
                            500,
                            format!("auth plugin {:?} error", provider.auth_type()),
                        ),
                        None,
                    )
                }
            }
        }
    }
}

/// Lazily-initialized HTTP client for forward-auth subrequests. A
/// single pooled client across all requests avoids the per-request
/// socket and TLS-handshake cost of constructing a fresh
/// `reqwest::Client`. The per-call `fwd.timeout` is applied as a
/// request-scoped deadline below. The outer client-level timeout
/// (default 30s) reads from
/// `proxy.http_client_timeouts.forward_auth_client_secs` on first use.
static FORWARD_AUTH_CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();

fn forward_auth_client() -> &'static reqwest::Client {
    FORWARD_AUTH_CLIENT.get_or_init(|| {
        let secs = reload::current_pipeline()
            .config
            .server
            .http_client_timeouts
            .forward_auth_client_secs;
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(secs))
            .build()
            .expect("forward-auth reqwest::Client build must succeed")
    })
}

/// Lazily-initialized HTTP client for dynamic Web Bot Auth directory
/// lookups. Directory fetches have their own 2s deadline inside
/// `sbproxy-modules`; this client-level timeout is a conservative
/// outer guard and shares connections across requests. Reads from
/// `proxy.http_client_timeouts.bot_auth_directory_client_secs`
/// (default 5s) on first use.
static BOT_AUTH_DIRECTORY_CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();

fn bot_auth_directory_client() -> &'static reqwest::Client {
    BOT_AUTH_DIRECTORY_CLIENT.get_or_init(|| {
        let secs = reload::current_pipeline()
            .config
            .server
            .http_client_timeouts
            .bot_auth_directory_client_secs;
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(secs))
            .build()
            .expect("bot-auth directory reqwest::Client build must succeed")
    })
}

/// Run forward auth by making an HTTP subrequest to the auth service.
async fn check_forward_auth(
    fwd: &sbproxy_modules::auth::ForwardAuthProvider,
    request_headers: &http::HeaderMap,
) -> std::result::Result<Vec<(String, String)>, (u16, String)> {
    let client = forward_auth_client();
    let default_request_secs = reload::current_pipeline()
        .config
        .server
        .http_client_timeouts
        .forward_auth_request_secs;
    let timeout = std::time::Duration::from_secs(fwd.timeout.unwrap_or(default_request_secs));

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
    .with_tenant_id(ctx.tenant_id.to_string())
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

/// Audit-bus correlation context for one policy decision.
///
/// Filled at the dispatcher entry and reused for every policy in the
/// chain so [`emit_policy_verdict`] does not re-derive identifiers
/// per arm.
#[derive(Clone)]
struct PolicyVerdictCtx {
    request_id: String,
    tenant_id: String,
    workspace_id: String,
}

/// Try to publish a [`sbproxy_observe::events::PolicyVerdictEvent`]
/// for one policy decision.
///
/// Drop-on-overflow per the audit-binding ADR: a full bus increments
/// `sbproxy_policy_audit_events_dropped_total{tenant}` and returns
/// silently. The hot path never blocks on the bus.
fn emit_policy_verdict(
    ctx: &PolicyVerdictCtx,
    policy_id: &str,
    surface: sbproxy_observe::events::PolicySurface,
    verdict: sbproxy_observe::events::VerdictTag,
    decision_started: std::time::Instant,
) {
    let elapsed = decision_started.elapsed();
    let elapsed_ms = elapsed.as_millis().min(u32::MAX as u128) as u32;
    sbproxy_observe::metrics::record_policy_decision_latency(
        surface.as_label(),
        elapsed.as_secs_f64(),
    );
    sbproxy_observe::metrics::record_policy_audit_emitted(
        verdict.as_label(),
        surface.as_label(),
        policy_id,
    );
    // WOR-75: stamp an exemplar on the policy-evaluation histogram so
    // dashboards can hop from a slow-policy bucket to the originating
    // trace. The hostname dimension is the request's tenant
    // workspace_id (the OSS tenant proxy); verdict is the closed
    // allow/deny/confirm label already on the audit bus.
    sbproxy_observe::metrics::record_policy_evaluation_duration(
        &ctx.workspace_id,
        verdict.as_label(),
        elapsed.as_secs_f64(),
    );
    let event = sbproxy_observe::events::PolicyVerdictEvent::new(
        uuid::Uuid::new_v4(),
        ctx.request_id.clone(),
        ctx.tenant_id.clone(),
        ctx.workspace_id.clone(),
        chrono::Utc::now(),
        policy_id.to_string(),
        surface,
        verdict,
        elapsed_ms,
    );
    if let Err(_dropped) = crate::policy_bus::try_publish(event) {
        // Bus full or not yet installed; the dropped-events metric
        // is the paging signal per
        // `docs/adr-policy-audit-binding.md`. Tenant label uses the
        // workspace id as the OSS-scope tenant proxy.
        sbproxy_observe::metrics::record_policy_audit_event_dropped(&ctx.workspace_id);
    }
}

/// Build a frozen `http::Request<bytes::Bytes>` snapshot of the
/// inbound request for a `PolicyEnforcer` call.
///
/// `PolicyEnforcer::enforce` takes an immutable request reference;
/// this helper materialises one from the Pingora session so the
/// existing built-in arms can keep their `Session` view while
/// plugin enforcers see the standard `http` types.
fn build_plugin_request_snapshot(session: &Session) -> Option<http::Request<bytes::Bytes>> {
    let req = session.req_header();
    let method = req.method.as_str();
    let path_and_query = req
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let builder = http::Request::builder().method(method).uri(path_and_query);
    let mut built = builder.body(bytes::Bytes::new()).ok()?;
    *built.headers_mut() = req.headers.clone();
    Some(built)
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

/// Read the effective policy-type label that the response handler
/// should use to choose its response shape.
///
/// Prefers [`RequestContext::deny_policy_type`], which the built-in
/// enforcer wrappers stamp with their stable policy_type label
/// (`rate_limit`, `waf`, `ip_filter`, ...) before short-circuiting.
/// Falls back to the dispatcher-supplied `"plugin"`-family label for
/// the Plugin and dispatcher-synthesised paths that never set the
/// slot.
#[inline]
fn effective_policy_type(ctx: &RequestContext, fallback: &'static str) -> &'static str {
    ctx.deny_policy_type.unwrap_or(fallback)
}

/// Run every enforcer for an origin in chain order. Returns `None`
/// when every enforcer allowed the request, or `Some((status,
/// message, fallback_policy_type))` for the first deny.
///
/// The fallback label is the `"plugin"`-family string produced by
/// [`crate::policy_dispatch::translate_plugin_decision`]. Caller
/// code threads it through [`effective_policy_type`], which prefers
/// the per-request slot [`RequestContext::deny_policy_type`] set by
/// the built-in enforcer wrappers (`rate_limit`, `waf`, `ip_filter`,
/// ...). The slot wins because the wrappers stamp their stable
/// policy_type label there before short-circuiting; the plugin
/// fallback only surfaces when no slot was set, which is the case
/// for `Policy::Plugin` enforcers and dispatcher-synthesised denies.
///
/// Async because rate-limit enforcers attached to an L2 (Redis)
/// store call `allow_with_info_async`, which `spawn_blocking`s the
/// Redis INCR. Local-only token-bucket rate limiters short-circuit
/// synchronously without hitting the runtime.
///
/// `verdict_ctx` carries the request / tenant / workspace
/// identifiers reused for every
/// [`sbproxy_observe::events::PolicyVerdictEvent`] emitted from the
/// chain. Threading it as an argument keeps the dispatcher pure:
/// the audit-bus correlation is fixed at the dispatcher entry and
/// never re-derived inside the loop.
async fn check_policies(
    enforcers: &[crate::builtin_enforcers::CompiledEnforcer],
    session: &Session,
    ctx: &mut RequestContext,
    verdict_ctx: &PolicyVerdictCtx,
) -> Option<(u16, String, &'static str)> {
    use sbproxy_observe::events::VerdictTag;

    // Materialise the request snapshot once. Built-in wrappers and
    // plugin enforcers share this view; the session-specific data
    // they need (client_ip, hostname, rate_limit_info) lives on
    // `RequestContext` and is threaded through the `&mut Any`
    // downcast inside each `enforce()` body.
    let req_snapshot = match build_plugin_request_snapshot(session) {
        Some(r) => r,
        None => {
            // Fail-closed: a request that cannot be materialised
            // into the trait's snapshot is denied with the same
            // generic plugin-style label the WOR-201 PR 1b
            // dispatcher used for malformed requests.
            return Some((500, "policy: bad request".to_string(), "plugin"));
        }
    };

    let mut confirm_state = crate::policy_dispatch::ConfirmReducerState::default();

    for compiled in enforcers {
        let policy_id = compiled.enforcer.policy_type().to_string();
        let started = std::time::Instant::now();
        let surface = compiled.surface;
        let ctx_any: &mut dyn std::any::Any = ctx;
        let decision = match compiled.enforcer.enforce(&req_snapshot, ctx_any).await {
            Ok(d) => d,
            Err(err) => {
                tracing::warn!(
                    target: "sbproxy::policy",
                    error = %err,
                    policy = %policy_id,
                    "policy enforce() returned error; treating as deny"
                );
                emit_policy_verdict(verdict_ctx, &policy_id, surface, VerdictTag::Deny, started);
                return Some((500, "policy error".to_string(), "plugin"));
            }
        };
        let translated = crate::policy_dispatch::translate_plugin_decision(
            decision,
            &mut ctx.policy_response_headers,
            &mut confirm_state,
        );
        emit_policy_verdict(
            verdict_ctx,
            &policy_id,
            surface,
            translated.verdict,
            started,
        );
        if let Some(deny) = translated.deny {
            return Some(deny);
        }
    }

    None
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
fn lua_response_modifier(
    script: &str,
    status: u16,
    response_headers: &serde_json::Map<String, serde_json::Value>,
    ctx: &RequestContext,
) -> anyhow::Result<Vec<(String, String)>> {
    use sbproxy_extension::lua::LuaEngine;

    let engine = LuaEngine::new()?;

    let resp_table = serde_json::json!({
        "status_code": status,
        "headers": response_headers,
    });
    let ctx_table = script_modifier_context(ctx);

    // Try the Rust format first (modify_response returning {set_headers: {...}}).
    let result = engine.call_function(
        script,
        "modify_response",
        vec![resp_table.clone(), ctx_table.clone()],
    );

    let mut headers_to_set = Vec::new();
    match result {
        Ok(result) => {
            headers_to_set.extend(response_modifier_headers(&result, response_headers));
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

/// Execute a JavaScript response modifier script.
///
/// The script defines `modify_response(resp, ctx)` and returns either
/// `{set_headers: {...}}` or the mutated `resp` object with changed
/// `resp.headers` entries.
fn js_response_modifier(
    script: &str,
    status: u16,
    response_headers: &serde_json::Map<String, serde_json::Value>,
    ctx: &RequestContext,
) -> anyhow::Result<Vec<(String, String)>> {
    let engine = sbproxy_extension::js::JsEngine::new()?;

    let resp_table = serde_json::json!({
        "status_code": status,
        "headers": response_headers,
    });
    let ctx_table = script_modifier_context(ctx);

    let result = engine.call_function(script, "modify_response", vec![resp_table, ctx_table])?;
    Ok(response_modifier_headers(&result, response_headers))
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
//
// Webhook/callback/mirror dispatch lives in the `callbacks`
// submodule. The glob re-import keeps call sites unchanged.
mod callbacks;
use callbacks::*;

// --- AI proxy helpers ---
mod ai_support;
use ai_support::*;

mod ai_dispatch;
use ai_dispatch::*;

// --- Non-proxy action handlers ---

mod action_dispatch;
use action_dispatch::*;

// The ProxyHttp trait impl lives in the `proxy_http` submodule
//. A trait impl needs no re-import to take effect.
mod proxy_http;
mod request_phase;

// --- Access log emission helpers ---
//
// These live in the `access_log` submodule. The glob
// re-import keeps every existing call site in this file unchanged.
mod access_log;
use access_log::*;
mod custom_log;

mod lifecycle;
pub use lifecycle::*;

#[cfg(test)]
mod tests;
