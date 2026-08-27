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
///
/// WOR-2476: reads the `EgressPurpose::AiProvider` authorizer from
/// `sbproxy_security::egress`'s process-wide configured-gate registry and
/// attaches it via `with_egress` when one is installed. The registry is
/// populated by `lifecycle::arm_egress_gates_from_config`, which calls
/// this function itself (not a separate caller) immediately after
/// installing the registry, so this always reads the authorizer the
/// current config compiled (or `None`, preserving `AiClient`'s legacy
/// ungated contract, when `egress:` omits `ai_providers` or was never
/// configured at all). `arm_egress_gates_from_config` is the one seam
/// both `lifecycle::run` (boot) and the reload path call, specifically
/// so this function runs at boot and not only from the second config a
/// process ever loads.
pub fn reload_ai_client() {
    use sbproxy_security::egress::{configured_gate, EgressPurpose};

    let mut client = AiClient::new();
    if let Some(authorizer) = configured_gate(EgressPurpose::AiProvider) {
        client = client.with_egress(authorizer);
    }
    AI_CLIENT.store(std::sync::Arc::new(client));
}

/// The current AI client, for surfaces outside the request pipeline
/// (e.g. the admin chat playground) that need to dispatch a provider
/// call. Returns an owned snapshot safe to hold across an await.
pub(crate) fn ai_client() -> std::sync::Arc<AiClient> {
    AI_CLIENT.load_full()
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

/// Tracks background response-cache work so graceful shutdown can drain
/// it. Same `spawn` -> `close` -> `wait` pattern as [`WEBHOOK_TASKS`]
/// but a separate tracker so a slow upstream on one feature does not
/// stall the other.
///
/// Two producers: the stale-while-revalidate refresh, and the deferred
/// `cache.admit` evaluation plus its write-back in `proxy_http`. Both
/// carry a decision record as well as an entry, so dropping one at
/// shutdown loses evidence and not only a cache line (WOR-2404).
///
/// Worth knowing before relying on it: no caller invokes
/// [`shutdown_cache_revalidate_tasks`] today, so the tracker makes this
/// work *drainable* rather than drained. Registering here is still what
/// makes wiring the drain a one-line change instead of an audit of
/// every background spawn.
static CACHE_REVALIDATE_TASKS: std::sync::LazyLock<tokio_util::task::TaskTracker> =
    std::sync::LazyLock::new(tokio_util::task::TaskTracker::new);

/// Drain in-flight stale-while-revalidate background refreshes. Call
/// from the graceful-shutdown driver after listeners stop. New spawns
/// after this returns become no-ops.
pub async fn shutdown_cache_revalidate_tasks() {
    CACHE_REVALIDATE_TASKS.close();
    CACHE_REVALIDATE_TASKS.wait().await;
}

/// Pending semantic-cache write produced by a lookup that missed
/// (WOR-2099).
///
/// Tuple components: the compiled cache for the routed action, and the
/// private write token that lookup produced. The token carries the derived
/// namespace, prompt digest, normalized embedding, and generated keys, so
/// the eventual write cannot drift from the lookup that admitted it. When
/// populated, the buffered AI relay awaits `cache.store` once the provider
/// response has passed the status gate and the output guardrails.
type PendingEmbedMiss = (
    std::sync::Arc<sbproxy_ai::EmbeddingCache>,
    sbproxy_ai::SemanticWriteToken,
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
    // Advertise h2 in ALPN so clients can negotiate HTTP/2 over the mTLS
    // listener; without this the handshake only offers http/1.1.
    settings.enable_h2();
    let verifier = sbproxy_tls::mtls::build_client_cert_verifier(
        &mtls.client_ca_file,
        mtls.require,
        &mtls.allowed_cn_patterns,
        cache,
    )?;
    settings.set_client_cert_verifier(verifier);
    Ok(settings)
}

/// Build Pingora `TlsSettings` for a manual or ACME-bootstrap cert with HTTP/2
/// enabled. Pingora's convenience `add_tls(addr, cert, key)` only advertises
/// `http/1.1` in ALPN, so a plain `tls_cert_file` listener never negotiates h2.
/// Building the settings explicitly and calling `enable_h2()` adds `h2` to the
/// ALPN list, so clients get HTTP/2 over TLS and fall back to HTTP/1.1 when they
/// do not offer it.
fn build_tls_settings(
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<pingora_core::listeners::tls::TlsSettings> {
    let mut settings = pingora_core::listeners::tls::TlsSettings::intermediate(cert_path, key_path)
        .map_err(|e| anyhow::anyhow!("TlsSettings::intermediate: {e}"))?;
    settings.enable_h2();
    Ok(settings)
}

/// Build Pingora `TlsSettings` whose server cert is selected per handshake by
/// the ACME `CertResolver` (WOR-1772), via the forked
/// `TlsSettings::with_cert_resolver`. The resolver holds the live cert set, so
/// an ACME-issued or renewed cert is served immediately without rebuilding the
/// listener or restarting the process. h2 is advertised in ALPN.
fn build_tls_settings_with_resolver(
    resolver: std::sync::Arc<sbproxy_tls::cert_resolver::CertResolver>,
) -> anyhow::Result<pingora_core::listeners::tls::TlsSettings> {
    let mut settings = pingora_core::listeners::tls::TlsSettings::with_cert_resolver(resolver)
        .map_err(|e| anyhow::anyhow!("TlsSettings::with_cert_resolver: {e}"))?;
    settings.enable_h2();
    Ok(settings)
}

/// Like [`build_tls_settings_with_resolver`] but also attaches the mTLS client
/// certificate verifier, so an ACME listener that also requires client certs
/// still serves its cert dynamically (WOR-1772).
fn build_mtls_tls_settings_with_resolver(
    resolver: std::sync::Arc<sbproxy_tls::cert_resolver::CertResolver>,
    mtls: &sbproxy_config::MtlsListenerConfig,
    cache: sbproxy_tls::mtls::MtlsCertCacheHandle,
) -> anyhow::Result<pingora_core::listeners::tls::TlsSettings> {
    let mut settings = pingora_core::listeners::tls::TlsSettings::with_cert_resolver(resolver)
        .map_err(|e| anyhow::anyhow!("TlsSettings::with_cert_resolver: {e}"))?;
    settings.enable_h2();
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
/// Decide whether a failed transform's posture is the operator's call or
/// an unconditional host 500.
///
/// WOR-168 promotes any typed [`TransformError`] to a 500 regardless of
/// posture, on the grounds that it is a code-level bug or a misbehaving
/// plugin. WOR-2268 carves out one case. A dynamic bundle transform
/// declares its own posture in its manifest, and a guest that times out
/// or panics is precisely what that key describes, so the declaration
/// decides it. An `InvariantViolated` is still the host's own bug and
/// still a 500 either way.
///
/// All three response paths that run transforms consult this, so they
/// cannot drift apart: the upstream body filter, the plugin-action
/// response, and the locally generated (`static` / `mock`) body. The
/// third was added last and is the reason this sentence counts them:
/// for a while it read "both", and the path that did not consult this
/// served an invariant violation as a `200`.
///
/// [`TransformError`]: sbproxy_modules::transform::TransformError
pub(crate) fn transform_error_is_unconditional_500(
    compiled: &sbproxy_modules::CompiledTransform,
    error: &anyhow::Error,
) -> bool {
    use sbproxy_modules::transform::TransformError;
    let Some(typed) = error.downcast_ref::<TransformError>() else {
        return false;
    };
    let guest_declared_posture = matches!(typed, TransformError::Plugin { .. })
        && matches!(
            &compiled.transform,
            sbproxy_modules::Transform::Plugin(plugin) if plugin.dynamic_hook().is_some()
        );
    !guest_declared_posture
}

#[cfg(test)]
mod transform_failure_routing_tests {
    use super::transform_error_is_unconditional_500;
    use sbproxy_config::{BundleBodyMode, FailureMode};
    use sbproxy_modules::transform::TransformError;
    use sbproxy_modules::{CompiledTransform, DynamicHookMetadata, PluginTransform, Transform};
    use sbproxy_plugin::{TransformContext, TransformHandler};

    struct StubTransform;

    impl TransformHandler for StubTransform {
        fn transform_type(&self) -> &str {
            "stub_bundle_transform"
        }

        fn apply<'a>(
            &'a self,
            _body: &'a mut bytes::BytesMut,
            _content_type: Option<&'a str>,
            _ctx: &'a TransformContext,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = sbproxy_plugin::PluginResult<()>> + Send + 'a>,
        > {
            Box::pin(async { Ok(()) })
        }
    }

    fn compiled(transform: Transform) -> CompiledTransform {
        CompiledTransform {
            transform,
            content_types: Vec::new(),
            failure_posture: FailureMode::Open,
            max_body_size: 1024,
        }
    }

    fn dynamic() -> Transform {
        Transform::Plugin(PluginTransform::dynamic(
            Box::new(StubTransform),
            DynamicHookMetadata::new(
                "stub-bundle",
                "stub_bundle_transform",
                sbproxy_config::BundleRuntime::Wasm,
                BundleBodyMode::Buffered,
                1024,
                FailureMode::Open,
            ),
        ))
    }

    fn plugin_error() -> anyhow::Error {
        anyhow::Error::new(TransformError::Plugin {
            plugin: "stub_bundle_transform".to_owned(),
            detail: "timed out after 100ms".to_owned(),
        })
    }

    fn invariant_error() -> anyhow::Error {
        anyhow::Error::new(TransformError::InvariantViolated {
            reason: "body vanished".to_owned(),
        })
    }

    #[test]
    fn a_bundle_transforms_own_failure_follows_its_declared_posture() {
        assert!(!transform_error_is_unconditional_500(
            &compiled(dynamic()),
            &plugin_error()
        ));
    }

    #[test]
    fn a_host_invariant_violation_is_a_500_even_for_a_bundle() {
        assert!(transform_error_is_unconditional_500(
            &compiled(dynamic()),
            &invariant_error()
        ));
    }

    #[test]
    fn a_linked_plugin_keeps_the_unconditional_500() {
        // A linked plugin declares no posture, so WOR-168's original
        // rule is still the only one that can apply to it.
        let linked = Transform::Plugin(PluginTransform::linked(Box::new(StubTransform)));
        assert!(transform_error_is_unconditional_500(
            &compiled(linked),
            &plugin_error()
        ));
    }

    #[test]
    fn an_ordinary_config_error_was_never_a_typed_error() {
        assert!(!transform_error_is_unconditional_500(
            &compiled(Transform::Noop),
            &anyhow::anyhow!("bad regex")
        ));
    }
}

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
        Transform::Lua(t) => t.apply_with_context(body, script_modifier_context(ctx)),
        Transform::LuaJson(t) => t.apply_with_context(body, script_modifier_context(ctx)),
        Transform::JavaScript(t) => t.apply_with_context(body, script_modifier_context(ctx)),
        Transform::JsJson(t) => t.apply_with_context(body, script_modifier_context(ctx)),
        // WOR-2493 item 5: `request_context: true` is an explicit,
        // per-transform cacheability opt-in (see
        // `Transform::request_dependent`), so this arm only reaches
        // the ctx-carrying path when the operator asked for it. The
        // ctx-off default keeps hitting the wildcard arm below and
        // stays byte-identical to the pre-existing stdin-only
        // contract.
        Transform::Wasm(t) if t.request_context => {
            t.apply_with_context(body, script_modifier_context(ctx))
        }
        Transform::CelScript(t) => {
            // Wave 5 day-6 Item 1: typed dispatch for the CEL response
            // transform. The per-header `headers:` rules evaluate
            // against the live response context here and stash their
            // mutations onto `ctx` for the static action /
            // response_filter to stamp onto the outgoing response.
            //
            // WOR-2362: there is no body half any more. The
            // `on_response:` expression replaced the whole body with a
            // scalar and is refused at config compile, so header
            // mutation is the transform's entire output.
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
            // `anyhow::Error` so the body-buffer pipeline's typed-error
            // path takes over and synthesises a 500 with attribution.
            match t.evaluate_headers_with_request(
                body.as_ref(),
                status,
                &http::HeaderMap::new(),
                request_view,
            ) {
                Ok(mutations) => {
                    ctx.cel_response_header_mutations.extend(mutations);
                    Ok(())
                }
                Err(e) => Err(anyhow::Error::new(e)),
            }
        }
        Transform::A2aAgentCardRewrite(t) => {
            // WOR-2315: typed dispatch for the agent-card rewriter. The
            // standard `(body, content_type)` signature cannot carry the
            // request path the rewriter gates on, so the path is threaded
            // in from ctx here (stamped in `request_filter` alongside
            // `hostname`). Host precedence is the transform's documented
            // contract: the configured `proxy_host` wins, the inbound
            // `Host` header is the fallback so one deployment behind
            // several hostnames routes cleanly.
            let host = t.proxy_host.as_deref().unwrap_or(ctx.hostname.as_str());
            t.apply_with_path(body, content_type, ctx.request_path.as_str(), host)
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

/// Resolve the host a gateway-served A2A agent card advertises.
///
/// Same precedence contract as the `a2a_agent_card_rewrite` dispatch
/// arm in [`apply_transform_with_ctx`]: a `proxy_host` configured on
/// the origin's `a2a_agent_card_rewrite` transform wins, otherwise
/// the inbound `Host` header (already stripped of its port on
/// `ctx.hostname`) is used. Keeping the two surfaces on one contract
/// means a deployment that pins `proxy_host` advertises the same
/// hostname whether the card came from the operator's config or from
/// the upstream via the rewriter.
fn a2a_card_serve_host<'a>(
    transforms: &'a [sbproxy_modules::CompiledTransform],
    inbound_host: &'a str,
) -> &'a str {
    transforms
        .iter()
        .find_map(|compiled| match &compiled.transform {
            sbproxy_modules::Transform::A2aAgentCardRewrite(t) => t.proxy_host.as_deref(),
            _ => None,
        })
        .unwrap_or(inbound_host)
}

/// Render the operator-configured A2A agent card for serving.
///
/// Clones the stored card and swaps the hostnames on its `url`,
/// `endpoint`, and nested `agent.url` fields for `host` via the
/// rewriter's shared [`sbproxy_modules::rewrite_card_urls`] core, so
/// a card pasted with the upstream's own URL never leaks that URL to
/// a discovery client. Everything else serializes verbatim.
fn render_a2a_agent_card(card: &serde_json::Value, host: &str) -> Vec<u8> {
    let mut json = card.clone();
    sbproxy_modules::rewrite_card_urls(&mut json, host);
    // A `serde_json::Value` cannot fail to serialize; fall back to
    // the stored card's own rendering on the unreachable error arm
    // rather than panicking on the request path.
    serde_json::to_vec(&json).unwrap_or_else(|_| card.to_string().into_bytes())
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

/// Render `ctx.principal` as the JSON shape every script engine shares.
///
/// One call site for the whole request path, so the Lua `ctx.principal`
/// table, the JS `ctx.principal` object, and the CEL `principal.*`
/// namespace can never drift apart: all three are fed from the same
/// [`sbproxy_plugin::Principal`] on the live context.
fn principal_context_json(principal: &sbproxy_plugin::Principal) -> serde_json::Value {
    sbproxy_extension::js::build_principal_json(
        Some(principal.tenant_id.as_str()),
        (!principal.sub.is_empty()).then_some(principal.sub.as_str()),
        Some(principal.source.as_str()),
        principal.virtual_key.as_ref().map(|vk| vk.name.as_str()),
        principal
            .virtual_key
            .as_ref()
            .map(|vk| vk.allowed_providers.as_slice())
            .unwrap_or(&[]),
        principal.attrs.project.as_deref(),
        principal.attrs.user.as_deref(),
        principal.attrs.team.as_deref(),
        &principal.attrs.tags,
        &principal.attrs.metadata,
        &principal.attrs.roles,
        principal.attrs.claims.as_ref(),
    )
}

/// Build the shared `ctx` table handed to every Lua / JS script surface
/// (request modifiers, response modifiers, and the Lua/JS body
/// transforms, which all route through here).
///
/// Carries `request.aipref`, `request.tls`, and `principal`, mirroring
/// the CEL namespaces so a policy written for CEL ports across engines.
/// Absent signals render as empty strings / `false` rather than being
/// omitted, so a script can branch on `ctx.request.tls.ja4` or
/// `ctx.principal.attrs.team` without probing for presence first.
fn script_modifier_context(ctx: &RequestContext) -> serde_json::Value {
    let aipref = ctx.aipref.unwrap_or_default();
    let mut root = serde_json::json!({
        "request": {
            "aipref": {
                "train": aipref.train,
                "search": aipref.search,
                "ai_input": aipref.ai_input,
                "ai-input": aipref.ai_input,
            }
        }
    });
    // WOR-2083: the TLS fingerprint rides on the request sub-table so
    // scripts read `ctx.request.tls.ja4` exactly like the CEL surface.
    if let Some(request) = root.get_mut("request") {
        let fp = ctx.tls_fingerprint.as_ref();
        sbproxy_extension::lua::bindings::enrich_request_table_with_tls_fingerprint(
            request,
            fp.and_then(|f| f.ja3.as_deref()),
            fp.and_then(|f| f.ja4.as_deref()),
            fp.and_then(|f| f.ja4h.as_deref()),
            fp.is_some_and(|f| f.trustworthy),
        );
    }
    if let Some(map) = root.as_object_mut() {
        map.insert(
            "principal".to_string(),
            principal_context_json(&ctx.principal),
        );
    }
    root
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

/// Digest the caller a response-cache entry belongs to.
///
/// The credential identity is the one `semantic_credential_identity`
/// already builds for the semantic cache, deliberately rather than a
/// second selection order: two caches that disagree about who a caller
/// is would eventually disagree about which of them is right. The
/// `Cookie` header is folded in on top of it because an
/// upstream-managed session runs no auth provider at all, so every
/// caller in one resolves to the same anonymous principal.
///
/// Returns the empty string for a request presenting neither, which is
/// the key uncredentialed traffic had before this existed.
fn request_caller_identity(
    req: &pingora_http::RequestHeader,
    principal: &sbproxy_plugin::Principal,
) -> String {
    // A nested item rather than a closure: the borrow this returns comes
    // from `req` and not from `name`, and a closure has one inferred
    // signature for both.
    fn header<'a>(req: &'a pingora_http::RequestHeader, name: &str) -> Option<&'a str> {
        req.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
    }
    // `proxy-authorization` is a credential the same way `authorization`
    // is, and the semantic-cache selection does not look at it.
    let authorization = header(req, "authorization").or_else(|| header(req, "proxy-authorization"));
    let credential = sbproxy_ai::semantic_cache::semantic_credential_identity(
        principal.api_key_id(),
        principal.source.as_str(),
        principal.sub.as_str(),
        authorization,
    );
    // The sentinel is compared by name rather than by its spelling, and
    // it is flattened to the empty string here rather than recognized
    // in `sbproxy-cache`, which has no dependency on the crate that
    // owns it. A rename over there is then a compile error here instead
    // of a cache that silently stops distinguishing anonymous traffic.
    let resolved = if credential == sbproxy_ai::semantic_cache::SEMANTIC_ANONYMOUS_CREDENTIAL {
        ""
    } else {
        credential.as_str()
    };
    sbproxy_cache::caller_identity(resolved, header(req, "cookie"))
}

/// Build the canonical response-cache key for a request.
///
/// `workspace` is the empty string in OSS / single-tenant mode; the
/// enterprise crate populates it. `tenant` is the serving origin's
/// resolved tenant. `config_fp` is the serving origin's
/// [`cache_config_fingerprint`]. The result is the colon-delimited
/// shape documented at the top of `sbproxy_cache::response`.
///
/// [`cache_config_fingerprint`]: sbproxy_config::CompiledOrigin::cache_config_fingerprint
fn build_response_cache_key(
    workspace: &str,
    tenant: &str,
    hostname: &str,
    req: &pingora_http::RequestHeader,
    principal: &sbproxy_plugin::Principal,
    cfg: &sbproxy_config::ResponseCacheConfig,
    config_fp: &str,
) -> String {
    build_response_cache_key_with_plan(
        workspace, tenant, hostname, req, principal, cfg, config_fp, None,
    )
}

/// As [`build_response_cache_key`], with an optional `cache.key` plan
/// folded in.
///
/// The plan reaches **only** the vary fingerprint of
/// `v2:<workspace>:<tenant>:<hostname>:<method>:<path>:<identity>:<query>:<vary>:<config>`.
/// Every other field is stamped by the host from values the request
/// resolved to, whatever the event returns.
///
/// That is the whole poisoning defense, and it is structural rather than
/// advisory: a key policy that omits a dimension it should have included
/// serves one tenant's response to another, so there is deliberately no
/// document a policy can return that reaches the tenant, hostname, or
/// identity fields. It can narrow a key by adding dimensions; it cannot
/// widen one.
// Eight parameters, one over the threshold, and the eighth is the plan
// this function exists to fold in. Bundling the other seven into a
// struct would move the key's field list away from the code that
// renders it, which is the same reason `compute_cache_key` keeps its
// list flat.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_response_cache_key_with_plan(
    workspace: &str,
    tenant: &str,
    hostname: &str,
    req: &pingora_http::RequestHeader,
    principal: &sbproxy_plugin::Principal,
    cfg: &sbproxy_config::ResponseCacheConfig,
    config_fp: &str,
    plan: Option<&sbproxy_cache::cache_event::CacheKeyPlan>,
) -> String {
    let method = req.method.as_str();
    let path = req.uri.path();
    let query = req.uri.query();
    let identity = request_caller_identity(req, principal);
    let mode = query_mode_from_config(&cfg.query_normalize);
    // The host's own vary pair goes first, ahead of both the operator's
    // `vary:` and any plan, because the proxy forwards `Accept-Encoding`
    // and an upstream that compresses answers two differently
    // negotiating callers with different bytes. Bucketed rather than
    // taken raw so the dozen spellings of one capability set stay one
    // entry; see `sbproxy_cache::negotiated_encoding_bucket`. An
    // operator who also lists `accept-encoding` in `vary:` gets both,
    // which is redundant and harmless: it can only narrow.
    //
    // Prepending rather than appending keeps the operator's own entries
    // in their configured relative order, which
    // `the_operators_static_vary_order_is_not_reordered_by_a_plan`
    // pins.
    let mut vary = Vec::with_capacity(cfg.vary.len() + 1);
    vary.push((
        "accept-encoding".to_owned(),
        sbproxy_cache::negotiated_encoding_bucket(
            req.headers
                .get("accept-encoding")
                .and_then(|value| value.to_str().ok()),
        ),
    ));
    vary.extend(collect_vary_headers(req, &cfg.vary));
    if let Some(plan) = plan {
        // Added to the configured `vary:`, never replacing it: an
        // operator's static dimensions stay in the key whatever the
        // event says.
        // Appended in sorted order rather than sorting the merged list.
        //
        // `fold_into_vary` already sorts its own output, and
        // `vary_fingerprint` hashes pairs in order, so this gives the
        // property that matters, a declining policy and an absent one
        // produce the same key, without re-ordering the operator's
        // static `vary:` entries. Sorting the merged list would change
        // the key of every existing multi-entry `vary:` config on
        // deploy: a cold cache, an origin load spike, and with a Redis
        // or file store the old entries holding space until their TTLs
        // expire, none of which anything would have warned about.
        vary.extend(plan.fold_into_vary(
            |name| match name {
                "query" => query.unwrap_or_default().to_owned(),
                // Unreachable from a decoded plan: `decode_cache_key`
                // refuses every unprefixed name outside
                // `CACHE_VARY_HOST_DIMENSIONS`, and this arm covers the
                // same set.
                //
                // It resolves to the name itself rather than to the
                // empty string on purpose. An empty value is the
                // silently-partitions-nothing failure this whole design
                // refuses names to prevent, so if the two lists ever
                // drift, the dimension still varies the key by its own
                // name instead of quietly collapsing every caller into
                // one entry. A useless key beats a shared one.
                other => other.to_owned(),
            },
            |header| {
                req.headers
                    .get(header)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
            },
        ));
    }
    sbproxy_cache::compute_cache_key(
        workspace, tenant, hostname, method, path, &identity, query, &mode, &vary, config_fp,
    )
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

fn swr_cache_write_back(
    cache_store: &dyn sbproxy_cache::CacheStore,
    cache_key: &str,
    stale_entry: &sbproxy_cache::CachedResponse,
    refreshed_entry: &sbproxy_cache::CachedResponse,
) -> anyhow::Result<bool> {
    cache_store.compare_and_swap(cache_key, stale_entry, refreshed_entry)
}

#[derive(Debug, PartialEq, Eq)]
struct SwrRevalidationRequest {
    upstream_url: String,
    host_header: String,
    vary_headers: Vec<(String, String)>,
}

fn build_swr_revalidation_request(
    pipeline: &CompiledPipeline,
    origin_idx: usize,
    request: &pingora_http::RequestHeader,
    vary: &[String],
) -> Option<SwrRevalidationRequest> {
    let path = request.uri.path();
    let query = request.uri.query();
    // Revalidating against the wrong upstream writes that upstream's
    // response into this entry's key, so the preview walks the rules in
    // priority order and an ambiguous answer skips the refresh rather
    // than guessing. A later rule that previews clean is shadowed by an
    // earlier unevaluable one under first-match-wins.
    let rules = pipeline
        .forward_rules
        .get(origin_idx)
        .map_or(&[][..], Vec::as_slice);
    let action = match crate::pipeline::preview_forward_rules(
        rules,
        &request.method,
        path,
        query,
        &request.headers,
    ) {
        crate::pipeline::ForwardRulePreview::Matched(rule) => Some(&rule.action),
        crate::pipeline::ForwardRulePreview::NoMatch => pipeline.actions.get(origin_idx),
        crate::pipeline::ForwardRulePreview::Indeterminate => return None,
    }?;
    let Action::Proxy(proxy) = action else {
        return None;
    };
    let host_header = proxy.host_override.clone().or_else(|| {
        url::Url::parse(&proxy.url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string))
    })?;
    let vary_headers = vary
        .iter()
        .filter(|name| !name.eq_ignore_ascii_case("host"))
        .filter_map(|name| {
            let lower = name.to_ascii_lowercase();
            let value = request.headers.get(&lower)?.to_str().ok()?.to_string();
            Some((lower, value))
        })
        .collect();

    Some(SwrRevalidationRequest {
        upstream_url: proxy.url.trim_end_matches('/').to_string(),
        host_header,
        vary_headers,
    })
}

/// Spawn an async refresh of `cache_key` against the origin's upstream.
///
/// The entry is stale but still inside its SWR window. The caller has
/// already served it to the client; this dispatches a background
/// validation and refreshes the stored TTL on a `304 Not Modified`.
/// The task is registered with [`CACHE_REVALIDATE_TASKS`] so graceful
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
    stale_entry: sbproxy_cache::CachedResponse,
    ttl_secs: u64,
    revalidation_request: SwrRevalidationRequest,
    path_and_query: String,
    cacheable_status: Vec<u16>,
    pipeline: std::sync::Arc<crate::pipeline::CompiledPipeline>,
    origin_idx: usize,
    admit_scope: Option<crate::server::proxy_http::AdmitEventScope>,
) {
    let full_url = format!("{}{}", revalidation_request.upstream_url, path_and_query);

    CACHE_REVALIDATE_TASKS.spawn(async move {
        let Some(client) = swr_client() else {
            // The revalidation client could not be built (logged once at
            // init). SWR is best-effort, so skip the refresh and keep
            // serving the cached entry.
            return;
        };
        let mut request = client
            .get(&full_url)
            .header("host", &revalidation_request.host_header);
        for (name, value) in &revalidation_request.vary_headers {
            request = request.header(name, value);
        }
        if let Some(etag) = stale_entry
            .etag()
            .and_then(|value| reqwest::header::HeaderValue::from_str(value).ok())
        {
            request = request.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = stale_entry
            .last_modified()
            .and_then(|value| reqwest::header::HeaderValue::from_str(value).ok())
        {
            request = request.header(reqwest::header::IF_MODIFIED_SINCE, last_modified);
        }
        let resp = match request.send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    // The reqwest Display would repeat the URL the next
                    // field already carries, so it adds nothing and takes
                    // the redaction decision out of this line's hands.
                    error = %sbproxy_httpkit::request_error_summary(&e),
                    url = %full_url,
                    "swr: revalidation request failed"
                );
                return;
            }
        };
        let status = resp.status().as_u16();
        // Capture headers before consuming a successful response body.
        // `freshen_from_not_modified` applies the stricter 304 merge
        // rules, including preserving the stored Content-Length.
        let mut headers: Vec<(String, String)> = Vec::with_capacity(resp.headers().len());
        for (name, value) in resp.headers() {
            let n = name.as_str().to_ascii_lowercase();
            if let Ok(v) = value.to_str() {
                headers.push((n, v.to_string()));
            }
        }
        let refreshed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if status == 304 {
            let refreshed = stale_entry.freshen_from_not_modified(&headers, refreshed_at, ttl_secs);
            let _ = tokio::task::spawn_blocking(move || {
                match swr_cache_write_back(
                    cache_store.as_ref(),
                    &cache_key,
                    &stale_entry,
                    &refreshed,
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::debug!("swr: stale 304 write-back lost a generation race")
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "swr: 304 write-back to cache failed")
                    }
                }
            })
            .await;
            return;
        }

        let connection_fields: Vec<String> = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
            .flat_map(|(_, value)| value.split(','))
            .map(|name| name.trim().to_ascii_lowercase())
            .filter(|name| !name.is_empty())
            .collect();
        headers.retain(|(name, _)| {
            !matches!(
                name.as_str(),
                "connection"
                    | "transfer-encoding"
                    | "keep-alive"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailer"
                    | "upgrade"
                    | "x-sbproxy-cache"
            ) && !connection_fields
                .iter()
                .any(|connection_name| connection_name.eq_ignore_ascii_case(name))
        });

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

        // A revalidation response is buffered before write-back. Cap it
        // so an origin cannot make the background path consume unbounded
        // memory. Oversized refreshes leave the stale entry untouched.
        const MAX_SWR_CACHE_BODY_BYTES: usize = 64 * 1024 * 1024;
        if resp
            .content_length()
            .is_some_and(|length| length > MAX_SWR_CACHE_BODY_BYTES as u64)
        {
            tracing::warn!(
                url = %full_url,
                cap = MAX_SWR_CACHE_BODY_BYTES,
                "swr: refresh Content-Length exceeds cache body cap"
            );
            return;
        }
        let mut body = Vec::new();
        let mut body_stream = resp.bytes_stream();
        while let Some(chunk) = body_stream.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(e) => {
                    // Same reqwest Display, same trailing URL (WOR-2629).
                    let summary = sbproxy_httpkit::request_error_summary(&e);
                    tracing::warn!(error = %summary, "swr: failed to read refresh body");
                    return;
                }
            };
            if body.len().saturating_add(chunk.len()) > MAX_SWR_CACHE_BODY_BYTES {
                tracing::warn!(
                    url = %full_url,
                    cap = MAX_SWR_CACHE_BODY_BYTES,
                    "swr: refresh body exceeds cache body cap"
                );
                return;
            }
            body.extend_from_slice(&chunk);
        }

        // Ingest transforms (WOR-2417): the entry must hold the
        // transform chain's output, exactly as the live store path
        // does, or a refresh would quietly swap a transformed body
        // for a raw one. Every transform on a cached origin is
        // request-independent by construction (config load refuses
        // the combination otherwise), so the context-free apply path
        // is sufficient here, where no request exists.
        let transforms = pipeline
            .transforms
            .get(origin_idx)
            .map_or(&[][..], Vec::as_slice);
        if !transforms.is_empty() {
            let content_type_owned = headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                .map(|(_, value)| value.clone());
            let content_type = content_type_owned.as_deref();
            let mut buf = bytes::BytesMut::from(&body[..]);
            for compiled in transforms {
                if !compiled.matches_content_type(content_type) {
                    continue;
                }
                if buf.len() > compiled.max_body_size {
                    // The live path passes an oversized body through
                    // untransformed and, on a cached origin, stores
                    // nothing; the refresh mirrors that by keeping the
                    // stale entry.
                    tracing::warn!(
                        url = %full_url,
                        transform = compiled.transform.transform_type(),
                        cap = compiled.max_body_size,
                        "swr: refresh body exceeds a transform cap, leaving stale"
                    );
                    return;
                }
                if let Err(error) = compiled.transform.apply(&mut buf, content_type) {
                    match compiled.failure_posture {
                        sbproxy_config::FailureMode::Closed => {
                            // The live path refuses the response; with
                            // no response to refuse, the refresh keeps
                            // the stale entry and lets it age out.
                            tracing::warn!(
                                url = %full_url,
                                transform = compiled.transform.transform_type(),
                                error = %error,
                                "swr: closed transform failed on refresh, leaving stale"
                            );
                            return;
                        }
                        _ => {
                            tracing::warn!(
                                url = %full_url,
                                transform = compiled.transform.transform_type(),
                                error = %error,
                                "swr: transform failed on refresh, continuing with next"
                            );
                        }
                    }
                }
            }
            body = buf.to_vec();
            // The refresh response's Content-Length describes the raw
            // upstream body; the chain may have changed the length,
            // and a stored header that disagrees with the stored body
            // truncates every later hit. The live path strips it for
            // transformed origins before its header snapshot; mirror
            // that here.
            headers.retain(|(name, _)| !name.eq_ignore_ascii_case("content-length"));
        }

        // WOR-2367: the refresh runs the origin's `admit_event` against
        // the response it just fetched. Without this the refresh writes
        // back with the static `ttl_secs` and stores whatever it got,
        // silently reverting both the event's TTL override and any
        // response the event refused, which is why the two used to be
        // refused together at config load.
        //
        // The refresh serves nobody, so a refusal here is not a
        // fail-open: the stale entry simply stays until it ages out.
        let mut ttl_secs = ttl_secs;
        // Preserves the window the stale entry was admitted with when
        // the refresh runs no event, so a refresh does not quietly
        // revert to the origin's default.
        let mut swr_secs = stale_entry.swr_secs;
        if let Some(scope) = admit_scope.as_ref() {
            // WOR-2404: the event is an operator script with a CPU
            // budget and no await points, and this task shares a reactor
            // with live request traffic. Running it inline here stalls
            // that traffic for the script's whole budget, on a refresh
            // nobody is waiting for, so it goes to the blocking pool.
            let admit_pipeline = pipeline.clone();
            let admit_scope_owned = scope.clone();
            let admit_headers = headers.clone();
            let admit_body_len = body.len();
            let plan = match tokio::task::spawn_blocking(move || {
                crate::server::proxy_http::evaluate_cache_admit_for(
                    &admit_pipeline,
                    &admit_scope_owned,
                    status,
                    &admit_headers,
                    admit_body_len,
                )
            })
            .await
            {
                Ok(plan) => plan,
                Err(join_error) => {
                    // The refresh serves nobody, so a lost evaluation
                    // keeps the stale entry rather than writing back
                    // under a plan that was never computed. The live
                    // path fails open here because a client is waiting;
                    // this one has no client to fail open for.
                    tracing::warn!(
                        error = %join_error,
                        "swr: admit_event evaluation task failed to join; keeping the stale entry"
                    );
                    return;
                }
            };
            if !plan.store {
                tracing::debug!(
                    url = %full_url,
                    reason = plan.reason.as_str(),
                    "swr: admit_event refused the refreshed response; keeping the stale entry"
                );
                return;
            }
            if let Some(override_ttl) = plan.ttl_secs {
                ttl_secs = override_ttl;
            }
            swr_secs = plan.swr_secs;
        }

        let entry = sbproxy_cache::CachedResponse {
            generation: sbproxy_cache::new_cache_generation(),
            status,
            headers,
            body,
            cached_at: refreshed_at,
            ttl_secs,
            swr_secs,
            // WOR-2407: a refresh replaces the exact entry it observed,
            // under the same key, so it inherits that entry's config
            // identity rather than re-deriving one. `compare_and_swap`
            // compares against `stale_entry`, so the two must agree.
            config_fp: stale_entry.config_fp.clone(),
        };
        // Write-back goes through spawn_blocking for the same reason
        // the live path does: blocking I/O for the Redis backend.
        let _ = tokio::task::spawn_blocking(move || {
            match swr_cache_write_back(cache_store.as_ref(), &cache_key, &stale_entry, &entry) {
                Ok(true) => {}
                Ok(false) => tracing::debug!("swr: stale write-back lost a generation race"),
                Err(e) => tracing::warn!(error = %e, "swr: write-back to cache failed"),
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
    let metadata = sbproxy_cache::ReserveMetadata::from_cached_response(entry, now, expires_at);

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

    sbproxy_util::truncate_utf8_with_marker(&cleaned, REDACTED_FIELD_CAP, "...").into_owned()
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

/// Value of `SBPROXY_E2E_HARNESS_TOKEN`, read once and cached for the
/// life of the process.
///
/// Only the e2e test harness (`e2e/src/lib.rs`) sets this, on the
/// spawned proxy child's own environment; it is never set in
/// production. When present, both `proxy_http::response_filter` (the
/// normal upstream-relay path) and `send_response` below (the
/// short-circuit path used for the proxy's own synthetic responses,
/// including the unmatched-Host 404) echo it back on every response
/// via `x-sbproxy-e2e-harness-token` (WOR-2295). That lets a
/// harness's readiness probe confirm a response came from the child
/// it spawned rather than a different, concurrently-starting test's
/// proxy that raced it for the same ephemeral port. Defined here
/// rather than in `proxy_http` so `send_response` can reach it
/// directly; `proxy_http` picks it up unqualified via `use super::*;`.
fn e2e_harness_token() -> Option<&'static str> {
    static TOKEN: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    TOKEN
        .get_or_init(|| {
            std::env::var("SBPROXY_E2E_HARNESS_TOKEN")
                .ok()
                .filter(|v| !v.is_empty())
        })
        .as_deref()
}

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
    send_response_with_extra_headers(session, status, content_type, body, &[]).await
}

/// [`send_response`] plus caller-supplied response headers appended
/// after the framing ones.
///
/// Header names and values are copied verbatim. An entry the header
/// builder refuses is skipped with a warning rather than failing the
/// whole response, so one malformed challenge from a third-party auth
/// provider cannot turn a 401 into a dropped connection.
///
/// Named `_extra_` rather than mirroring `request_phase`'s own
/// `send_response_with_headers`: that one is a separate, stricter
/// helper for the introspect 401, and `request_phase` glob-imports this
/// module, so two identical names would shadow.
async fn send_response_with_extra_headers(
    session: &mut Session,
    status: u16,
    content_type: &str,
    body: &[u8],
    extra_headers: &[(String, String)],
) -> Result<()> {
    let mut header = pingora_http::ResponseHeader::build(status, Some(2 + extra_headers.len()))
        .map_err(|e| {
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
    for (name, value) in extra_headers {
        if let Err(e) = header.append_header(name.clone(), value) {
            warn!(
                header_name = %name,
                error = %e,
                "error response carried an invalid header; skipping",
            );
        }
    }
    // WOR-2295: see `e2e_harness_token` above. The e2e harness's
    // readiness probe hits precisely this path on a freshly booted
    // proxy (its Host header matches no configured origin), so this
    // short-circuit response is the one that most needs the token.
    if let Some(token) = e2e_harness_token() {
        let _ = header.insert_header("x-sbproxy-e2e-harness-token", token);
    }
    session
        .write_response_header(Box::new(header), false)
        .await?;
    session
        .write_response_body(Some(bytes::Bytes::copy_from_slice(body)), true)
        .await?;
    Ok(())
}

/// Replay one complete idempotency-cache hit with the same framing cleanup
/// used by the early request-filter path.
async fn send_idempotency_cache_hit(
    session: &mut Session,
    cached: sbproxy_middleware::idempotency::CachedResponse,
) -> Result<u16> {
    let status = cached.status;
    let filtered_headers: Vec<(String, String)> = cached
        .headers
        .into_iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            lower != "content-length" && lower != "transfer-encoding" && lower != "connection"
        })
        .collect();
    let mut header = pingora_http::ResponseHeader::build(status, Some(filtered_headers.len() + 1))?;
    for (name, value) in filtered_headers {
        let _ = header.insert_header(name, value);
    }
    let _ = header.insert_header("x-sbproxy-idempotency", "HIT");
    session
        .write_response_header(Box::new(header), false)
        .await?;
    session
        .write_response_body(Some(bytes::Bytes::from(cached.body)), true)
        .await?;
    Ok(status)
}

/// Build a `{"error": "<message>"}` JSON body with the message
/// correctly escaped (WOR-1738).
///
/// The error message can carry client-controlled text (for example an
/// AI request's `model` field echoed back in a 403), so it must be
/// escaped rather than interpolated into a hand-built JSON string. A
/// quote or backslash in the message would otherwise break the envelope
/// or inject sibling fields.
/// Classify a resolved `security_headers` entry as a CSP emission, and in
/// which mode.
///
/// Both response paths (proxied and generated) call this on every header
/// the policy resolved so `sbproxy_security_headers_csp_emitted_total`
/// counts the header that actually reaches the client rather than the one
/// the config asked for. Those two were not the same thing before
/// WOR-2526, and the config file could not tell you which you had.
pub(super) fn csp_emission_mode(name: &str) -> Option<&'static str> {
    match name {
        "content-security-policy" => Some("enforce"),
        "content-security-policy-report-only" => Some("report_only"),
        _ => None,
    }
}

pub(super) fn error_json_body(message: &str) -> String {
    serde_json::json!({ "error": message }).to_string()
}

/// Send a JSON error response.
async fn send_error(session: &mut Session, status: u16, message: &str) -> Result<()> {
    let body = error_json_body(message);
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
    let body = error_json_body(message);
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
/// 3. The `{"error": message}` JSON default, written inline rather
///    than through `send_error` so the extra headers below reach
///    this branch too.
///
/// When multiple custom pages match a status and the client expresses
/// no concrete preference, JSON is preferred, then HTML, then the
/// first authored entry.
///
/// `extra_headers` are appended to whichever body wins. Every branch
/// gets them because a challenge and a body are independent choices:
/// authoring an `error_pages` 401 must not cost the origin its
/// `WWW-Authenticate` header, which is what a body-only emitter would
/// do (WOR-2525).
#[allow(clippy::too_many_arguments)]
async fn send_error_with_pages(
    session: &mut Session,
    status: u16,
    message: &str,
    error_pages: Option<&[sbproxy_config::ErrorPageEntry]>,
    problem_details: Option<&sbproxy_config::ProblemDetailsConfig>,
    request_path: &str,
    extra_headers: &[(String, String)],
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

            return send_response_with_extra_headers(
                session,
                status,
                &chosen.content_type,
                body.as_bytes(),
                extra_headers,
            )
            .await;
        }
    }

    // No custom page matched. Fall through to problem-details when enabled.
    if let Some(pd) = problem_details {
        if pd.enabled {
            let body = render_problem_details(status, message, pd, request_path);
            return send_response_with_extra_headers(
                session,
                status,
                "application/problem+json",
                body.as_bytes(),
                extra_headers,
            )
            .await;
        }
    }

    // No matching error page, no problem-details: the plain JSON
    // default, still carrying the challenge.
    let body = error_json_body(message);
    send_response_with_extra_headers(
        session,
        status,
        "application/json",
        body.as_bytes(),
        extra_headers,
    )
    .await
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
    /// Authentication passed, but the authenticated principal exhausted
    /// an auth-provider-owned request budget.
    RateLimited(sbproxy_modules::RateLimitInfo),
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

fn cap_principal_from_verified_token(
    tenant_id: sbproxy_plugin::TenantId,
    view: &sbproxy_modules::auth::CapTokenView,
) -> sbproxy_plugin::Principal {
    sbproxy_plugin::Principal {
        tenant_id,
        sub: view.subject.clone(),
        source: sbproxy_plugin::PrincipalSource::Cap,
        virtual_key: None,
        attrs: sbproxy_plugin::PrincipalAttrs::default(),
    }
}

/// Trust-specific outcome of an authentication attempt.
///
/// HTTP denials are not all evidence of hostile traffic. Missing credentials,
/// an interactive challenge, and verifier infrastructure failures remain
/// neutral; only a proof that was actually offered and failed verification is
/// load-bearing evidence for the `suspicious` tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthTrustOutcome {
    Allowed,
    Missing,
    Challenge,
    InvalidProof,
    BackendFailure,
}

impl AuthTrustOutcome {
    fn is_suspicious(self) -> bool {
        matches!(self, Self::InvalidProof)
    }

    /// Severity order for aggregating an OR composition's slots
    /// (WOR-2517): an offered-and-rejected credential outranks a
    /// backend failure, which outranks a neutral challenge, which
    /// outranks nothing offered at all. `Allowed` never aggregates
    /// because a success short-circuits the loop.
    fn severity(self) -> u8 {
        match self {
            Self::Allowed => 0,
            Self::Missing => 1,
            Self::Challenge => 2,
            Self::BackendFailure => 3,
            Self::InvalidProof => 4,
        }
    }
}

fn plugin_denial_trust_outcome(
    provider: &dyn sbproxy_plugin::AuthProvider,
    decision: &sbproxy_plugin::AuthDecision,
    status: u16,
) -> AuthTrustOutcome {
    if status >= 500 {
        return AuthTrustOutcome::BackendFailure;
    }

    match provider.denial_kind(decision) {
        sbproxy_plugin::AuthDenialKind::Challenge => AuthTrustOutcome::Challenge,
        sbproxy_plugin::AuthDenialKind::InvalidProof => AuthTrustOutcome::InvalidProof,
    }
}

fn api_key_was_offered(
    auth: &sbproxy_modules::auth::ApiKeyAuth,
    headers: &http::HeaderMap,
    query: Option<&str>,
) -> bool {
    if headers.contains_key(auth.header_name.as_str()) {
        return true;
    }
    let Some(param_name) = auth.query_param.as_deref() else {
        return false;
    };
    query.is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes()).any(|(name, _)| name == param_name)
    })
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
#[cfg(test)]
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
    // Test convenience over `check_auth_with_tls_outcome` for cases
    // that need neither the trust outcome nor a TLS-cert thumbprint.
    // `None` here means "no client cert presented", so a provider
    // configured with `require_mtls_bound = true` rejects (the
    // verifier treats `None` as "no TLS binding"). The production
    // caller in `request_phase` passes the session-derived
    // thumbprint instead.
    let (result, principal, _) = check_auth_with_tls_outcome(
        auth,
        headers,
        query,
        method,
        path,
        tenant_id,
        None,
        resolved_agent_id,
    )
    .await;
    (result, principal)
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

/// WOR-1074 + WOR-2316: the auth entry point for the request phase.
/// Threads the inbound TLS client cert's thumbprint through to the
/// [`MtlsBoundVerifier`](sbproxy_modules::auth::mtls_bound::MtlsBoundVerifier)
/// when a JWT provider has `require_mtls_bound = true` set.
///
/// `tls_cert_thumbprint` is the base64url-no-pad SHA-256 of the
/// end-entity DER (RFC 8705 `cnf.x5t#S256`); the production caller in
/// `request_phase` derives it from the session's TLS digest via
/// `client_cert_x5t_s256`. `None` means the connection presented no
/// client cert, so a bound token is rejected (fail closed) while
/// providers without `require_mtls_bound` are unaffected.
#[allow(clippy::too_many_arguments)]
async fn check_auth_with_tls_outcome(
    auth: &Auth,
    headers: &http::HeaderMap,
    query: Option<&str>,
    method: &str,
    path: &str,
    tenant_id: sbproxy_plugin::TenantId,
    tls_cert_thumbprint: Option<&str>,
    resolved_agent_id: Option<&str>,
) -> (
    AuthResult,
    Option<sbproxy_plugin::Principal>,
    AuthTrustOutcome,
) {
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
                Some(principal) => (
                    AuthResult::allow_anonymous(),
                    Some(principal),
                    AuthTrustOutcome::Allowed,
                ),
                None => (
                    AuthResult::Deny(401, "unauthorized".to_string()),
                    None,
                    if api_key_was_offered(a, headers, query) {
                        AuthTrustOutcome::InvalidProof
                    } else {
                        AuthTrustOutcome::Missing
                    },
                ),
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
                    AuthTrustOutcome::Allowed,
                )
            }
            None => (
                // WOR-2525: a Basic 401 without `WWW-Authenticate` is
                // not a Basic denial, it is an opaque one. RFC 9110
                // section 11.6.1 requires the challenge, and until this
                // arm carried it the origin's configured `realm` was
                // parsed and then dropped: no browser prompted and no
                // client learned which scheme to retry with. In an
                // `any_of` composition `check_any_of_auth`'s merge loop
                // reads the header off this variant, so the challenge
                // joins the composite 401 too.
                AuthResult::DenyWithHeaders(
                    401,
                    "unauthorized".to_string(),
                    vec![("WWW-Authenticate".to_string(), a.challenge())],
                ),
                None,
                if headers.contains_key(http::header::AUTHORIZATION) {
                    AuthTrustOutcome::InvalidProof
                } else {
                    AuthTrustOutcome::Missing
                },
            ),
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
                            AuthTrustOutcome::BackendFailure,
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
                        let outcome = if dpop_header.is_some() {
                            AuthTrustOutcome::InvalidProof
                        } else {
                            AuthTrustOutcome::Missing
                        };
                        return (
                            AuthResult::Deny(401, format!("DPoP verification failed: {err}")),
                            None,
                            outcome,
                        );
                    }
                }
                (
                    AuthResult::allow_anonymous(),
                    Some(principal),
                    AuthTrustOutcome::Allowed,
                )
            }
            None => (
                AuthResult::Deny(401, "unauthorized".to_string()),
                None,
                if headers.contains_key(http::header::AUTHORIZATION) {
                    AuthTrustOutcome::InvalidProof
                } else {
                    AuthTrustOutcome::Missing
                },
            ),
        },
        Auth::Jwt(a) => match a
            .check_request_with_claims(headers, tenant_id.clone())
            .await
        {
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
                            AuthTrustOutcome::InvalidProof,
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
                        let outcome = if dpop_header.is_some() {
                            AuthTrustOutcome::InvalidProof
                        } else {
                            AuthTrustOutcome::Missing
                        };
                        return (
                            AuthResult::Deny(401, format!("DPoP verification failed: {err}")),
                            None,
                            outcome,
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
                            if tls_cert_thumbprint.is_some() {
                                AuthTrustOutcome::InvalidProof
                            } else {
                                AuthTrustOutcome::Missing
                            },
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
                (auth_result, Some(principal), AuthTrustOutcome::Allowed)
            }
            None => (
                AuthResult::Deny(401, "unauthorized".to_string()),
                None,
                if headers.contains_key(http::header::AUTHORIZATION) {
                    AuthTrustOutcome::InvalidProof
                } else {
                    AuthTrustOutcome::Missing
                },
            ),
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
                            AuthTrustOutcome::Allowed,
                        )
                    }
                    None => {
                        let nonce = sbproxy_modules::auth::DigestAuth::generate_nonce();
                        (
                            AuthResult::DigestChallenge(d.challenge(&nonce)),
                            None,
                            AuthTrustOutcome::InvalidProof,
                        )
                    }
                }
            } else {
                let nonce = sbproxy_modules::auth::DigestAuth::generate_nonce();
                (
                    AuthResult::DigestChallenge(d.challenge(&nonce)),
                    None,
                    AuthTrustOutcome::Challenge,
                )
            }
        }
        Auth::Hmac(h) => {
            use sbproxy_modules::auth::HmacVerdict;
            // Synthesize the request shape the RFC 9421 verifier reads
            // method / target-uri / headers from, mirroring bot_auth.
            // The body is empty because auth runs before the body is
            // buffered, so the provider verifies with the deferring form
            // and the `content-digest` binding is completed against the
            // real body in the request body filter, armed by
            // `request_phase::arm_deferred_body_digest_binding`. Handing
            // these empty bytes to the enforcing form instead compares
            // the covered digest against zero bytes, which refuses an
            // honest client and admits one declaring the empty-body
            // digest.
            let target_uri = match query {
                Some(q) if !q.is_empty() => format!("{}?{}", path, q),
                _ => path.to_string(),
            };
            let builder = http::Request::builder().method(method);
            let mut req = match builder.uri(target_uri.as_str()).body(bytes::Bytes::new()) {
                Ok(r) => r,
                Err(_) => {
                    return (
                        AuthResult::Deny(500, "hmac_auth: bad request".to_string()),
                        None,
                        AuthTrustOutcome::BackendFailure,
                    );
                }
            };
            *req.headers_mut() = headers.clone();
            // The challenge names the scheme and nothing else: no key
            // id, no reason, and never any part of the credential.
            let challenge_headers =
                || vec![("WWW-Authenticate".to_string(), "Signature".to_string())];
            match h.verify(&req) {
                HmacVerdict::Verified { key_id } => {
                    match h.principal_for(&key_id, tenant_id.clone()) {
                        Some(principal) => {
                            let sub = principal.sub.clone();
                            (
                                AuthResult::Allow {
                                    sub: Some(sub),
                                    source: Some(sbproxy_plugin::AuthSubjectSource::Header),
                                },
                                Some(principal),
                                AuthTrustOutcome::Allowed,
                            )
                        }
                        // Unreachable (a verified key_id is in the map),
                        // but if the invariant ever breaks, fail closed.
                        None => (
                            AuthResult::DenyWithHeaders(
                                401,
                                "hmac_auth: verification failed".to_string(),
                                challenge_headers(),
                            ),
                            None,
                            AuthTrustOutcome::InvalidProof,
                        ),
                    }
                }
                HmacVerdict::Missing => (
                    AuthResult::DenyWithHeaders(
                        401,
                        "hmac_auth: signature required".to_string(),
                        challenge_headers(),
                    ),
                    None,
                    AuthTrustOutcome::Missing,
                ),
                HmacVerdict::UnknownKey { key_id } => {
                    // The key id is an identifier the client itself
                    // sent, safe to log; the client-facing message
                    // stays generic so probes cannot enumerate the
                    // configured key set.
                    tracing::warn!(key_id = %key_id, "hmac_auth: unknown key id");
                    (
                        AuthResult::DenyWithHeaders(
                            401,
                            "hmac_auth: verification failed".to_string(),
                            challenge_headers(),
                        ),
                        None,
                        AuthTrustOutcome::InvalidProof,
                    )
                }
                HmacVerdict::Failed { key_id, reason } => {
                    // Log the failure, never the credential: `reason`
                    // comes from the verifier's log-safe set and the
                    // client sees only the generic message.
                    tracing::warn!(key_id = %key_id, reason = %reason, "hmac_auth: verification failed");
                    (
                        AuthResult::DenyWithHeaders(
                            401,
                            "hmac_auth: verification failed".to_string(),
                            challenge_headers(),
                        ),
                        None,
                        AuthTrustOutcome::InvalidProof,
                    )
                }
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
            AuthTrustOutcome::Allowed,
        ),
        // WOR-2519: LDAP directory bind. Like forward_auth, this is an
        // outbound dial on the inbound path, but the provider needs only
        // the request headers, so it dispatches through this function
        // like every non-forward-auth type. An unreachable directory
        // fails closed with a 503 (mirroring forward_auth's
        // "auth service unavailable") and stays trust-neutral: a backend
        // failure is not evidence about the caller.
        Auth::Ldap(a) => {
            use sbproxy_modules::auth::ldap::LdapBindOutcome;
            match a.authenticate(headers).await {
                LdapBindOutcome::Allowed { username } => {
                    let principal = sbproxy_plugin::Principal {
                        tenant_id: tenant_id.clone(),
                        sub: username.clone(),
                        source: sbproxy_plugin::PrincipalSource::Ldap,
                        virtual_key: None,
                        attrs: sbproxy_plugin::PrincipalAttrs::default(),
                    };
                    (
                        AuthResult::Allow {
                            sub: Some(username),
                            source: Some(sbproxy_plugin::AuthSubjectSource::Header),
                        },
                        Some(principal),
                        AuthTrustOutcome::Allowed,
                    )
                }
                LdapBindOutcome::NoCredentials => (
                    AuthResult::Deny(401, "unauthorized".to_string()),
                    None,
                    AuthTrustOutcome::Missing,
                ),
                LdapBindOutcome::InvalidCredentials => (
                    AuthResult::Deny(401, "unauthorized".to_string()),
                    None,
                    AuthTrustOutcome::InvalidProof,
                ),
                LdapBindOutcome::DirectoryUnavailable => (
                    AuthResult::Deny(503, "auth directory unavailable".to_string()),
                    None,
                    AuthTrustOutcome::BackendFailure,
                ),
            }
        }
        Auth::BotAuth(b) => {
            use sbproxy_modules::auth::BotAuthVerdict;
            // Synthesize a minimal http::Request the verifier can read
            // method / target-uri / headers from. Verification runs
            // before the body is buffered, so we pass an empty body and
            // the provider uses the deferring verify form: a signature
            // covering `content-digest` is provisional here and its body
            // half is completed in the request body filter, against the
            // complete pre-transform body.
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
                        AuthTrustOutcome::BackendFailure,
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
                    (
                        AuthResult::allow_anonymous(),
                        Some(principal),
                        AuthTrustOutcome::Allowed,
                    )
                }
                BotAuthVerdict::Missing => (
                    AuthResult::Deny(401, "bot_auth: signature required".to_string()),
                    None,
                    AuthTrustOutcome::Missing,
                ),
                BotAuthVerdict::UnknownAgent { key_id } => (
                    AuthResult::Deny(401, format!("bot_auth: unknown agent keyid {}", key_id)),
                    None,
                    AuthTrustOutcome::InvalidProof,
                ),
                BotAuthVerdict::Failed { agent_name, reason } => {
                    let agent = agent_name.unwrap_or_else(|| "<unknown>".to_string());
                    tracing::warn!(agent = %agent, reason = %reason, "bot_auth verification failed");
                    (
                        AuthResult::Deny(401, "bot_auth: verification failed".to_string()),
                        None,
                        AuthTrustOutcome::InvalidProof,
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
                        AuthTrustOutcome::BackendFailure,
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
                    return (
                        AuthResult::Deny(500, "cap: bad request".to_string()),
                        None,
                        AuthTrustOutcome::BackendFailure,
                    );
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
                CapVerdict::Verified(view) => {
                    let principal = cap_principal_from_verified_token(tenant_id.clone(), &view);
                    (
                        AuthResult::allow_anonymous(),
                        Some(principal),
                        AuthTrustOutcome::Allowed,
                    )
                }
                CapVerdict::RateLimited(info) => {
                    let principal =
                        cap_principal_from_verified_token(tenant_id.clone(), &info.token);
                    (
                        AuthResult::RateLimited(sbproxy_modules::RateLimitInfo {
                            allowed: false,
                            limit: info.limit,
                            remaining: info.remaining,
                            reset_secs: info.reset_secs,
                            headers_enabled: true,
                            include_retry_after: true,
                            include_ratelimit_policy: false,
                        }),
                        Some(principal),
                        AuthTrustOutcome::Allowed,
                    )
                }
                CapVerdict::Missing => (
                    AuthResult::DenyWithHeaders(
                        401,
                        "cap: token required".to_string(),
                        vec![("WWW-Authenticate".to_string(), "License".to_string())],
                    ),
                    None,
                    AuthTrustOutcome::Missing,
                ),
                CapVerdict::Invalid(err) => {
                    let status = err.http_status();
                    let code = err.www_auth_code();
                    let trust_outcome =
                        if matches!(&err, sbproxy_modules::auth::CapError::DirectoryUnavailable) {
                            AuthTrustOutcome::BackendFailure
                        } else {
                            AuthTrustOutcome::InvalidProof
                        };
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
                        trust_outcome,
                    )
                }
            }
        }
        Auth::Noop => (
            AuthResult::allow_anonymous(),
            Some(sbproxy_plugin::Principal::anonymous_for(tenant_id.clone())),
            AuthTrustOutcome::Allowed,
        ),
        Auth::Oidc(cfg) => {
            let result = oidc_check(cfg.as_ref(), headers);
            let trust_outcome = match &result {
                AuthResult::Allow { .. } | AuthResult::RateLimited(_) => AuthTrustOutcome::Allowed,
                AuthResult::Deny(status, _) | AuthResult::DenyWithHeaders(status, _, _)
                    if *status >= 500 =>
                {
                    AuthTrustOutcome::BackendFailure
                }
                AuthResult::Deny(..)
                | AuthResult::DenyWithHeaders(..)
                | AuthResult::DigestChallenge(..) => AuthTrustOutcome::Challenge,
            };
            // The OIDC happy path stamps the principal on `Allow`;
            // pull the sub off the AuthResult before we return so
            // the call site can copy the full principal onto ctx.
            let principal = if let AuthResult::Allow { sub: Some(sub), .. } = &result {
                Some(cfg.to_principal(sub.clone(), tenant_id.clone()))
            } else {
                None
            };
            (result, principal, trust_outcome)
        }
        Auth::AnyOf(providers) => {
            // WOR-2517: OR composition. The winner's label is dropped
            // here because this signature predates composition; the
            // request phase calls `check_auth_decided` instead and
            // keeps it for attribution.
            let (result, principal, outcome, _provider) = check_any_of_auth(
                providers,
                headers,
                query,
                method,
                path,
                tenant_id,
                tls_cert_thumbprint,
                resolved_agent_id,
            )
            .await;
            (result, principal, outcome)
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
                        AuthTrustOutcome::BackendFailure,
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
                Ok(decision) => {
                    let trust_outcome = match &decision {
                        sbproxy_plugin::AuthDecision::Allow { .. } => AuthTrustOutcome::Allowed,
                        sbproxy_plugin::AuthDecision::Deny { status, .. }
                        | sbproxy_plugin::AuthDecision::DenyWithHeaders { status, .. } => {
                            plugin_denial_trust_outcome(provider.as_ref(), &decision, *status)
                        }
                    };

                    match decision {
                        sbproxy_plugin::AuthDecision::Allow { sub, source } => {
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
                            (
                                AuthResult::Allow { sub, source },
                                Some(principal),
                                trust_outcome,
                            )
                        }
                        sbproxy_plugin::AuthDecision::Deny { status, message } => {
                            (AuthResult::Deny(status, message), None, trust_outcome)
                        }
                        sbproxy_plugin::AuthDecision::DenyWithHeaders {
                            status,
                            message,
                            headers,
                            // `kind` already fed `trust_outcome` through
                            // `denial_kind`; the response only needs the wire fields.
                            kind: _,
                        } => (
                            AuthResult::DenyWithHeaders(status, message, headers),
                            None,
                            trust_outcome,
                        ),
                    }
                }
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
                        AuthTrustOutcome::BackendFailure,
                    )
                }
            }
        }
    }
}

/// WOR-2517: the auth entry point the request phase calls. Same
/// contract as [`check_auth_with_tls_outcome`] plus a fourth element:
/// the auth type that decided the request. For a single provider that
/// is its own type; for an [`Auth::AnyOf`] composition a success names
/// the winning slot's provider (so audit and decision records
/// attribute the request to the credential that actually
/// authenticated it), and exhaustion names the composite `any_of`.
#[allow(clippy::too_many_arguments)]
async fn check_auth_decided(
    auth: &Auth,
    headers: &http::HeaderMap,
    query: Option<&str>,
    method: &str,
    path: &str,
    tenant_id: sbproxy_plugin::TenantId,
    tls_cert_thumbprint: Option<&str>,
    resolved_agent_id: Option<&str>,
) -> (
    AuthResult,
    Option<sbproxy_plugin::Principal>,
    AuthTrustOutcome,
    String,
) {
    match auth {
        Auth::AnyOf(providers) => {
            check_any_of_auth(
                providers,
                headers,
                query,
                method,
                path,
                tenant_id,
                tls_cert_thumbprint,
                resolved_agent_id,
            )
            .await
        }
        single => {
            let (result, principal, outcome) = check_auth_with_tls_outcome(
                single,
                headers,
                query,
                method,
                path,
                tenant_id,
                tls_cert_thumbprint,
                resolved_agent_id,
            )
            .await;
            (result, principal, outcome, single.auth_type().to_string())
        }
    }
}

/// WOR-2517: evaluate an [`Auth::AnyOf`] composition.
///
/// Providers run in declared order through the same
/// [`check_auth_with_tls_outcome`] a scalar config uses, so each slot
/// behaves exactly as it would standing alone. The first `Allow` (or
/// CAP `RateLimited`, which is a recognized credential over its
/// budget) wins: its result, principal, and trust outcome return
/// unchanged, and no later provider runs. A slot that fails, however
/// it fails, loses only its own slot; evaluation continues.
///
/// Exhaustion follows the rule the WOR-2517 ticket argued from RFC
/// 7235: the first provider's status and message win (the first slot
/// is the origin's primary scheme by declaration), and every slot's
/// `WWW-Authenticate` challenge is merged onto the response in
/// declared order so a client learns every scheme the origin accepts.
/// The aggregate trust outcome is the most severe slot's, so one
/// offered-and-rejected credential marks the request suspicious even
/// when the other slots merely saw nothing.
#[allow(clippy::too_many_arguments)]
async fn check_any_of_auth(
    providers: &[Auth],
    headers: &http::HeaderMap,
    query: Option<&str>,
    method: &str,
    path: &str,
    tenant_id: sbproxy_plugin::TenantId,
    tls_cert_thumbprint: Option<&str>,
    resolved_agent_id: Option<&str>,
) -> (
    AuthResult,
    Option<sbproxy_plugin::Principal>,
    AuthTrustOutcome,
    String,
) {
    // First provider's denial, kept whole: status, message, and its
    // own headers (a digest challenge is folded into header form so it
    // can merge with the other slots' challenges).
    struct FirstDenial {
        status: u16,
        message: String,
        headers: Vec<(String, String)>,
    }
    let mut first_denial: Option<FirstDenial> = None;
    // Later slots' `WWW-Authenticate` values, in declared order.
    let mut merged_challenges: Vec<(String, String)> = Vec::new();
    let mut aggregate = AuthTrustOutcome::Missing;

    for provider in providers {
        // Boxed: async recursion (the composition evaluating its
        // members through the same entry point) needs a pinned future.
        let (result, principal, outcome) = Box::pin(check_auth_with_tls_outcome(
            provider,
            headers,
            query,
            method,
            path,
            tenant_id.clone(),
            tls_cert_thumbprint,
            resolved_agent_id,
        ))
        .await;

        let denial_headers: Vec<(String, String)> = match &result {
            // First success wins: bind the winning provider's
            // principal and name it for attribution. RateLimited is a
            // recognized credential (CAP over budget), so it decides
            // the request the same way an Allow does.
            AuthResult::Allow { .. } | AuthResult::RateLimited(_) => {
                return (result, principal, outcome, provider.auth_type().to_string());
            }
            AuthResult::Deny(..) => Vec::new(),
            AuthResult::DenyWithHeaders(_, _, headers) => headers.clone(),
            AuthResult::DigestChallenge(challenge) => {
                vec![("WWW-Authenticate".to_string(), challenge.clone())]
            }
        };

        if outcome.severity() > aggregate.severity() {
            aggregate = outcome;
        }
        if first_denial.is_none() {
            let (status, message) = match &result {
                AuthResult::Deny(status, message)
                | AuthResult::DenyWithHeaders(status, message, _) => (*status, message.clone()),
                AuthResult::DigestChallenge(_) => (401, "unauthorized".to_string()),
                // Unreachable: Allow / RateLimited returned above.
                AuthResult::Allow { .. } | AuthResult::RateLimited(_) => {
                    (401, "unauthorized".to_string())
                }
            };
            first_denial = Some(FirstDenial {
                status,
                message,
                headers: denial_headers,
            });
        } else {
            merged_challenges.extend(
                denial_headers
                    .into_iter()
                    .filter(|(name, _)| name.eq_ignore_ascii_case("www-authenticate")),
            );
        }
    }

    // Construction guarantees at least two providers, so the loop ran
    // and `first_denial` is set; the fallback denial only guards a
    // hypothetical empty composition, and it fails closed.
    let FirstDenial {
        status,
        message,
        headers: mut response_headers,
    } = first_denial.unwrap_or_else(|| FirstDenial {
        status: 401,
        message: "unauthorized".to_string(),
        headers: Vec::new(),
    });
    for (name, value) in merged_challenges {
        let duplicate = response_headers
            .iter()
            .any(|(existing_name, existing_value)| {
                existing_name.eq_ignore_ascii_case(&name) && existing_value == &value
            });
        if !duplicate {
            response_headers.push((name, value));
        }
    }
    let result = if response_headers.is_empty() {
        AuthResult::Deny(status, message)
    } else {
        AuthResult::DenyWithHeaders(status, message, response_headers)
    };
    (result, None, aggregate, "any_of".to_string())
}

/// Lazily-initialized HTTP client for forward-auth subrequests. A
/// single pooled client across all requests avoids the per-request
/// socket and TLS-handshake cost of constructing a fresh
/// `reqwest::Client`. The per-call `fwd.timeout` is applied as a
/// request-scoped deadline below. The outer client-level timeout
/// (default 30s) reads from
/// `proxy.http_client_timeouts.forward_auth_client_secs` on first use.
/// Redirects are disabled because this client also acquires bound outbound
/// credentials: replaying an authorization subrequest or DPoP proof at a
/// redirected method or URI would invalidate its security binding.
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
            .redirect(reqwest::redirect::Policy::none())
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

fn is_auth_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Return whether an HTTP authentication challenge explicitly carries the
/// requested auth parameter and value.
///
/// The scanner ignores quoted strings while looking for parameter names and
/// enforces RFC token boundaries, so values such as
/// `error_description="invalid_token"` cannot masquerade as `error=...`.
fn auth_challenge_has_parameter(header: &str, name: &str, expected: &str) -> bool {
    let bytes = header.as_bytes();
    let name = name.as_bytes();
    let expected = expected.as_bytes();
    let mut cursor = 0;

    while cursor < bytes.len() {
        if bytes[cursor] == b'"' {
            cursor += 1;
            while cursor < bytes.len() {
                match bytes[cursor] {
                    b'\\' if cursor + 1 < bytes.len() => cursor += 2,
                    b'"' => {
                        cursor += 1;
                        break;
                    }
                    _ => cursor += 1,
                }
            }
            continue;
        }

        let name_end = cursor.saturating_add(name.len());
        let has_name = name_end <= bytes.len()
            && bytes[cursor..name_end].eq_ignore_ascii_case(name)
            && (cursor == 0 || !is_auth_token_byte(bytes[cursor - 1]))
            && (name_end == bytes.len() || !is_auth_token_byte(bytes[name_end]));
        if !has_name {
            cursor += 1;
            continue;
        }

        let mut value_start = name_end;
        while value_start < bytes.len() && bytes[value_start].is_ascii_whitespace() {
            value_start += 1;
        }
        if bytes.get(value_start) != Some(&b'=') {
            cursor = name_end;
            continue;
        }
        value_start += 1;
        while value_start < bytes.len() && bytes[value_start].is_ascii_whitespace() {
            value_start += 1;
        }

        if bytes.get(value_start) == Some(&b'"') {
            value_start += 1;
            let mut value_end = value_start;
            while value_end < bytes.len() && bytes[value_end] != b'"' {
                if bytes[value_end] == b'\\' {
                    break;
                }
                value_end += 1;
            }
            if value_end < bytes.len()
                && bytes[value_start..value_end].eq_ignore_ascii_case(expected)
            {
                return true;
            }
        } else {
            let mut value_end = value_start;
            while value_end < bytes.len() && is_auth_token_byte(bytes[value_end]) {
                value_end += 1;
            }
            if bytes[value_start..value_end].eq_ignore_ascii_case(expected) {
                return true;
            }
        }

        cursor = value_start.saturating_add(1);
    }

    false
}

fn forward_auth_denial_trust_outcome(
    status: u16,
    headers: &reqwest::header::HeaderMap,
) -> AuthTrustOutcome {
    if status >= 500 {
        return AuthTrustOutcome::BackendFailure;
    }

    let mut challenge_present = false;
    for value in headers.get_all(reqwest::header::WWW_AUTHENTICATE).iter() {
        challenge_present = true;
        if value
            .to_str()
            .is_ok_and(|value| auth_challenge_has_parameter(value, "error", "invalid_token"))
        {
            return AuthTrustOutcome::InvalidProof;
        }
    }

    if challenge_present {
        AuthTrustOutcome::Challenge
    } else {
        AuthTrustOutcome::Missing
    }
}

/// Run forward auth by making an HTTP subrequest to the auth service.
async fn check_forward_auth(
    fwd: &sbproxy_modules::auth::ForwardAuthProvider,
    request_headers: &http::HeaderMap,
) -> std::result::Result<Vec<(String, String)>, (u16, String, AuthTrustOutcome)> {
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
        // Trace context is derived below, not copied. An operator who
        // listed `traceparent` here would otherwise get two of them on
        // the wire, because `RequestBuilder::header` appends, and the
        // copied one would name the caller's span rather than this hop.
        if header_name.eq_ignore_ascii_case("traceparent")
            || header_name.eq_ignore_ascii_case("tracestate")
        {
            continue;
        }
        if let Some(val) = request_headers.get(header_name.as_str()) {
            if let Ok(val_str) = val.to_str() {
                req = req.header(header_name.as_str(), val_str);
            }
        }
    }
    // The caller instruments this future with `sbproxy.intake.authenticate`
    // (`request_phase.rs`), so the ambient span is the context to
    // propagate and nothing needs plumbing here.
    req = sbproxy_observe::telemetry::inject_reqwest_trace_context(req, None);

    let response = req.send().await.map_err(|e| {
        // Not `error = %e`: the reqwest Display ends with the full URL,
        // and a forward-auth endpoint is operator config that can carry a
        // token in its path (WOR-2629).
        warn!(
            error = %sbproxy_httpkit::request_error_summary(&e),
            url = %sbproxy_security::url_redact::redacted_url(&fwd.url),
            "forward auth request failed"
        );
        (
            503u16,
            "auth service unavailable".to_string(),
            AuthTrustOutcome::BackendFailure,
        )
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
        let trust_outcome = forward_auth_denial_trust_outcome(status, response.headers());
        Err((401u16, "unauthorized".to_string(), trust_outcome))
    }
}

/// Record one authentication decision, on every surface that carries it.
///
/// The single seam for the `auth` decision event (WOR-2446). It records
/// the per-feature metric, the shared decision family, and the audit
/// record, so the three cannot disagree about what was decided or drift
/// as call sites are added.
///
/// # Why this replaced fourteen bare metric calls
///
/// `record_auth` had fourteen production call sites across the
/// virtual-key, forward-auth, and native-key paths. Wiring the audit at
/// some of them and not others would have been worse than leaving it
/// unwired: `DecisionEvent::Auth::has_emitter()` gates the startup
/// warning that currently tells an operator this feed is silent, so a
/// partial wiring silences that warning while the feed is still missing
/// every decision the untouched sites make. A detector has to be as wide
/// as the thing it detects, so the metric and the audit are emitted
/// together or not at all.
///
/// # Why `origin_label` is not the origin the record carries
///
/// Callers pass `ctx.hostname`, the request `Host`, which is what the
/// existing `sbproxy_auth_results_total` metric has always labelled by.
/// The decision family cannot use it. Under a wildcard origin every
/// subdomain is a distinct label value, and `origin` is budgeted at 200
/// across every family that uses it, so exhausting it here would demote
/// every not-yet-seen origin to `__other__` on unrelated metrics for the
/// life of the process. The record and the family both take the
/// config-bounded `origin_id`, the same choice `PolicyVerdictCtx` makes
/// and for the same reason.
///
/// A request that matched no origin has no `origin_id` and no
/// per-origin audit scope to consult, so it records the metric and the
/// family under the default origin and publishes no record. There is no
/// configured origin whose block could have asked for one.
pub(crate) fn record_auth_decision(
    ctx: &RequestContext,
    origin_label: &str,
    auth_type: &str,
    allowed: bool,
    reason: &str,
) {
    use sbproxy_observe::decision::{DecisionEngine, DecisionEvent, DecisionOutcome};

    // The pre-existing per-feature metric, unchanged, still labelled by
    // hostname so no dashboard or alert built on it moves.
    sbproxy_observe::metrics::record_auth(origin_label, auth_type, allowed);

    let origin_id = ctx
        .origin_idx
        .and_then(|idx| ctx.pipeline.config.origins.get(idx))
        .map(|origin| origin.origin_id.to_string());
    let outcome = if allowed {
        DecisionOutcome::Allow
    } else {
        DecisionOutcome::Deny
    };
    let origin_for_family = origin_id.as_deref().unwrap_or(DEFAULT_ORIGIN_LABEL);
    sbproxy_observe::decision::record_decision(
        DecisionEvent::Auth,
        DecisionEngine::BuiltIn,
        outcome,
        origin_for_family,
        &ctx.tenant_id,
    );

    let Some(origin_id) = origin_id else {
        return;
    };
    if !crate::server::proxy_http::audit_publishes(
        &ctx.pipeline,
        DecisionEvent::Auth,
        Some(&ctx.tenant_id),
        Some(&origin_id),
    ) {
        return;
    }
    crate::policy_bus::emit_decision_audit_detailed(
        DecisionEvent::Auth,
        DecisionEngine::BuiltIn,
        outcome,
        &ctx.request_id,
        &origin_id,
        &origin_id,
        &ctx.tenant_id,
        reason,
        sbproxy_observe::decision::DecisionDetails::auth(auth_type),
    );
}

/// Origin label for a decision made before any origin matched.
///
/// A closed constant rather than the empty string: the family's label
/// budget treats an empty origin as the proxy-wide path, which would
/// make "no origin matched" indistinguishable from "every origin".
const DEFAULT_ORIGIN_LABEL: &str = "__unmatched__";

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
    .with_key_context(
        ctx.native_key_provider.clone(),
        ctx.inbound_key_mode.as_str(),
    )
    // WOR-2093: a denial names the key it denied, when one resolved.
    .with_api_key_id(ctx.accountable_key_id())
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
    /// Workspace the origin belongs to.
    ///
    /// Nothing in this workspace populates `CompiledOrigin::workspace_id`
    /// today, so this is the empty string in every deployment. It stays
    /// because the enterprise audit binding distinguishes workspace from
    /// tenant through a lookup the OSS proxy does not own. Do not reach
    /// for it as a tenant: [`Self::tenant`] is the populated one.
    workspace_id: String,
    /// Origin the decision is being made on.
    ///
    /// Required by the shared decision-event family (WOR-2370): a
    /// decision is meaningless without knowing whose traffic it was
    /// made on.
    ///
    /// This is `CompiledOrigin::origin_id`, not the request `Host`.
    /// Several recorders in this tree pass the `Host`, which is
    /// attacker-chosen: under a wildcard origin every subdomain is a
    /// distinct label value. The limiter's accepted-value set is keyed
    /// by label *name* across every metric that uses it and `origin` is
    /// budgeted at 200, so exhausting it here would permanently demote
    /// every not-yet-seen origin to `__other__` on
    /// `sbproxy_origin_requests_total`, `sbproxy_cache_results_total`,
    /// and every other origin-labelled family for the life of the
    /// process. That risk was tolerable while the write path was WAF
    /// and retry; this family records on every policy decision, so it
    /// uses the config-bounded id the way `record_cache` already does.
    origin: String,
    /// Tenant the decision is attributed to, for the shared family.
    ///
    /// Deliberately not [`Self::tenant_id`]. That field carries
    /// `CompiledOrigin::workspace_id`, which nothing in this workspace
    /// ever populates: every construction site sets it to
    /// `CompactString::default()`, so it is the empty string in every
    /// deployment. Using it here would have shipped all three families
    /// with `tenant=""` everywhere, which also short-circuits
    /// `sanitize_label_budget_tenant` to the proxy-wide path and so
    /// silently skips the per-tenant budget isolation the family exists
    /// to provide. `CompiledOrigin::tenant_id` is the populated one and
    /// defaults to `__default__`, which is what the docs promise.
    tenant: String,
    /// Which wire shape this process publishes `policy` records in
    /// (WOR-2448).
    ///
    /// Resolved at the dispatcher entry from the compiled config, next
    /// to the identifiers, rather than read per policy: the encoding is
    /// a property of the process, and a chain whose first policy
    /// serialized one way and whose second serialized another would be
    /// unreadable in exactly the way this migration exists to fix.
    record_format: sbproxy_config::types::PolicyRecordFormat,
}

/// Map a policy verdict onto the shared outcome vocabulary.
///
/// `Confirm` maps to `Deny` deliberately. It holds the request pending
/// human approval, so from the request's point of view it did not
/// proceed, and a SIEM rule counting refusals should see it. The
/// distinction survives in the audit record's reason, which names the
/// confirmation rather than collapsing it.
const fn decision_outcome_for(
    verdict: sbproxy_observe::events::VerdictTag,
) -> sbproxy_observe::decision::DecisionOutcome {
    use sbproxy_observe::decision::DecisionOutcome;
    use sbproxy_observe::events::VerdictTag;
    match verdict {
        VerdictTag::Allow | VerdictTag::AllowWithHeaders => DecisionOutcome::Allow,
        VerdictTag::Deny | VerdictTag::Confirm => DecisionOutcome::Deny,
        // `VerdictTag` is `#[non_exhaustive]`, so this arm is required.
        // It maps to `Deny` rather than `Allow` deliberately: a verdict
        // this build does not recognize must not be counted as traffic
        // this build permitted on a security metric. The counterfactual
        // is visible because the arm is reachable only for a tag added
        // upstream after this match was written.
        _ => DecisionOutcome::Deny,
    }
}

/// Distinguish a hook that ran out of time from one that faulted.
///
/// `outcome` is documented as always carrying `error` and `timeout`
/// alongside an event's own verdicts, so a failing hook is alertable
/// without knowing in advance which hook it was in. That claim is only
/// true if something actually produces `timeout`, and
/// `PluginError::Timeout` is the signal: every sandboxed engine maps its
/// deadline to it, so a policy that blew its budget is separable from
/// one that returned garbage. They want different responses, a budget
/// change versus a bug fix, which is the whole reason they are separate
/// outcomes.
const fn engine_fault_outcome(
    error: &sbproxy_plugin::PluginError,
) -> sbproxy_observe::decision::DecisionOutcome {
    match error {
        sbproxy_plugin::PluginError::Timeout => sbproxy_observe::decision::DecisionOutcome::Timeout,
        _ => sbproxy_observe::decision::DecisionOutcome::Error,
    }
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
    engine: sbproxy_observe::decision::DecisionEngine,
    verdict: sbproxy_observe::events::VerdictTag,
    decision_started: std::time::Instant,
) {
    emit_policy_verdict_with_outcome(
        ctx,
        policy_id,
        surface,
        engine,
        verdict,
        decision_started,
        None,
    );
}

/// As [`emit_policy_verdict`], but lets the caller name the shared
/// family's outcome instead of deriving it from the verdict.
///
/// The two are not the same question. A policy whose `enforce()`
/// returned `Err` still produces a verdict, because the posture decides
/// what happens to the request, but the *decision* was an engine fault
/// and has to say so. Without this the `error` and `timeout` outcomes
/// the family documents would never be emitted by anything, and an alert
/// written against them would read flat zero while policies faulted.
fn emit_policy_verdict_with_outcome(
    ctx: &PolicyVerdictCtx,
    policy_id: &str,
    surface: sbproxy_observe::events::PolicySurface,
    engine: sbproxy_observe::decision::DecisionEngine,
    verdict: sbproxy_observe::events::VerdictTag,
    decision_started: std::time::Instant,
    engine_outcome: Option<sbproxy_observe::decision::DecisionOutcome>,
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
    // WOR-2370: the same decision on the shared family. The per-feature
    // metrics above stay; this is the family new events use and the one
    // existing events migrate toward, so the policy event is the first
    // to carry both.
    sbproxy_observe::decision::record_decision(
        sbproxy_observe::decision::DecisionEvent::Policy,
        engine,
        engine_outcome.unwrap_or_else(|| decision_outcome_for(verdict)),
        &ctx.origin,
        &ctx.tenant,
    );
    sbproxy_observe::decision::record_decision_duration(
        sbproxy_observe::decision::DecisionEvent::Policy,
        engine,
        &ctx.origin,
        elapsed.as_secs_f64(),
    );
    // WOR-2370: the audit record carries the resolved tenant, not the
    // workspace id. Origin and tenant are mandatory on an audit record
    // rather than optional context, because a record an analyst cannot
    // filter to a customer is not evidence, and `workspace_id` is
    // `CompactString::default()` at every construction site in this
    // workspace. Leaving it would have shipped the Prometheus series
    // saying `tenant="acme-corp"` while the SIEM record for the same
    // decision said `tenant_id=""`, and the SIEM record is the
    // analyst-facing half.
    // WOR-2448: one record either way, in the shape this process is
    // configured for. Publishing both during the deprecation window
    // would double volume on the densest event in the system and give an
    // analyst two rows for one decision, which is the thing the
    // convergence exists to stop.
    //
    // Neither arm consults `decision_audit.publishes("policy")`. Policy
    // records have published unconditionally since the audit bus landed,
    // and gating the converged shape on a block an operator has probably
    // never written would turn a format change into a silent loss of the
    // most security-relevant feed in the system. The flag chooses an
    // encoding; it does not choose whether to emit.
    match ctx.record_format {
        sbproxy_config::types::PolicyRecordFormat::Legacy => {
            let event = sbproxy_observe::events::PolicyVerdictEvent::new(
                uuid::Uuid::new_v4(),
                ctx.request_id.clone(),
                ctx.tenant.clone(),
                ctx.workspace_id.clone(),
                chrono::Utc::now(),
                policy_id.to_string(),
                surface,
                engine,
                verdict,
                elapsed_ms,
            );
            if let Err(_dropped) = crate::policy_bus::try_publish(event) {
                // Bus full or not yet installed; the dropped-events metric is
                // the paging signal per `docs/adr-policy-audit-binding.md`. The
                // drop counter is per tenant on purpose: one noisy tenant
                // filling the queue must not silently degrade another tenant's
                // audit trail, which it would if this were keyed on the always
                // empty workspace id.
                sbproxy_observe::metrics::record_policy_audit_event_dropped(&ctx.tenant);
            }
        }
        sbproxy_config::types::PolicyRecordFormat::Decision => {
            // The reason the legacy shape had no room for. It is
            // proxy-authored rather than operator prose, so it says what
            // decided and what it decided, and the structured detail
            // beside it is what a rule actually selects on.
            let reason = format!(
                "policy {policy_id} returned {} on the {} surface",
                verdict.as_label(),
                surface.as_label()
            );
            crate::policy_bus::emit_decision_audit_detailed(
                sbproxy_observe::decision::DecisionEvent::Policy,
                engine,
                engine_outcome.unwrap_or_else(|| decision_outcome_for(verdict)),
                &ctx.request_id,
                &ctx.origin,
                &ctx.origin,
                &ctx.tenant,
                &reason,
                sbproxy_observe::decision::DecisionDetails::policy(
                    policy_id,
                    surface.as_label(),
                    verdict.as_label(),
                    elapsed_ms,
                ),
            );
        }
    }
    // WOR-2094: non-allow verdicts land on the console's audit sample.
    // Allow verdicts stay off the ring (they would flood it at request
    // volume); the per-request policy_decisions column carries them.
    if !matches!(verdict, sbproxy_observe::events::VerdictTag::Allow) {
        sbproxy_observe::audit_ring::push_audit_event(
            sbproxy_observe::audit_ring::AuditRingEvent::new(
                "policy",
                policy_id,
                None,
                Some(ctx.tenant.clone()),
                None,
                Some(ctx.request_id.clone()),
                Some(format!(
                    "{} verdict on {} surface ({elapsed_ms}ms)",
                    verdict.as_label(),
                    surface.as_label(),
                )),
            ),
        );
    }
}

/// Build a frozen `http::Request<bytes::Bytes>` snapshot of the
/// inbound request for a `PolicyEnforcer` call.
///
/// `PolicyEnforcer::enforce` takes an immutable request reference;
/// this helper materialises one from the Pingora session so the
/// existing built-in arms can keep their `Session` view while
/// plugin enforcers see the standard `http` types.
///
/// Header-phase callers pass an empty body. Dynamic policies that declare
/// buffered access are deferred until end-of-stream and pass the complete,
/// cap-checked body. Dynamic `none` policies and linked plugins retain the
/// header-only snapshot.
fn build_plugin_request_snapshot(
    session: &Session,
    body: bytes::Bytes,
) -> Option<http::Request<bytes::Bytes>> {
    let req = session.req_header();
    let method = req.method.as_str();
    let path_and_query = req
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let builder = http::Request::builder().method(method).uri(path_and_query);
    let mut built = builder.body(body).ok()?;
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
/// SSRF guard for an upstream `host:port` (WOR-1689).
///
/// Async and non-blocking: an IP-literal host is checked directly with
/// no DNS, and a hostname is resolved once via
/// `ssrf::resolve_host_addrs` (getaddrinfo on tokio's blocking pool,
/// `await`ed with a 2s timeout) instead of the old per-request OS-thread
/// spawn that blocked the async worker. The verdict is fail-closed: any
/// resolve error, timeout, or empty result rejects, and any resolved
/// private IP rejects unless it falls inside `allow_private_cidrs`.
/// Nothing is cached, so a host later re-pointed at a private address
/// cannot ride a stale "allowed" verdict.
async fn guard_upstream(
    host: &str,
    port: u16,
    tls: bool,
    allow_private_cidrs: &[ipnetwork::IpNetwork],
) -> Result<()> {
    use sbproxy_security::ssrf;
    let _ = tls; // scheme is no longer reconstructed into a URL

    // IP literal: check it directly, no DNS. Hostname: resolve the full
    // address set (fail-closed on error/timeout/empty).
    let ips: Vec<std::net::IpAddr> = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        vec![ip]
    } else {
        let addrs = ssrf::resolve_host_addrs(host, port)
            .await
            .map_err(|reason| {
                warn!(upstream_host = %host, reason = %reason, "SSRF: blocked upstream URL");
                Error::because(
                    ErrorType::ConnectError,
                    "SSRF: blocked upstream URL",
                    anyhow::anyhow!(reason),
                )
            })?;
        if addrs.is_empty() {
            warn!(upstream_host = %host, "SSRF: upstream resolved to no addresses");
            return Err(Error::because(
                ErrorType::ConnectError,
                "SSRF: blocked upstream URL",
                anyhow::anyhow!("hostname '{host}' resolved to no addresses"),
            ));
        }
        addrs.into_iter().map(|sa| sa.ip()).collect()
    };

    // Reject any private IP not covered by the operator's allowlist.
    for ip in ips {
        if ssrf::is_private_ip(&ip) && !allow_private_cidrs.iter().any(|net| net.contains(ip)) {
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

/// Whether this enforcer publishes its own `policy_verdict_event` from
/// the request-body phase, so the header phase must not publish a
/// terminal `allow` for it (WOR-2687).
///
/// The header-phase `Allow` from an enforcer of this kind is not a
/// decision. `OpenApiValidationEnforcer::enforce` returns `Allow`
/// unconditionally, because all it does at that phase is set
/// `validate_request_body` so the body it validates gets buffered; the
/// verdict is reached later, in `request_body_filter`. Publishing both
/// puts two contradicting records on the bus for one decision, keyed
/// identically on `(request_id, policy_id)` and separable only by
/// arrival order, which is the shape `docs/observability.md` and
/// `docs/decision-records.md` both record as rejected: the natural SIEM
/// query for "which requests did this policy admit" would match every
/// request it denied.
///
/// Both axes are load bearing, because suppressing a record that
/// nothing republishes deletes a decision rather than de-duplicating
/// one, and `policy_id` alone cannot tell the two apart.
///
/// `surface` first. `policy_id` is `compiled.enforcer.policy_type()`,
/// and for a `Policy::Plugin` (a linked Rust plugin or a config-loaded
/// bundle hook) that string is chosen by the plugin: nothing reserves
/// the built-in policy type names against it. A bundle registering a
/// hook called `openapi_validation` would otherwise have its
/// header-phase record suppressed while having no body-phase emission
/// at all, and its decision would leave no record anywhere.
/// `builtin_enforcers::registry` gives every such enforcer
/// `PolicySurface::Plugin` and gives the enum-arm path
/// `PolicySurface::BuiltIn`, so requiring `BuiltIn` here keeps the
/// suppression on the arm that this file's body phase actually
/// republishes. A surface added to that `#[non_exhaustive]` enum later
/// is not `BuiltIn`, so it keeps its header record until someone
/// deliberately adds it.
///
/// `policy_id` second, and the list is one entry long on purpose. The
/// other policies that decide in the body phase, `request_validator`,
/// `content_digest`, `body_threat_protection`, `prompt_injection_v2`'s
/// body scan, and the A2A push-notification check, all refuse from
/// `request_body_filter` without publishing a verdict there, so their
/// header-phase `allow` is the only record their decision has. The list
/// grows one policy at a time, paired with the emission that replaces
/// what it suppresses.
fn emits_own_verdict_in_body_phase(
    surface: sbproxy_observe::events::PolicySurface,
    policy_id: &str,
) -> bool {
    matches!(surface, sbproxy_observe::events::PolicySurface::BuiltIn)
        && matches!(policy_id, "openapi_validation")
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
/// Async for two reasons. Every enforcer's `enforce` returns a future,
/// and, since WOR-2332, a rate-limit policy attached to an L2 (Redis)
/// store or a mesh tier is admitted *here* rather than inside its
/// enforcer, through
/// [`crate::builtin_enforcers::shared_admission::SharedAdmission`]. That
/// admission is the await this function exists to host: `enforce` cannot
/// perform it, because its future must be `Send` and the `&mut dyn Any`
/// it receives to reach the request context is not.
///
/// Local-only token-bucket rate limiters carry no such handle and still
/// decide synchronously inside `enforce`, without hitting the runtime.
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

    // WOR-1697: an origin with no enforcers is the common case; return
    // "allow" (None) before materialising the request snapshot. The
    // caller records the `record_policy(.., "all", "allow")` metric on
    // the None path, so the empty-chain metric still fires.
    ctx.dynamic_request_body_plan =
        crate::request_body_plan::DynamicRequestBodyPlan::from_policy_metadata(
            enforcers
                .iter()
                .enumerate()
                .map(|(index, compiled)| (index, compiled.dynamic_hook.as_ref())),
        );
    // Record the non-dynamic buffering demand before the empty-chain exit.
    //
    // `request_body_filter` releases the body early when nothing needs it,
    // and it decides that from this flag plus the dynamic policy set. An
    // origin with no policies took the exit below, so the flag kept its
    // `false` default while `ctx.validate_request_body` was already true,
    // and the early release then skipped Web Bot Auth's body-bound proof:
    // a signed request whose body did not match its covered
    // `content-digest` was admitted with a 200. Every consumer that sets
    // `validate_request_body` outside the policy chain, Web Bot Auth at
    // `request_phase::request_filter` among them, runs before this point,
    // so recording it here sees all of them.
    ctx.dynamic_request_body_plan
        .set_other_buffering_required(ctx.validate_request_body);
    if enforcers.is_empty() {
        return None;
    }

    // Materialise the request snapshot once. Built-in wrappers and
    // plugin enforcers share this view; the session-specific data
    // they need (client_ip, hostname, rate_limit_info) lives on
    // `RequestContext` and is threaded through the `&mut Any`
    // downcast inside each `enforce()` body.
    let req_snapshot = match build_plugin_request_snapshot(session, bytes::Bytes::new()) {
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
        if compiled
            .dynamic_hook
            .as_ref()
            .is_some_and(|hook| hook.body_mode() == sbproxy_config::BundleBodyMode::Buffered)
        {
            continue;
        }
        // WOR-1697: `policy_type()` is a `&'static str`; keep the borrow
        // instead of allocating a String per enforcer. `emit_policy_verdict`
        // takes `&str` and owns its own copy only where it needs one.
        let policy_id = compiled.enforcer.policy_type();
        let started = std::time::Instant::now();
        let surface = compiled.surface;
        let engine = compiled.engine;
        // WOR-2332: admission against a cluster-shared tier happens here,
        // not inside `enforce`. See `resolve_shared_admission`.
        crate::builtin_enforcers::resolve_shared_admission(compiled, &req_snapshot, ctx).await;
        let ctx_any: &mut dyn std::any::Any = ctx;
        // WOR-2318: one span per enforcer. The chain already reports a
        // per-policy verdict event and a per-policy metric, and neither
        // answers "which of the eleven policies on this origin is the one
        // adding 40ms". A span per evaluation does, and it nests under the
        // intake span for free because `request_filter` runs this whole
        // filter inside it.
        //
        // `.instrument` rather than an entered guard: `enforce` is awaited
        // and the dispatch future has to stay `Send`, which an `Entered`
        // held across the await would break.
        let enforce_span = sbproxy_observe::telemetry::policy_enforce_span(policy_id);
        // WOR-2477: a panicking tenant policy used to crash the whole
        // proxy, taking every other tenant with it. Contain it the way
        // the transform-plugin runner already does
        // (sbproxy-modules/src/transform/mod.rs) and fail just this one
        // request closed. `ctx_any` is not read back on the panic arm
        // below, so a partial mutation left behind by the unwound
        // enforcer is never observed.
        use futures::FutureExt as _;
        let enforced = tracing::Instrument::instrument(
            std::panic::AssertUnwindSafe(compiled.enforcer.enforce(&req_snapshot, ctx_any))
                .catch_unwind(),
            enforce_span,
        );
        let decision = match enforced.await {
            Ok(Ok(d)) => d,
            Ok(Err(err)) => {
                // WOR-2423: a dynamic bundle hook running in the header
                // phase declares the same `failure_posture` the buffered
                // path already honors (WOR-2268); consulting it only on
                // one of the two paths made the setting silently inert
                // for `body_mode: none` policy hooks. Built-in and
                // linked enforcers have no posture and keep the
                // unconditional refusal.
                let posture = compiled
                    .dynamic_hook
                    .as_ref()
                    .map(|metadata| metadata.failure_posture());
                let verdict = match posture {
                    Some(posture) if posture.admits() => VerdictTag::Allow,
                    _ => VerdictTag::Deny,
                };
                tracing::warn!(
                    target: "sbproxy::policy",
                    error = %err,
                    policy = %policy_id,
                    bundle = compiled
                        .dynamic_hook
                        .as_ref()
                        .map(|metadata| metadata.bundle_id())
                        .unwrap_or("built_in"),
                    failure_posture = posture.map(|p| p.as_label()).unwrap_or("none"),
                    "policy enforce() returned error"
                );
                emit_policy_verdict_with_outcome(
                    verdict_ctx,
                    policy_id,
                    surface,
                    engine,
                    verdict,
                    started,
                    // A fail-open is not an error (WOR-2370): an
                    // admitting posture keeps the verdict's own outcome
                    // and the fail-open family carries the fault.
                    (verdict == VerdictTag::Deny).then(|| engine_fault_outcome(&err)),
                );
                if let Some(posture) = posture.filter(|posture| posture.admits()) {
                    // The request proceeded without the decision being
                    // made; count the unearned allow separately, exactly
                    // as the buffered path does.
                    sbproxy_observe::decision::record_decision_fail_open(
                        sbproxy_observe::decision::DecisionEvent::Policy,
                        engine,
                        &verdict_ctx.origin,
                        &verdict_ctx.tenant,
                    );
                    let label = if posture.records_counterfactual() || posture.guarantee_waived() {
                        posture.as_label()
                    } else {
                        verdict.as_label()
                    };
                    ctx.record_policy_decision(policy_id, label);
                    continue;
                }
                // WOR-2094: the ring row explains the denial too.
                ctx.record_policy_decision(policy_id, VerdictTag::Deny.as_label());
                ctx.deny_reason = Some(format!("{policy_id}: enforce error"));
                return Some((500, "policy error".to_string(), "plugin"));
            }
            Err(_panic) => {
                // WOR-2477: unconditional fail-closed, unlike the
                // `Ok(Err(err))` arm above. A returned `PluginError` is
                // a policy the operator configured and can set a
                // fail-open posture on; a panic is a bug in that
                // policy's own code, so there is no posture to honor
                // and no partial mutation of `ctx` left by the unwound
                // future to trust. The counter makes a panicking policy
                // visible in dashboards instead of only in logs.
                sbproxy_observe::metrics::record_policy_panic(policy_id);
                tracing::error!(
                    target: "security_audit",
                    policy = %policy_id,
                    "policy enforcer panicked; request denied, proxy still serving"
                );
                sbproxy_plugin::PolicyDecision::Deny {
                    status: 500,
                    message: "policy enforcer panicked".to_string(),
                }
            }
        };
        let translated = crate::policy_dispatch::translate_plugin_decision(
            decision,
            &mut ctx.policy_response_headers,
            &mut confirm_state,
        );
        // WOR-2687: an enforcer that only arms body buffering here has
        // not decided anything yet, and the phase that does decide
        // publishes the verdict itself. Skipped after
        // `translate_plugin_decision` rather than before `enforce`,
        // because the enforcer still has to run: arming the buffer is
        // the whole reason it is in the chain, and any response headers
        // or confirm state its decision carries have already been
        // applied by the line above. A deny is never skipped, so an
        // enforcer of this kind that starts refusing in the header
        // phase keeps its record here.
        if translated.deny.is_none() && emits_own_verdict_in_body_phase(surface, policy_id) {
            continue;
        }
        emit_policy_verdict(
            verdict_ctx,
            policy_id,
            surface,
            engine,
            translated.verdict,
            started,
        );
        // WOR-2094: mirror every verdict onto the request context so the
        // admin ring row can explain what applied, not just what denied.
        ctx.record_policy_decision(policy_id, translated.verdict.as_label());
        if let Some(deny) = translated.deny {
            ctx.deny_reason = Some(format!("{policy_id}: {}", deny.1));
            return Some(deny);
        }
    }

    let declared_body_len = session
        .req_header()
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if let Some(declared_body_len) = declared_body_len {
        match ctx
            .dynamic_request_body_plan
            .before_growth(declared_body_len, None)
        {
            Ok(skipped) => {
                for skipped_hook in skipped {
                    let hook = skipped_hook.metadata();
                    let posture = hook.failure_posture();
                    tracing::warn!(
                        target: "sbproxy::extension",
                        bundle = hook.bundle_id(),
                        hook = hook.hook_type(),
                        policy_index = skipped_hook.policy_index(),
                        received = declared_body_len,
                        cap = skipped_hook.cap(),
                        failure_posture = posture.as_label(),
                        "skipping buffered dynamic policy from declared request body length"
                    );
                    if posture.guarantee_waived() || posture.records_counterfactual() {
                        ctx.record_policy_decision(hook.hook_type(), posture.as_label());
                    }
                }
            }
            Err(overflow) => {
                let hook = overflow.metadata();
                tracing::debug!(
                    target: "sbproxy::extension",
                    bundle = hook.bundle_id(),
                    hook = hook.hook_type(),
                    policy_index = ?overflow.policy_index(),
                    received = declared_body_len,
                    cap = overflow.cap(),
                    "buffered dynamic policy rejected declared request body length"
                );
                return Some((413, "request entity too large".to_string(), "plugin"));
            }
        }
    }

    ctx.dynamic_request_body_plan
        .set_other_buffering_required(ctx.validate_request_body);
    if ctx.dynamic_request_body_plan.has_active_buffered_policies() {
        ctx.validate_request_body = true;
    }

    None
}

/// Run dynamic bundle policies that declared buffered request-body access.
///
/// The header phase deliberately skips these enforcers. This body-phase
/// dispatcher supplies one complete immutable body only after the shared
/// request buffer reaches end-of-stream.
async fn check_buffered_dynamic_policies(
    enforcers: &[crate::builtin_enforcers::CompiledEnforcer],
    session: &Session,
    ctx: &mut RequestContext,
    body: bytes::Bytes,
    verdict_ctx: &PolicyVerdictCtx,
) -> Option<(u16, String, &'static str)> {
    use sbproxy_observe::events::VerdictTag;

    let active_indexes = ctx.dynamic_request_body_plan.active_policy_indexes();
    if active_indexes.is_empty() {
        return None;
    }
    // Consume the plan before the first enforcer runs so a later phase
    // cannot dispatch the same buffered hook twice (WOR-2681).
    ctx.dynamic_request_body_plan
        .mark_buffered_policies_dispatched();
    let req_snapshot = match build_plugin_request_snapshot(session, body) {
        Some(request) => request,
        None => return Some((500, "policy: bad request".to_string(), "plugin")),
    };
    let mut confirm_state = crate::policy_dispatch::ConfirmReducerState::default();

    for index in active_indexes {
        let Some(compiled) = enforcers.get(index) else {
            return Some((500, "policy plan changed".to_string(), "plugin"));
        };
        let Some(metadata) = compiled.dynamic_hook.as_ref() else {
            continue;
        };
        if metadata.body_mode() != sbproxy_config::BundleBodyMode::Buffered {
            continue;
        }

        let policy_id = compiled.enforcer.policy_type();
        let started = std::time::Instant::now();
        let ctx_any: &mut dyn std::any::Any = ctx;
        // WOR-2477: same containment as the header-phase dispatcher in
        // `check_policies` above, applied here for the buffered-body
        // seam. A panicking buffered dynamic policy used to crash the
        // whole proxy exactly like the header-phase one did. `ctx_any`
        // is not read back on the panic arm below, so a partial
        // mutation left behind by the unwound enforcer is never
        // observed.
        use futures::FutureExt as _;
        let enforce_result =
            std::panic::AssertUnwindSafe(compiled.enforcer.enforce(&req_snapshot, ctx_any))
                .catch_unwind()
                .await;
        let decision = match enforce_result {
            Ok(Ok(decision)) => decision,
            Ok(Err(error)) => {
                // The manifest posture decides this, not the host. A
                // bundle that declares `failure_posture: open` is asking
                // for its own breakage to be non-fatal, and denying
                // anyway made the setting inert (WOR-2268).
                let posture = metadata.failure_posture();
                let verdict = if posture.admits() {
                    VerdictTag::Allow
                } else {
                    VerdictTag::Deny
                };
                tracing::warn!(
                    target: "sbproxy::policy",
                    error = %error,
                    policy = %policy_id,
                    bundle = metadata.bundle_id(),
                    failure_posture = posture.as_label(),
                    "buffered dynamic policy enforce() returned error"
                );
                // WOR-2370: a fail-open is deliberately *not* counted as
                // `outcome="error"`. The docs say "a fail-open is not an
                // error", and an operator alerting on the error rate must
                // not be paged by every request a posture admitted on
                // purpose. So an admitting posture keeps the verdict's own
                // outcome, which is the `allow` the request actually got,
                // and the separate fail-open family carries the fault. A
                // posture that refuses is a different case: nothing
                // proceeded, so the engine fault is the outcome.
                emit_policy_verdict_with_outcome(
                    verdict_ctx,
                    policy_id,
                    compiled.surface,
                    compiled.engine,
                    verdict,
                    started,
                    (!posture.admits()).then(|| engine_fault_outcome(&error)),
                );
                if posture.admits() {
                    // The request proceeded *without the decision being
                    // made*, which is a different operational fact from an
                    // engine fault and wants a different alert. The call
                    // above counted the allow; this says the allow was not
                    // earned.
                    sbproxy_observe::decision::record_decision_fail_open(
                        sbproxy_observe::decision::DecisionEvent::Policy,
                        compiled.engine,
                        &verdict_ctx.origin,
                        &verdict_ctx.tenant,
                    );
                    // `Observe` and `Degraded` both proceed, and both
                    // want the counterfactual on the record: the label
                    // is what an operator alerts on to find controls
                    // that are admitting traffic they never evaluated.
                    let label = if posture.records_counterfactual() || posture.guarantee_waived() {
                        posture.as_label()
                    } else {
                        verdict.as_label()
                    };
                    ctx.record_policy_decision(policy_id, label);
                    continue;
                }
                ctx.record_policy_decision(policy_id, VerdictTag::Deny.as_label());
                ctx.deny_reason = Some(format!("{policy_id}: enforce error"));
                return Some((500, "policy error".to_string(), "plugin"));
            }
            Err(_panic) => {
                // WOR-2477: unconditional fail-closed, unlike the
                // `Ok(Err(error))` arm above, for the same reason as the
                // header-phase dispatcher: a `failure_posture` is a
                // manifest-declared response to a returned error, not a
                // policy to honor when the policy's own code panicked.
                sbproxy_observe::metrics::record_policy_panic(policy_id);
                tracing::error!(
                    target: "security_audit",
                    policy = %policy_id,
                    "policy enforcer panicked; request denied, proxy still serving"
                );
                sbproxy_plugin::PolicyDecision::Deny {
                    status: 500,
                    message: "policy enforcer panicked".to_string(),
                }
            }
        };
        let translated = crate::policy_dispatch::translate_plugin_decision(
            decision,
            &mut ctx.policy_response_headers,
            &mut confirm_state,
        );
        emit_policy_verdict(
            verdict_ctx,
            policy_id,
            compiled.surface,
            compiled.engine,
            translated.verdict,
            started,
        );
        ctx.record_policy_decision(policy_id, translated.verdict.as_label());
        if let Some(deny) = translated.deny {
            ctx.deny_reason = Some(format!("{policy_id}: {}", deny.1));
            return Some(deny);
        }
    }

    None
}

// --- Lua modifier helpers ---

/// Return a process-wide shared [`sbproxy_extension::lua::LuaEngine`],
/// rebuilding it only when the active Lua sandbox configuration changes
/// (WOR-1702).
///
/// A `LuaEngine` holds no per-request state: every `execute` /
/// `call_function` builds its own fresh sandboxed `mlua::Lua`, so one
/// instance is safe to reuse across requests and workers. Sharing it
/// removes the per-request engine construction (and, on the Go-format
/// fallback path, the second construction per request). The engine
/// snapshots the sandbox limits when it is built, so it is keyed by the
/// `active_sandbox_config()` Arc: a hot reload of
/// `proxy.scripting.lua.sandbox` swaps that Arc and this rebuilds the
/// engine; otherwise the steady state is a cheap Arc clone. Building
/// lazily (never at pipeline-compile time) means the engine always sees
/// the operator's installed limits, not the boot-time defaults.
///
/// `pub(crate)` rather than private because the decision-event path
/// (`crate::decision_script`) reuses it for the same reason the
/// modifiers do (WOR-2404).
pub(crate) fn shared_lua_engine(
) -> anyhow::Result<std::sync::Arc<sbproxy_extension::lua::LuaEngine>> {
    use sbproxy_extension::lua::{active_sandbox_config, LuaEngine, SandboxConfig};
    #[allow(clippy::type_complexity)]
    static CACHE: std::sync::LazyLock<
        parking_lot::Mutex<Option<(std::sync::Arc<SandboxConfig>, std::sync::Arc<LuaEngine>)>>,
    > = std::sync::LazyLock::new(|| parking_lot::Mutex::new(None));

    let active = active_sandbox_config();
    let mut cache = CACHE.lock();
    if let Some((cfg, engine)) = cache.as_ref() {
        if std::sync::Arc::ptr_eq(cfg, &active) {
            return Ok(engine.clone());
        }
    }
    let engine = std::sync::Arc::new(LuaEngine::with_config((*active).clone())?);
    *cache = Some((active, engine.clone()));
    Ok(engine)
}

/// Execute a Lua request modifier script.
///
/// The script must define `modify_request(req, ctx)` which receives the
/// request data as a table with `method`, `path`, `headers`, and `tls`
/// fields, and a context table carrying `request.aipref`, `request.tls`,
/// and `principal` (WOR-2083). It must return a table with `set_headers`
/// (and optionally `remove_headers`) to apply to the upstream request.
///
/// Returns a list of (header_name, header_value) pairs to set.
fn lua_request_modifier(
    script: &str,
    req_header: &RequestHeader,
    ctx: &RequestContext,
) -> anyhow::Result<Vec<(String, String)>> {
    let engine = shared_lua_engine()?;

    // Build request table for the Lua script
    let mut headers_map = std::collections::HashMap::new();
    for (name, value) in req_header.headers.iter() {
        if let Ok(v) = value.to_str() {
            headers_map.insert(name.as_str().to_string(), v.to_string());
        }
    }

    let mut req_table = serde_json::json!({
        "method": req_header.method.as_str(),
        "path": req_header.uri.path(),
        "headers": headers_map,
        "host": ctx.hostname.as_str(),
    });
    // WOR-2083: `req.tls.ja4` etc., matching the CEL `tls.*` namespace.
    {
        let fp = ctx.tls_fingerprint.as_ref();
        sbproxy_extension::lua::bindings::enrich_request_table_with_tls_fingerprint(
            &mut req_table,
            fp.and_then(|f| f.ja3.as_deref()),
            fp.and_then(|f| f.ja4.as_deref()),
            fp.and_then(|f| f.ja4h.as_deref()),
            fp.is_some_and(|f| f.trustworthy),
        );
    }
    let ctx_table = script_modifier_context(ctx);

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
            let go_engine = shared_lua_engine()?;
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
    let engine = shared_lua_engine()?;

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
            let go_engine = shared_lua_engine()?;
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

/// Execute a JavaScript request modifier script.
///
/// The script defines `modify_request(req, ctx)` and returns
/// `{set_headers: {...}}`. The request table matches the one
/// [`lua_request_modifier`] builds, so a script ported between the two
/// engines reads the same fields, including the `req.tls.*` namespace.
///
/// There is no Go-format fallback here. That branch exists on the Lua
/// side to keep `match_request(req, ctx)` scripts from the archived Go
/// implementation working, and no JavaScript modifier ever ran in that
/// implementation, so there is nothing to stay compatible with.
fn js_request_modifier(
    script: &str,
    req_header: &RequestHeader,
    ctx: &RequestContext,
) -> anyhow::Result<Vec<(String, String)>> {
    let engine = sbproxy_extension::js::JsEngine::new()?;

    let mut headers_map = std::collections::HashMap::new();
    for (name, value) in req_header.headers.iter() {
        if let Ok(v) = value.to_str() {
            headers_map.insert(name.as_str().to_string(), v.to_string());
        }
    }

    let mut req_table = serde_json::json!({
        "method": req_header.method.as_str(),
        "path": req_header.uri.path(),
        "headers": headers_map,
        "host": ctx.hostname.as_str(),
    });
    {
        let fp = ctx.tls_fingerprint.as_ref();
        sbproxy_extension::lua::bindings::enrich_request_table_with_tls_fingerprint(
            &mut req_table,
            fp.and_then(|f| f.ja3.as_deref()),
            fp.and_then(|f| f.ja4.as_deref()),
            fp.and_then(|f| f.ja4h.as_deref()),
            fp.is_some_and(|f| f.trustworthy),
        );
    }
    let ctx_table = script_modifier_context(ctx);

    let result = engine.call_function(script, "modify_request", vec![req_table, ctx_table])?;

    let mut headers_to_set = Vec::new();
    if let Some(set_headers) = result.get("set_headers").and_then(|h| h.as_object()) {
        for (key, value) in set_headers {
            if let Some(v) = value.as_str() {
                headers_to_set.push((key.clone(), v.to_string()));
            }
        }
    }
    Ok(headers_to_set)
}

// --- Rego modifier helpers ---
//
// WOR-2482: engine-surface parity. `rego_module` / `rego_module_path`
// on a request or response modifier evaluate the same way `lua_script`
// / `js_script` do: a fresh `CompiledRego` is built from the module
// text on every invocation, no config-load compile and no cached
// engine, matching how `js_request_modifier` above builds a fresh
// `JsEngine` per call rather than caching a parsed script. The failure
// posture mirrors the Lua/JS row of `docs/scripting.md`'s modifier
// error table, not `policy: rego`'s fail-closed-and-deny posture: an
// error (a module that does not name the queried rule at all, a
// budget overrun) is logged by the caller and the modifier's headers
// are simply not applied; the request proceeds. A rule that is defined
// but simply does not fire for a given input is `undefined`, which
// Rego treats as "no opinion" rather than a fault
// (`CompiledRego::eval_value`), so it also produces no headers without
// logging anything.
//
// The evaluated rule name is a fixed convention,
// `data.sbproxy.modify_request` / `data.sbproxy.modify_response`,
// mirroring how Lua and JavaScript modifiers also call a fixed
// function name (`modify_request` / `modify_response`) with no config
// knob to rename it: the capability is identical, only the spelling
// differs per language.

/// Default evaluation budget for a Rego request/response modifier when
/// `rego_budget_ms` is not set, matching `policy: rego`'s default
/// (`docs/scripting.md` §3a). Operator-overridable per modifier via
/// `rego_budget_ms`, unlike Lua's/JS's sandbox budgets, which are
/// process-wide (`proxy.scripting.{lua,javascript}.sandbox`); Rego's is
/// per-policy already on the other two Rego surfaces, so the modifier
/// form matches them rather than introducing a third shape.
const REGO_MODIFIER_BUDGET_MS: u64 = 50;

/// The rule a Rego request modifier's `rego_module` evaluates.
const REGO_MODIFIER_REQUEST_QUERY: &str = "data.sbproxy.modify_request";

/// The rule a Rego response modifier's `rego_module` evaluates.
const REGO_MODIFIER_RESPONSE_QUERY: &str = "data.sbproxy.modify_response";

/// Build the Rego `input` document a request modifier's `rego_module`
/// evaluates against.
///
/// Lua and JavaScript request modifiers receive two arguments, `req`
/// (`method`/`path`/`headers`/`host`/`tls`) and `ctx`
/// (`aipref`/`tls`/`principal`, [`script_modifier_context`]). Rego
/// takes one `input` document, so this merges the two: `ctx`'s
/// `request` object already carries `aipref` and `tls`; `req`'s fields
/// join it under the same key. `input.principal` is `ctx`'s `principal`
/// unchanged. The result is exactly the union of what the two engines
/// see, addressed as `input.request.*` / `input.principal.*` instead of
/// two arguments.
fn rego_request_modifier_input(
    req_header: &RequestHeader,
    ctx: &RequestContext,
) -> serde_json::Value {
    let mut headers_map = std::collections::HashMap::new();
    for (name, value) in req_header.headers.iter() {
        if let Ok(v) = value.to_str() {
            headers_map.insert(name.as_str().to_string(), v.to_string());
        }
    }
    let mut input = script_modifier_context(ctx);
    if let Some(request) = input
        .get_mut("request")
        .and_then(serde_json::Value::as_object_mut)
    {
        request.insert(
            "method".to_string(),
            serde_json::Value::String(req_header.method.as_str().to_string()),
        );
        request.insert(
            "path".to_string(),
            serde_json::Value::String(req_header.uri.path().to_string()),
        );
        request.insert(
            "host".to_string(),
            serde_json::Value::String(ctx.hostname.as_str().to_string()),
        );
        request.insert("headers".to_string(), serde_json::json!(headers_map));
    }
    input
}

/// Build the Rego `input` document a response modifier's `rego_module`
/// evaluates against.
///
/// Mirrors [`rego_request_modifier_input`]: `ctx`'s `request` /
/// `principal` objects carry what Lua/JS's `ctx` argument carries, and
/// `resp` (`status_code`/`headers`) joins as a new `response` key, the
/// same fields Lua/JS's `resp` argument carries.
fn rego_response_modifier_input(
    status: u16,
    response_headers: &serde_json::Map<String, serde_json::Value>,
    ctx: &RequestContext,
) -> serde_json::Value {
    let mut input = script_modifier_context(ctx);
    if let Some(map) = input.as_object_mut() {
        map.insert(
            "response".to_string(),
            serde_json::json!({
                "status_code": status,
                "headers": response_headers,
            }),
        );
    }
    input
}

/// Execute a Rego request modifier module.
///
/// Extracts `set_headers` from the evaluated `data.sbproxy.modify_request`
/// document, the same field Lua's and JS's `modify_request` return.
/// `budget_ms` is the modifier's resolved `rego_budget_ms` (the caller
/// applies the [`REGO_MODIFIER_BUDGET_MS`] default when the config left
/// it unset; config compile already refused a `Some(0)`).
///
/// # Errors
///
/// Returns an error when the module does not parse or evaluate, or
/// evaluation exceeds its budget. The caller logs this and skips the
/// modifier's headers, matching the Lua/JS request modifier row of
/// `docs/scripting.md`'s error table.
fn rego_request_modifier(
    module: &str,
    rego_v0: bool,
    budget_ms: u64,
    req_header: &RequestHeader,
    ctx: &RequestContext,
) -> anyhow::Result<Vec<(String, String)>> {
    let input = rego_request_modifier_input(req_header, ctx);
    let mut compiled = sbproxy_extension::rego::CompiledRego::compile(
        "rego request modifier",
        module,
        REGO_MODIFIER_REQUEST_QUERY,
        budget_ms,
        None,
        rego_v0,
    )?;
    let result = compiled.eval_value(input, ctx.principal.tenant_id.as_str())?;

    let mut headers_to_set = Vec::new();
    if let Some(set_headers) = result.get("set_headers").and_then(|h| h.as_object()) {
        for (key, value) in set_headers {
            if let Some(v) = value.as_str() {
                headers_to_set.push((key.clone(), v.to_string()));
            }
        }
    }
    Ok(headers_to_set)
}

/// Execute a Rego response modifier module.
///
/// Extracts headers the same way [`response_modifier_headers`] does for
/// Lua and JavaScript response modifiers, so a module returning
/// `{"set_headers": {...}}` behaves identically across all three
/// engines. `budget_ms` is the modifier's resolved `rego_budget_ms`,
/// the same as [`rego_request_modifier`]'s parameter of the same name.
///
/// # Errors
///
/// Returns an error when the module does not parse or evaluate, or
/// evaluation exceeds its budget. The caller logs this and skips the
/// modifier's headers, matching the Lua/JS response modifier row of
/// `docs/scripting.md`'s error table.
fn rego_response_modifier(
    module: &str,
    rego_v0: bool,
    budget_ms: u64,
    status: u16,
    response_headers: &serde_json::Map<String, serde_json::Value>,
    ctx: &RequestContext,
) -> anyhow::Result<Vec<(String, String)>> {
    let input = rego_response_modifier_input(status, response_headers, ctx);
    let mut compiled = sbproxy_extension::rego::CompiledRego::compile(
        "rego response modifier",
        module,
        REGO_MODIFIER_RESPONSE_QUERY,
        budget_ms,
        None,
        rego_v0,
    )?;
    let result = compiled.eval_value(input, ctx.principal.tenant_id.as_str())?;
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

// --- Response phases for locally generated responses (WOR-2496) ---

/// What the transform walk over a locally generated body produced.
///
/// `terminal_failure` is the `failure_posture: closed` outcome: the body
/// the caller must serve is the substituted error, never the buffer the
/// refused transform did not get to touch. Mirrors
/// `PluginActionTransformOutcome`, which carries the same decision for
/// the plugin-action path.
pub(crate) struct GeneratedBodyTransformOutcome {
    /// The bytes to serve.
    pub(crate) body: Bytes,
    /// A `closed` transform failed, so the response is a 500 and the
    /// generated body must not be written.
    pub(crate) terminal_failure: bool,
}

/// Apply the origin's transform chain to a locally generated response
/// body (a `static` or `mock` action's payload) and return the
/// transformed bytes.
///
/// Mirrors the walk the static action has always run: each transform
/// goes through `apply_transform_with_ctx` so the per-request ctx
/// fields (content shape, markdown projection, canonical URL, CEL
/// header mutations) behave exactly as they do for an upstream body.
///
/// A failing transform is routed the same way the proxied path and the
/// plugin-action path route one, in the same order: first
/// [`transform_error_is_unconditional_500`], which promotes a host
/// invariant violation to a 500 whatever the posture says, and only then
/// the transform's own `failure_posture`. The earlier reasoning for
/// warning and continuing here was that a generated body is
/// operator-authored, so there is nothing untrusted to fail closed
/// against. That does not survive a bundle transform: the untrusted
/// party is the *transform*, and a redaction transform that faults on a
/// `static` body ships the exact string it existed to strip. `open`
/// keeps the warn-and-continue behavior, which is what a `transforms:`
/// entry defaults to when neither the attachment nor the bundle says
/// otherwise.
fn apply_origin_transforms_to_generated_body(
    pipeline: &CompiledPipeline,
    origin_idx: Option<usize>,
    ctx: &mut RequestContext,
    body: Bytes,
    content_type: &str,
) -> GeneratedBodyTransformOutcome {
    let unchanged = |body: Bytes| GeneratedBodyTransformOutcome {
        body,
        terminal_failure: false,
    };
    let Some(idx) = origin_idx else {
        return unchanged(body);
    };
    if idx >= pipeline.transforms.len() || pipeline.transforms[idx].is_empty() {
        return unchanged(body);
    }
    let mut buf = bytes::BytesMut::from(&body[..]);
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
        if let Err(e) =
            apply_transform_with_ctx(compiled_transform, &mut buf, Some(content_type), ctx)
        {
            let transform_name = compiled_transform.transform.transform_type();
            // Substituting the body before returning is what makes a
            // refusal safe: the caller serves whatever is in this
            // buffer, and serving the untransformed generated body
            // would deliver exactly the bytes the refusal exists to
            // withhold.
            let refuse = |ctx: &mut RequestContext| {
                ctx.transform_error_attribution = Some(transform_name.to_string());
                GeneratedBodyTransformOutcome {
                    body: Bytes::from_static(b"{\"error\":\"internal server error\"}"),
                    terminal_failure: true,
                }
            };
            // The invariant carve-out comes first, ahead of the posture,
            // the same order `apply_plugin_action_response_transforms`
            // and the upstream body filter use. A typed `TransformError`
            // that is not a dynamic bundle hook's own is a host bug, not
            // a policy outcome, so no posture admits it (WOR-168,
            // WOR-2268). Consulting the shared predicate rather than
            // re-deriving the rule here is the point: it is the thing
            // that keeps the three response paths from drifting.
            if transform_error_is_unconditional_500(compiled_transform, &e) {
                tracing::error!(
                    hostname = %ctx.hostname,
                    transform = transform_name,
                    error = %e,
                    "generated-response transform invariant violated, returning a generic response"
                );
                return refuse(ctx);
            }
            // Read the resolved posture off the compiled transform, never
            // the legacy `fail_on_error` wire boolean, the same way the
            // proxied body filter does.
            let posture = compiled_transform.failure_posture;
            if posture == sbproxy_config::FailureMode::Closed {
                warn!(
                    hostname = %ctx.hostname,
                    transform = transform_name,
                    error = %e,
                    failure_posture = posture.as_label(),
                    "generated-response transform failed; response failed by failure_posture"
                );
                return refuse(ctx);
            }
            // `hostname` is not decoration here: `open` is the default
            // posture for a `transforms:` entry, so this is the line an
            // operator actually sees, and a config with many static
            // origins needs it to say which one dropped a transform.
            warn!(
                hostname = %ctx.hostname,
                transform = transform_name,
                error = %e,
                failure_posture = posture.as_label(),
                "generated-response transform failed, continuing"
            );
        }
    }
    unchanged(buf.freeze())
}

/// Apply the response-phase policy surface to a locally generated
/// response, right before it is written to the client.
///
/// `static`, `mock`, `echo`, `beacon`, and `redirect` actions answer
/// during the request phase and never reach Pingora's `response_filter`
/// / `response_body_filter`, so until WOR-2496 every response-phase
/// policy silently no-opped for them: the config compiled, the policy
/// chain logged `verdict=allow`, and the header or scan the operator
/// asked for never happened. This helper runs the subset of the
/// response phase that is meaningful for a generated response, in the
/// same order the proxied path applies it:
///
/// 1. `security_headers` policy headers (plus `x-csp-nonce` when nonce
///    mode is on)
/// 2. `page_shield` CSP (its yield check reads the generated response's
///    own CSP header, the analog of "the upstream already sent one")
/// 3. plugin-policy response headers accumulated during the request
///    phase (`AllowWithHeaders`, appended in chain order)
/// 4. the CSRF cookie staged by the csrf enforcer
/// 5. deprecation announcement headers from the route's `deprecation:`
///    block or a spec-driven `openapi_validation` match (WOR-2565)
/// 6. `assertion` policies (the body size is known exactly here, so it
///    is passed instead of the proxied header-phase's `None`)
/// 7. session cookie issuance from the origin's `session:` block
/// 8. the `sri` scan over the final body (observation-only, `text/html`
///    responses under an enforcing policy, identical logging and
///    metrics to the proxied body filter)
///
/// Deliberately not applied here, because they need an upstream
/// exchange to mean anything: on-status fallbacks, retries, meter and
/// idempotency capture, compression negotiation, and gRPC re-framing.
/// Response modifiers and transforms are applied by the action arms
/// themselves before this runs.
///
/// One precedence note: on the proxied path, response modifiers run
/// after policy headers and win same-key collisions; on a generated
/// response the modifiers have already been folded into `header` by the
/// action arm, so a policy-set header wins instead. Operators who need
/// a specific value on a generated response set it on the action or
/// the policy, not both.
fn apply_generated_response_phases(
    session: &Session,
    ctx: &mut RequestContext,
    pipeline: &CompiledPipeline,
    origin_idx: Option<usize>,
    header: &mut ResponseHeader,
    body: &[u8],
) {
    let Some(idx) = origin_idx else {
        return;
    };
    let policies = pipeline.policies.get(idx);

    // 1 + 2. security_headers and page_shield. The CSP-presence
    // snapshot is taken before either policy writes, mirroring the
    // proxied path where `upstream_has_csp` reads the raw upstream
    // header map rather than the pending mutation set.
    if let Some(policies) = policies {
        let generated_has_csp = header
            .headers
            .contains_key(http::header::CONTENT_SECURITY_POLICY)
            || header
                .headers
                .contains_key("content-security-policy-report-only");
        for policy in policies {
            if let Policy::SecHeaders(sec) = policy {
                let path = session.req_header().uri.path();
                let (headers, nonce) = sec.resolved_headers_for_request(path);
                for (name, value) in headers {
                    if let Some(mode) = csp_emission_mode(&name) {
                        sbproxy_observe::metrics::record_security_headers_csp_emitted(
                            mode,
                            ctx.tenant_id.as_ref(),
                        );
                    }
                    let _ = header.insert_header(name, &value);
                }
                if let Some(n) = nonce {
                    let _ = header.insert_header("x-csp-nonce", &n);
                }
            }
            if let Policy::PageShield(shield) = policy {
                if !shield.yields_to_upstream(generated_has_csp) {
                    let host = session
                        .req_header()
                        .headers
                        .get("host")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    let (name, value) = shield.header(host);
                    let _ = header.insert_header(name, value);
                }
            }
        }
    }

    // 3. Plugin-policy response headers, appended in chain order so
    // multi-value contracts survive (same drain the proxied path runs).
    for (key, value) in std::mem::take(&mut ctx.policy_response_headers) {
        let _ = header.append_header(key, &value);
    }

    // 4. CSRF cookie staged by the csrf enforcer during the request
    // phase.
    if let Some(ref cookie) = ctx.csrf_cookie {
        let _ = header.append_header("set-cookie", cookie);
    }

    // 5. WOR-2565: deprecation announcement headers (RFC 9745
    // `Deprecation`, RFC 8594 `Sunset`, the `successor-version` /
    // `deprecation` Link relations). Resolved the same way the proxied
    // response filter resolves them (forward-rule block, origin block,
    // then a spec-driven `openapi_validation` match), so static, mock,
    // redirect, and post-sunset 410 responses announce exactly like
    // proxied ones. Stamped before the assertions so an assertion can
    // observe them.
    if let Some(resolved) = deprecation::resolved_deprecation(
        pipeline,
        idx,
        ctx.forward_rule_idx,
        ctx.openapi_deprecation.as_ref(),
    ) {
        for (name, value) in deprecation::response_headers(resolved.config) {
            if name == "link" {
                let _ = header.append_header(name, &value);
            } else {
                let _ = header.insert_header(name, &value);
            }
        }
    }

    // 6. Assertions: observational only, never block or modify. Unlike
    // the proxied header phase, the full body is in hand, so its size
    // is passed to the CEL context.
    if let Some(policies) = policies {
        if policies.iter().any(|p| matches!(p, Policy::Assertion(_))) {
            let req = session.req_header();
            let method = req.method.as_str();
            let path = req.uri.path();
            let query = req.uri.query();
            let client_ip = ctx.client_ip.map(|ip| ip.to_string());
            let resp_status = header.status.as_u16();
            for policy in policies {
                if let Policy::Assertion(a) = policy {
                    let passed = a.evaluate_with_trust_tier(
                        method,
                        path,
                        &req.headers,
                        query,
                        client_ip.as_deref(),
                        &ctx.hostname,
                        resp_status,
                        &header.headers,
                        Some(body.len()),
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
        }
    }

    // 7. Session cookie: issue when the origin configures a `session:`
    // block and the client did not already present the cookie.
    {
        let origin = &pipeline.config.origins[idx];
        if let Some(ref session_cfg) = origin.session {
            let cookie_name = session_cfg.cookie_name.as_deref().unwrap_or("sbproxy_sid");
            let has_cookie = session
                .req_header()
                .headers
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .map(|cookies| {
                    cookies.split(';').any(|c| {
                        let c = c.trim();
                        c.starts_with(cookie_name) && c[cookie_name.len()..].starts_with('=')
                    })
                })
                .unwrap_or(false);
            if !has_cookie {
                let sid = uuid::Uuid::new_v4().to_string();
                let cookie_val = build_session_cookie(session_cfg, &sid);
                let _ = header.append_header("set-cookie", &cookie_val);
            }
        }
    }

    // 8. SRI scan over the final body. Same gate and semantics as the
    // proxied body filter: only under an enforcing policy, only for
    // text/html, observation-only (log + metric, no mutation).
    if let Some(policies) = policies {
        let ct = header
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let is_html = ct
            .split(';')
            .next()
            .map(|t| t.trim().eq_ignore_ascii_case("text/html"))
            .unwrap_or(false);
        let any_sri_enforcing = policies
            .iter()
            .any(|p| matches!(p, Policy::Sri(s) if s.enforce));
        if is_html && any_sri_enforcing {
            for policy in policies {
                if let Policy::Sri(s) = policy {
                    match s.check_html_body(body, ct) {
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
                            sbproxy_observe::metrics::record_policy(&ctx.hostname, "sri", "clean");
                        }
                        sbproxy_modules::SriCheckResult::NotApplicable => {}
                    }
                }
            }
        }
    }
}

// --- Callback firing ---
//
// Webhook/callback/mirror dispatch lives in the `callbacks`
// submodule. The glob re-import keeps call sites unchanged.
mod callbacks;
use callbacks::*;

// --- Bounded downstream body reads ---
//
// Shared by every action that finishes inside `request_filter` and so
// never reaches `request_body_filter`'s streaming cap (WOR-2616,
// WOR-2628). Named rather than glob re-imported: the dispatch
// submodules import the items they call by name, so a reader can see
// where a body cap came from.
mod downstream_body;

// --- AI proxy helpers ---
pub(crate) mod ai_classifier;

pub(crate) mod ai_support;
use ai_support::*;

mod ai_dispatch;
use ai_dispatch::*;

// WOR-1722: cluster-shared AI budget counters (optional Redis backend).
pub(crate) mod budget_share;

// WOR-1680: process-global local model host for serve: providers.
pub(crate) mod model_host;

// --- Non-proxy action handlers ---

mod action_dispatch;
/// First-class API deprecation: RFC 9745 `Deprecation`, RFC 8594
/// `Sunset`, the Link relations, the deprecated-usage metric, and the
/// post-sunset `gone` posture (WOR-2565).
pub(crate) mod deprecation;
use action_dispatch::*;

// Dispatch-side glue for the MCP tool rollout plane (versioned
// catalogue views, per-consumer routing, adapters, sunset).
pub(crate) mod mcp_rollout;

// WOR-2118: agent-to-agent checks that need the request body. They
// live at the body phase because `build_plugin_request_snapshot` above
// always hands enforcers an empty body, so the request-filter surface
// cannot run them.
pub(crate) mod a2a_body_phase;

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
// `pub(crate)` because pipeline construction compiles this module's CEL
// log fields once per config publication (WOR-2164).
pub(crate) mod custom_log;

mod lifecycle;
pub use lifecycle::*;

#[cfg(test)]
mod tests;

/// WOR-2477: a panicking policy enforcer must be contained at both
/// dispatch seams that call `PolicyEnforcer::enforce` (fail-closed 500,
/// not a crashed proxy): the header-phase `check_policies` and the
/// buffered-body-phase `check_buffered_dynamic_policies`. Kept as its
/// own module, separate from `mod tests` above, so it stays
/// self-contained inside this file.
#[cfg(test)]
mod wor_2477_panic_containment_tests {
    use std::future::Future;
    use std::pin::Pin;

    use pingora_core::protocols::l4::stream::Stream;
    use sbproxy_config::{BundleBodyMode, BundleRuntime, FailureMode};
    use sbproxy_modules::DynamicHookMetadata;
    use sbproxy_observe::decision::DecisionEngine;
    use sbproxy_observe::events::PolicySurface;
    use sbproxy_plugin::{PluginResult, PolicyDecision, PolicyEnforcer};
    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::builtin_enforcers::CompiledEnforcer;

    /// Stands in for a tenant policy with a real bug: every call
    /// unwinds instead of returning a decision. The label is carried
    /// per-instance so the header-phase and buffered-phase tests below
    /// record on distinct `policy` series and can never race each
    /// other's before/after counter snapshot.
    struct PanickingEnforcer(&'static str);

    impl PolicyEnforcer for PanickingEnforcer {
        fn policy_type(&self) -> &str {
            self.0
        }

        fn enforce(
            &self,
            _req: &http::Request<Bytes>,
            _ctx: &mut dyn std::any::Any,
        ) -> Pin<Box<dyn Future<Output = PluginResult<PolicyDecision>> + Send + '_>> {
            Box::pin(async { panic!("simulated tenant policy bug (WOR-2477 test fixture)") })
        }
    }

    /// Current value of `sbproxy_policy_panic_total{policy=<policy>}`,
    /// 0.0 if the series has not been recorded yet. Mirrors the
    /// `gathered_series` helper in `sbproxy_observe::metrics`'s own
    /// tests, which this crate cannot reach directly since it is
    /// private to that crate's test module.
    fn panic_counter_value(policy: &str) -> f64 {
        for family in prometheus::gather() {
            if family.name() != "sbproxy_policy_panic_total" {
                continue;
            }
            for metric in family.get_metric() {
                let matches = metric
                    .get_label()
                    .iter()
                    .any(|pair| pair.name() == "policy" && pair.value() == policy);
                if matches {
                    return metric.get_counter().value();
                }
            }
        }
        0.0
    }

    /// Real (loopback) Pingora `Session` around a minimal GET request.
    /// Same fixture shape `server/action_dispatch.rs` and
    /// `server/ai_dispatch.rs` already use to drive dispatch functions
    /// that take `&Session` outside of a live proxy: bind a listener,
    /// have a client task write a raw HTTP/1.1 request, accept it, and
    /// let Pingora parse its own downstream half.
    async fn test_session() -> Session {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind downstream fixture");
        let address = listener.local_addr().expect("downstream address");
        tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect downstream fixture");
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: wor-2477-panic-test.example\r\n\r\n")
                .await
                .expect("write request");
        });
        let (stream, _) = listener.accept().await.expect("accept downstream");
        let mut session = Session::new_h1(Box::new(Stream::from(stream)));
        session
            .as_downstream_mut()
            .read_request()
            .await
            .expect("parse downstream request");
        session
    }

    /// Drives a panicking enforcer through the real `check_policies`
    /// dispatch seam (not a re-implementation of it) and asserts the
    /// panic is contained: the request is denied closed with a 500,
    /// `sbproxy_policy_panic_total` rises for the panicking policy's
    /// label, and this test function itself returns normally, proving
    /// the panic never escaped the dispatch loop to crash the runtime.
    #[tokio::test]
    async fn panicking_policy_enforcer_is_contained_and_counted() {
        let policy_label = "wor_2477_panic_fixture";
        let enforcers = vec![CompiledEnforcer {
            surface: PolicySurface::Plugin,
            engine: DecisionEngine::Plugin,
            enforcer: Box::new(PanickingEnforcer(policy_label)),
            dynamic_hook: None,
            shared_admission: None,
        }];
        let mut ctx = RequestContext::new();
        let verdict_ctx = PolicyVerdictCtx {
            request_id: "wor-2477-test".to_string(),
            workspace_id: String::new(),
            origin: "wor-2477-test-origin".to_string(),
            tenant: "wor-2477-test-tenant".to_string(),
            record_format: sbproxy_config::types::PolicyRecordFormat::default(),
        };
        let before = panic_counter_value(policy_label);

        let session = test_session().await;
        let result = check_policies(&enforcers, &session, &mut ctx, &verdict_ctx).await;

        assert_eq!(
            result,
            Some((500, "policy enforcer panicked".to_string(), "plugin")),
            "a panicking enforcer must fail the request closed with a 500, not crash the proxy"
        );
        assert_eq!(
            panic_counter_value(policy_label),
            before + 1.0,
            "sbproxy_policy_panic_total did not rise for the panicking policy"
        );
    }

    /// Same containment property, driven through the buffered-body seam
    /// (`check_buffered_dynamic_policies`) instead of the header-phase
    /// one. Reuses the exact two-call sequence production code uses: the
    /// header-phase `check_policies` call primes
    /// `ctx.dynamic_request_body_plan` from each enforcer's
    /// `dynamic_hook` (a `Buffered`-mode hook makes `check_policies`
    /// skip enforcing it and instead mark it active for the body
    /// phase), then `check_buffered_dynamic_policies` consumes that
    /// plan once the body is available and is where the panic actually
    /// fires.
    #[tokio::test]
    async fn panicking_buffered_dynamic_policy_enforcer_is_contained_and_counted() {
        let policy_label = "wor_2477_panic_fixture_buffered";
        let dynamic_hook = DynamicHookMetadata::new(
            "wor-2477-test-bundle",
            "policy",
            BundleRuntime::Javascript,
            BundleBodyMode::Buffered,
            65_536,
            FailureMode::Closed,
        );
        let enforcers = vec![CompiledEnforcer {
            surface: PolicySurface::Plugin,
            engine: DecisionEngine::Plugin,
            enforcer: Box::new(PanickingEnforcer(policy_label)),
            dynamic_hook: Some(dynamic_hook),
            shared_admission: None,
        }];
        let mut ctx = RequestContext::new();
        let verdict_ctx = PolicyVerdictCtx {
            request_id: "wor-2477-test-buffered".to_string(),
            workspace_id: String::new(),
            origin: "wor-2477-test-origin".to_string(),
            tenant: "wor-2477-test-tenant".to_string(),
            record_format: sbproxy_config::types::PolicyRecordFormat::default(),
        };
        let before = panic_counter_value(policy_label);

        let session = test_session().await;
        // Header phase: skips enforcing the buffered-mode hook (it has
        // no body yet) but records it as an active buffered policy on
        // `ctx.dynamic_request_body_plan`, exactly as production does
        // between the header and body phases of one request.
        let header_result = check_policies(&enforcers, &session, &mut ctx, &verdict_ctx).await;
        assert_eq!(
            header_result, None,
            "a Buffered-mode hook must not be enforced in the header phase"
        );

        // Body phase: the panic fires here.
        let result = check_buffered_dynamic_policies(
            &enforcers,
            &session,
            &mut ctx,
            Bytes::new(),
            &verdict_ctx,
        )
        .await;

        assert_eq!(
            result,
            Some((500, "policy enforcer panicked".to_string(), "plugin")),
            "a panicking buffered-phase enforcer must fail the request closed with a 500, \
             not crash the proxy"
        );
        assert_eq!(
            panic_counter_value(policy_label),
            before + 1.0,
            "sbproxy_policy_panic_total did not rise for the panicking buffered policy"
        );
    }
}

/// A generated (`static` / `mock`) response body goes through the same
/// origin transform chain a proxied body does, so a transform that
/// faults there has to reach the same `failure_posture`.
///
/// Retrospective review of PR #1153 found it did not: every fault was a
/// `warn!` and the loop continued with the untransformed buffer, so a
/// redaction transform declared `closed` shipped the exact bytes it
/// existed to strip.
#[cfg(test)]
mod generated_body_failure_posture_tests {
    use super::*;
    use sbproxy_config::FailureMode;

    /// A `static` origin serving a secret-bearing body, with one
    /// transform whose posture the caller picks. The transform is
    /// replaced wholesale rather than written into the YAML so the test
    /// controls the posture and the fault independently of what any
    /// built-in transform's config validation allows.
    fn static_origin_pipeline(posture: FailureMode) -> crate::pipeline::CompiledPipeline {
        let inner =
            sbproxy_modules::transform::HtmlToMarkdownTransform::from_config(serde_json::json!({}))
                .expect("default html_to_markdown");
        static_origin_pipeline_with(
            posture,
            sbproxy_modules::transform::Transform::HtmlToMarkdown(inner),
        )
    }

    /// The same fixture with the transform itself supplied, so a test
    /// can pick the *kind* of fault as well as the posture.
    fn static_origin_pipeline_with(
        posture: FailureMode,
        transform: sbproxy_modules::transform::Transform,
    ) -> crate::pipeline::CompiledPipeline {
        const YAML: &str = r#"
origins:
  "status.example":
    action:
      type: static
      status: 200
      content_type: text/plain
      body: "placeholder"
"#;
        let config = sbproxy_config::compile_config(YAML).expect("fixture config");
        let mut pipeline =
            crate::pipeline::CompiledPipeline::from_config(config).expect("fixture pipeline");
        pipeline.transforms = vec![vec![sbproxy_modules::transform::CompiledTransform {
            transform,
            content_types: Vec::new(),
            failure_posture: posture,
            max_body_size: 1024,
        }]];
        pipeline
    }

    /// A linked (not bundle-supplied) transform with a host-side bug.
    /// `dispatch_plugin` turns the unwind into
    /// `TransformError::Plugin`, and because the plugin declares no
    /// posture of its own, `transform_error_is_unconditional_500` says
    /// no posture may admit it.
    struct PanickingLinkedTransform;

    impl sbproxy_plugin::TransformHandler for PanickingLinkedTransform {
        fn transform_type(&self) -> &str {
            "wor168_panicking_transform"
        }

        fn apply<'a>(
            &'a self,
            _body: &'a mut bytes::BytesMut,
            _content_type: Option<&'a str>,
            _ctx: &'a sbproxy_plugin::TransformContext,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = sbproxy_plugin::PluginResult<()>> + Send + 'a>,
        > {
            Box::pin(async { panic!("host invariant violated") })
        }
    }

    /// Invalid UTF-8 makes `html_to_markdown` fault deterministically
    /// and synchronously. It stands in for the failure scenario's
    /// budget-exceeded Rego scrub: what matters is that the transform
    /// returned an error without touching the body.
    const SECRET_BODY: &[u8] = b"\xffbuild=abcdef1 key=sk-live-9f2c0a4b";

    #[test]
    fn a_closed_transform_that_faults_on_a_generated_body_refuses_to_serve_it() {
        let pipeline = static_origin_pipeline(FailureMode::Closed);
        let mut ctx = RequestContext::new();

        let outcome = apply_origin_transforms_to_generated_body(
            &pipeline,
            Some(0),
            &mut ctx,
            Bytes::from_static(SECRET_BODY),
            "text/plain",
        );

        assert!(
            outcome.terminal_failure,
            "a closed transform's fault must fail the generated response"
        );
        assert!(
            !outcome.body.windows(7).any(|window| window == b"sk-live"),
            "the untransformed body must not reach the client: {:?}",
            outcome.body
        );
        assert_eq!(
            ctx.transform_error_attribution.as_deref(),
            Some("html_to_markdown"),
            "the refusal must name the transform that caused it"
        );
    }

    #[test]
    fn an_open_transform_that_faults_on_a_generated_body_still_continues() {
        let pipeline = static_origin_pipeline(FailureMode::Open);
        let mut ctx = RequestContext::new();

        let outcome = apply_origin_transforms_to_generated_body(
            &pipeline,
            Some(0),
            &mut ctx,
            Bytes::from_static(SECRET_BODY),
            "text/plain",
        );

        assert!(
            !outcome.terminal_failure,
            "an open transform's fault admits, exactly as it did before"
        );
        assert_eq!(
            outcome.body.as_ref(),
            SECRET_BODY,
            "an open posture passes the untransformed body through unchanged"
        );
        assert!(ctx.transform_error_attribution.is_none());
    }

    /// A typed `TransformError` from a host-side bug is a 500 whatever
    /// the posture says, because the operator's `open` is a statement
    /// about the transform's own failures and not about the proxy's.
    ///
    /// The upstream body filter and the plugin-action path have both
    /// held this since WOR-168; the generated-body path was the one that
    /// did not, so an `open` invariant violation on a `static` origin
    /// served the untransformed body with a `200` while the identical
    /// config on a `type: proxy` origin got the 500.
    #[test]
    fn an_open_transform_whose_host_invariant_breaks_is_still_a_500_on_a_generated_body() {
        let pipeline = static_origin_pipeline_with(
            FailureMode::Open,
            sbproxy_modules::transform::Transform::Plugin(
                sbproxy_modules::PluginTransform::linked(Box::new(PanickingLinkedTransform)),
            ),
        );
        let mut ctx = RequestContext::new();

        let outcome = apply_origin_transforms_to_generated_body(
            &pipeline,
            Some(0),
            &mut ctx,
            Bytes::from_static(SECRET_BODY),
            "text/plain",
        );

        assert!(
            outcome.terminal_failure,
            "an invariant violation is a 500 under every posture, `open` included"
        );
        assert!(
            !outcome.body.windows(7).any(|window| window == b"sk-live"),
            "the untransformed body must not reach the client: {:?}",
            outcome.body
        );
        assert_eq!(
            ctx.transform_error_attribution.as_deref(),
            Some("wor168_panicking_transform"),
        );
    }

    /// The same predicate, asked directly, so the test above cannot go
    /// green for the wrong reason (an `open` posture that started
    /// refusing everything would also pass it).
    #[test]
    fn an_ordinary_open_transform_fault_is_not_promoted() {
        let pipeline = static_origin_pipeline(FailureMode::Open);
        let compiled = &pipeline.transforms[0][0];
        assert!(
            !transform_error_is_unconditional_500(compiled, &anyhow::anyhow!("plain failure")),
            "an untyped failure is the transform's own, and `open` admits it"
        );
    }
}
