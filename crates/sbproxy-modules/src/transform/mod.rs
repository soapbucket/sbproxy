//! Transform module - enum dispatch for built-in transform handlers.
//!
//! Provides JSON manipulation transforms (set/remove/rename fields,
//! field projection, schema validation), text transforms (template
//! rendering, string replacement, normalization, encoding, format
//! conversion), control transforms (payload limits, discard, SSE
//! chunking), and a pipeline wrapper that controls content-type
//! matching and error behavior.

mod a2a_agent_card_rewrite;
mod boilerplate;
mod cel_script;
mod citation_block;
mod control;
mod json;
mod json_envelope;
pub mod llms_txt;
mod markup;
mod text;

pub use a2a_agent_card_rewrite::{
    rewrite_card_urls, A2aAgentCardRewriteConfig, A2aAgentCardRewriter, DEFAULT_AGENT_CARD_PATHS,
};
pub use boilerplate::{BoilerplateConfig, BoilerplateTransform};
pub use cel_script::{
    AgentClassView, CelHeaderMutation, CelHeaderOp, CelHeaderRule, CelResponseRequestView,
    CelScriptTransform, HeadlessSignalView, TlsFingerprintView, HEADER_DENY_LIST,
    HEADER_EVAL_BUDGET,
};
pub use citation_block::{CitationBlockConfig, CitationBlockTransform};
pub use control::{DiscardTransform, PayloadLimitTransform, SseChunkingTransform};
pub use json::{JsonProjectionTransform, JsonSchemaTransform, JsonTransform};
pub use json_envelope::{
    JsonEnvelope, JsonEnvelopeTransform, JSON_ENVELOPE_CONTENT_TYPE, JSON_ENVELOPE_PROFILE,
    JSON_ENVELOPE_SCHEMA_VERSION,
};
pub use markup::{
    CssTransform, HtmlToMarkdownTransform, HtmlTransform, MarkdownProjection, MarkdownTransform,
    OptimizeHtmlTransform, DEFAULT_TOKEN_BYTES_RATIO,
};
pub use text::{
    EncodingTransform, FormatConvertTransform, NormalizeTransform, ReplaceStringsTransform,
    TemplateTransform,
};

use bytes::{BufMut, BytesMut};
use sbproxy_config::types::FailureMode;
use sbproxy_plugin::{TransformContext, TransformHandler};
use serde::Deserialize;

// --- Transform error types ---

/// Typed transform errors surfaced by the body-buffer pipeline.
///
/// Most transform helpers return `anyhow::Result<()>` because their
/// failures are operator-config issues (bad regex, malformed JSON,
/// upstream error). This enum exists for the small set of failures
/// that should be promoted to a 500 with attribution rather than the
/// generic "transform failed, continuing with next transform" warn
/// log: pipeline invariants that, if violated, indicate a code bug
/// rather than a config or runtime problem.
///
/// The pipeline downcasts `anyhow::Error` to this enum to spot those
/// cases and emit a typed 500 (`x-sbproxy-transform-error: ...`).
#[derive(Debug, thiserror::Error)]
pub enum TransformError {
    /// A transform reached a state that should be unreachable under
    /// the documented invariants of the pipeline. Reported as a 500
    /// with the transform name attached so the caller and the
    /// operator both know the request was dropped because of a
    /// code-level bug, not a config error.
    #[error("transform invariant violated: {reason}")]
    InvariantViolated {
        /// Human-readable description of the invariant that was
        /// violated. Logged + attached to the response attribution
        /// header.
        reason: String,
    },
    /// A plugin-backed transform's future was either cancelled by
    /// the per-call timeout or panicked while being driven. Reported
    /// as a 500 so a slow / buggy plugin cannot stall the response
    /// or corrupt the body.
    #[error("transform plugin {plugin}: {detail}")]
    Plugin {
        /// Plugin name (`TransformHandler::transform_type()`).
        plugin: String,
        /// Either "timed out after Nms" or "panicked".
        detail: String,
    },
}

// --- Transform Enum ---

/// Transform handler - enum dispatch for built-in types.
/// Each variant holds its compiled config inline (no Box indirection).
pub enum Transform {
    /// Modify JSON by setting, removing, or renaming fields.
    Json(JsonTransform),
    /// Extract or exclude specific fields from JSON.
    JsonProjection(JsonProjectionTransform),
    /// Validate JSON against a schema.
    JsonSchema(JsonSchemaTransform),
    /// Render a template using response body as input data.
    Template(TemplateTransform),
    /// Find-and-replace strings (literal or regex) in the body.
    ReplaceStrings(ReplaceStringsTransform),
    /// Normalize whitespace, newlines, and trim the body.
    Normalize(NormalizeTransform),
    /// Base64 or URL encode/decode the body.
    Encoding(EncodingTransform),
    /// Convert between JSON and YAML formats.
    FormatConvert(FormatConvertTransform),
    /// Enforce a maximum body size (truncate or reject).
    PayloadLimit(PayloadLimitTransform),
    /// Discard the entire response body.
    Discard(DiscardTransform),
    /// Format the body as SSE events with proper chunking.
    SseChunking(SseChunkingTransform),
    /// Manipulate HTML content (inject, remove, rewrite attributes).
    Html(HtmlTransform),
    /// Minify HTML by removing comments and collapsing whitespace.
    OptimizeHtml(OptimizeHtmlTransform),
    /// Convert HTML to Markdown.
    HtmlToMarkdown(HtmlToMarkdownTransform),
    /// Convert Markdown to HTML.
    Markdown(MarkdownTransform),
    /// Manipulate CSS (inject rules, remove selectors, minify).
    Css(CssTransform),
    /// Lua-based JSON transform. Executes a Lua script that receives the
    /// JSON body and returns a modified version.
    LuaJson(LuaJsonTransform),
    /// JavaScript-based body transform. Calls a user-defined JS function
    /// with the raw body string, returning the modified string.
    JavaScript(JavaScriptTransform),
    /// JavaScript-based JSON transform. Calls a user-defined JS function
    /// with the parsed JSON body, returning the modified JSON value.
    JsJson(JsJsonTransform),
    /// WebAssembly-based body transform. Pipes the body through a sandboxed
    /// WASI module's stdin/stdout, returning whatever the module writes back.
    Wasm(WasmTransform),
    /// Boilerplate strip. Removes nav/footer/aside/ad
    /// chrome from HTML before the Markdown projection runs. Runs in
    /// the standard body-buffer pipeline; does not require per-request
    /// context.
    Boilerplate(BoilerplateTransform),
    /// Citation block. Prepends an attribution
    /// blockquote to a Markdown projection. The standard body-buffer
    /// `apply` is a no-op because the transform needs per-request
    /// `RequestContext` fields (`canonical_url`, `rsl_urn`,
    /// `citation_required`) that the simple `(body, content_type)`
    /// signature can't carry. The day-5 response-filter wiring calls
    /// the typed `CitationBlockTransform::apply` with the ctx fields.
    CitationBlock(CitationBlockTransform),
    /// JSON envelope. Wraps a Markdown projection in
    /// the v1 JSON envelope. Same caveat as `CitationBlock`: the
    /// standard body-buffer `apply` is a no-op; day-5 response-filter
    /// wiring calls the typed `JsonEnvelopeTransform::apply` with the
    /// ctx fields.
    JsonEnvelope(JsonEnvelopeTransform),
    /// CEL response-body transform. Evaluates a
    /// CEL expression against `response.body` / `response.status` /
    /// `response.headers` and replaces the body with the result. Used
    /// by the e2e tests to stamp `request.tls.ja4` /
    /// `request.kya.verdict` back into the response body for
    /// assertions.
    CelScript(CelScriptTransform),
    /// Rewrites the `url` / `endpoint` / `agent.url` fields
    /// on A2A agent-card responses so MCP and A2A clients route
    /// follow-up calls through the proxy instead of jumping straight
    /// at the upstream. Same caveat as `CitationBlock`: the standard
    /// body-buffer `apply` is a no-op; the typed dispatch arm in
    /// sbproxy-core calls `apply_with_path` with the request path and
    /// proxy host from the request context (WOR-2315).
    A2aAgentCardRewrite(A2aAgentCardRewriter),
    /// No transformation applied.
    Noop,
    /// Third-party plugin (only case using dynamic dispatch).
    ///
    /// Carries the bundle's manifest metadata when a dynamic bundle
    /// supplied the handler, so the response pipeline can read the
    /// declared failure posture. A linked plugin has no manifest and
    /// leaves it unset.
    Plugin(crate::PluginTransform),
}

impl Transform {
    /// Get the type name for this transform.
    pub fn transform_type(&self) -> &str {
        match self {
            Self::Json(_) => "json",
            Self::JsonProjection(_) => "json_projection",
            Self::JsonSchema(_) => "json_schema",
            Self::Template(_) => "template",
            Self::ReplaceStrings(_) => "replace_strings",
            Self::Normalize(_) => "normalize",
            Self::Encoding(_) => "encoding",
            Self::FormatConvert(_) => "format_convert",
            Self::PayloadLimit(_) => "payload_limit",
            Self::Discard(_) => "discard",
            Self::SseChunking(_) => "sse_chunking",
            Self::Html(_) => "html",
            Self::OptimizeHtml(_) => "optimize_html",
            Self::HtmlToMarkdown(_) => "html_to_markdown",
            Self::Markdown(_) => "markdown",
            Self::Css(_) => "css",
            Self::LuaJson(_) => "lua_json",
            Self::JavaScript(_) => "javascript",
            Self::JsJson(_) => "js_json",
            Self::Wasm(_) => "wasm",
            Self::Boilerplate(_) => "boilerplate",
            Self::CitationBlock(_) => "citation_block",
            Self::JsonEnvelope(_) => "json_envelope",
            Self::CelScript(_) => "cel",
            Self::A2aAgentCardRewrite(_) => "a2a_agent_card_rewrite",
            Self::Noop => "noop",
            Self::Plugin(p) => p.handler().transform_type(),
        }
    }

    /// Whether this transform's output depends on the incoming request.
    ///
    /// A request-independent transform is a pure function of the
    /// response body, the response content type, and its static
    /// config, so its output can be computed once and stored (the
    /// response cache's ingest pass) or recomputed with no request in
    /// scope (the stale-while-revalidate refresh). A request-dependent
    /// transform reads request state, through the ctx arms of the
    /// dispatcher in `sbproxy-core`, so caching its output would bake
    /// one requester's context into a shared entry.
    ///
    /// Review this method together with `apply_transform_with_ctx` in
    /// `sbproxy-core`: every variant with a non-wildcard arm there is
    /// request-dependent except `Boilerplate`, whose arm only writes a
    /// stripped-bytes metric back onto the context and reads nothing
    /// from it. `Plugin` is conservatively dependent: the guest is
    /// arbitrary out-of-tree code with no purity declaration, even
    /// though the context it receives today is empty.
    pub fn request_dependent(&self) -> bool {
        match self {
            Self::HtmlToMarkdown(_)
            | Self::CitationBlock(_)
            | Self::JsonEnvelope(_)
            | Self::CelScript(_)
            | Self::A2aAgentCardRewrite(_)
            | Self::LuaJson(_)
            | Self::JavaScript(_)
            | Self::JsJson(_)
            | Self::Plugin(_) => true,
            Self::Json(_)
            | Self::JsonProjection(_)
            | Self::JsonSchema(_)
            | Self::Template(_)
            | Self::ReplaceStrings(_)
            | Self::Normalize(_)
            | Self::Encoding(_)
            | Self::FormatConvert(_)
            | Self::PayloadLimit(_)
            | Self::Discard(_)
            | Self::SseChunking(_)
            | Self::Html(_)
            | Self::OptimizeHtml(_)
            | Self::Markdown(_)
            | Self::Css(_)
            | Self::Wasm(_)
            | Self::Boilerplate(_)
            | Self::Noop => false,
        }
    }

    /// Apply this transform to a body buffer.
    pub fn apply(&self, body: &mut BytesMut, content_type: Option<&str>) -> anyhow::Result<()> {
        match self {
            Self::Json(t) => t.apply(body),
            Self::JsonProjection(t) => t.apply(body),
            Self::JsonSchema(t) => t.apply(body),
            Self::Template(t) => t.apply(body),
            Self::ReplaceStrings(t) => t.apply(body),
            Self::Normalize(t) => t.apply(body),
            Self::Encoding(t) => t.apply(body),
            Self::FormatConvert(t) => t.apply(body),
            Self::PayloadLimit(t) => t.apply(body),
            Self::Discard(t) => t.apply(body),
            Self::SseChunking(t) => t.apply(body),
            Self::Html(t) => t.apply(body),
            Self::OptimizeHtml(t) => t.apply(body),
            Self::HtmlToMarkdown(t) => t.apply(body),
            Self::Markdown(t) => t.apply(body),
            Self::Css(t) => t.apply(body),
            Self::LuaJson(t) => t.apply(body),
            Self::JavaScript(t) => t.apply(body),
            Self::JsJson(t) => t.apply(body),
            Self::Wasm(t) => t.apply(body),
            Self::Boilerplate(t) => {
                // G4.10: byte count goes onto ctx.metrics in the
                // response-filter wiring; the standard pipeline path
                // discards it.
                t.apply(body).map(|_| ())
            }
            // G4.10 / G4.4 / WOR-2315: these three transforms need
            // per-request context (canonical_url, rsl_urn,
            // citation_required, request path) that the standard
            // body-buffer signature can't carry. The response-filter
            // wiring (`apply_transform_with_ctx` in sbproxy-core)
            // invokes the typed methods directly with the ctx fields.
            // They are no-ops here so the YAML schema accepts them
            // and the chain compiles end-to-end.
            Self::CitationBlock(_) | Self::JsonEnvelope(_) | Self::A2aAgentCardRewrite(_) => Ok(()),
            // WOR-2362: the CEL transform produces header mutations, not
            // a body. Its `on_response:` body-replacement path is
            // refused at config compile, so there is nothing for the
            // body-buffer signature to do here. Header rules are
            // evaluated by the response-filter wiring in `sbproxy-core`.
            Self::CelScript(_) => Ok(()),
            Self::Noop => Ok(()),
            Self::Plugin(handler) => dispatch_plugin(handler.handler(), body, content_type),
        }
    }
}

/// Hard wall-clock cap on a single plugin transform invocation
///. A misbehaving plugin should never be able to stall the
/// response pipeline indefinitely; once this elapses the dispatcher
/// surfaces a `TransformError::Plugin` and the body-buffer pipeline
/// maps it to a 500 with attribution.
pub const PLUGIN_TRANSFORM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Dispatch a `Transform::Plugin` to the held `TransformHandler`.
///
/// The trait's `apply` is async; the transform pipeline runs from
/// sync response-filter call sites. WOR-168 replaces the previous
/// `futures::executor::block_on` (which deadlocks plugins that try
/// to use the surrounding tokio runtime, and explodes on plugin
/// panics) with two safer paths:
///
/// 1. **Inside a tokio runtime** (the production case from a Pingora
///    worker): `tokio::task::block_in_place` lets us drive the
///    plugin future on the surrounding runtime via
///    `Handle::current().block_on(timeout(...))`. The
///    `block_in_place` call moves this thread off the runtime's
///    pollable-worker pool while the future runs, so other tasks
///    on the runtime keep making progress. This pattern is the same
///    one the proxy already uses for its pipeline lifecycle hook
///    (see `crates/sbproxy-core/src/server.rs::reload`).
/// 2. **Outside a tokio runtime** (the test case from `#[test]`): a
///    fresh current-thread runtime is built per call to drive the
///    future. Construction is cheap; tests that exercise this path
///    are the only callers that pay for it.
///
/// Both paths wrap the future in `tokio::time::timeout` for the
/// wall-clock cap and `AssertUnwindSafe(...).catch_unwind()` for the
/// panic guard. Either failure surfaces as `TransformError::Plugin`,
/// which the body-buffer pipeline maps to a 500 with attribution.
fn dispatch_plugin(
    handler: &dyn TransformHandler,
    body: &mut BytesMut,
    content_type: Option<&str>,
) -> anyhow::Result<()> {
    dispatch_plugin_within(handler, body, content_type, PLUGIN_TRANSFORM_TIMEOUT)
}

/// [`dispatch_plugin`] with the wall-clock cap supplied by the caller.
///
/// Production always goes through [`dispatch_plugin`], which passes
/// [`PLUGIN_TRANSFORM_TIMEOUT`]. The cap is a parameter only so the timeout
/// test can put the deadline a few hundred milliseconds out instead of waiting
/// out the full production cap. That keeps the test on the real clock, so it
/// still proves the timer actually fires, and avoids a global override that
/// other tests in the same process could observe.
fn dispatch_plugin_within(
    handler: &dyn TransformHandler,
    body: &mut BytesMut,
    content_type: Option<&str>,
    timeout: std::time::Duration,
) -> anyhow::Result<()> {
    let plugin_name = handler.transform_type().to_string();
    let ctx = TransformContext::empty();
    use futures::FutureExt;
    let future = std::panic::AssertUnwindSafe(async {
        tokio::time::timeout(timeout, handler.apply(body, content_type, &ctx)).await
    })
    .catch_unwind();

    let outcome = if tokio::runtime::Handle::try_current().is_ok() {
        // Production path: we're on a tokio worker. `block_in_place`
        // turns this worker into a blocking thread for the duration
        // of the call; other workers stay live and keep polling
        // tasks on the same runtime.
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
    } else {
        // Test path: no enclosing runtime, build a one-shot.
        match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt.block_on(future),
            Err(e) => {
                return Err(anyhow::Error::new(TransformError::Plugin {
                    plugin: plugin_name.clone(),
                    detail: format!("could not build dispatch runtime: {e}"),
                }));
            }
        }
    };

    match outcome {
        // Plugin returned a normal result. Map the typed PluginError back into
        // anyhow for this dispatcher's return type; the error chain
        // is preserved.
        Ok(Ok(apply_result)) => apply_result.map_err(anyhow::Error::from),
        // tokio::time::timeout fired before the plugin finished.
        Ok(Err(_elapsed)) => Err(anyhow::Error::new(TransformError::Plugin {
            plugin: plugin_name.clone(),
            detail: format!("timed out after {}ms", timeout.as_millis()),
        })),
        // The plugin (or the surrounding future) panicked.
        Err(_panic) => Err(anyhow::Error::new(TransformError::Plugin {
            plugin: plugin_name,
            detail: "panicked".to_string(),
        })),
    }
}

impl std::fmt::Debug for Transform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(t) => f.debug_tuple("Json").field(t).finish(),
            Self::JsonProjection(t) => f.debug_tuple("JsonProjection").field(t).finish(),
            Self::JsonSchema(t) => f.debug_tuple("JsonSchema").field(t).finish(),
            Self::Template(t) => f.debug_tuple("Template").field(t).finish(),
            Self::ReplaceStrings(t) => f.debug_tuple("ReplaceStrings").field(t).finish(),
            Self::Normalize(t) => f.debug_tuple("Normalize").field(t).finish(),
            Self::Encoding(t) => f.debug_tuple("Encoding").field(t).finish(),
            Self::FormatConvert(t) => f.debug_tuple("FormatConvert").field(t).finish(),
            Self::PayloadLimit(t) => f.debug_tuple("PayloadLimit").field(t).finish(),
            Self::Discard(t) => f.debug_tuple("Discard").field(t).finish(),
            Self::SseChunking(t) => f.debug_tuple("SseChunking").field(t).finish(),
            Self::Html(t) => f.debug_tuple("Html").field(t).finish(),
            Self::OptimizeHtml(t) => f.debug_tuple("OptimizeHtml").field(t).finish(),
            Self::HtmlToMarkdown(t) => f.debug_tuple("HtmlToMarkdown").field(t).finish(),
            Self::Markdown(t) => f.debug_tuple("Markdown").field(t).finish(),
            Self::Css(t) => f.debug_tuple("Css").field(t).finish(),
            Self::LuaJson(t) => f.debug_tuple("LuaJson").field(t).finish(),
            Self::JavaScript(t) => f.debug_tuple("JavaScript").field(t).finish(),
            Self::JsJson(t) => f.debug_tuple("JsJson").field(t).finish(),
            Self::Wasm(t) => f.debug_tuple("Wasm").field(t).finish(),
            Self::Boilerplate(t) => f.debug_tuple("Boilerplate").field(t).finish(),
            Self::CitationBlock(t) => f.debug_tuple("CitationBlock").field(t).finish(),
            Self::JsonEnvelope(t) => f.debug_tuple("JsonEnvelope").field(t).finish(),
            Self::CelScript(t) => f.debug_tuple("CelScript").field(t).finish(),
            Self::A2aAgentCardRewrite(t) => f.debug_tuple("A2aAgentCardRewrite").field(t).finish(),
            Self::Noop => write!(f, "Noop"),
            Self::Plugin(_) => write!(f, "Plugin(...)"),
        }
    }
}

// --- TransformConfig (deserialization wrapper) ---

fn default_max_body() -> usize {
    10 * 1024 * 1024
}

/// Wrapper that controls when a transform is applied.
#[derive(Debug, Deserialize)]
pub struct TransformConfig {
    /// The transform type discriminator (e.g. "json", "json_projection").
    #[serde(rename = "type")]
    pub transform_type: String,
    /// Only apply to these content types (empty = all).
    #[serde(default)]
    pub content_types: Vec<String>,
    /// Legacy failure knob: if true, an error in this transform fails the
    /// entire response.
    ///
    /// Superseded by `failure_posture`, which spells the same decision
    /// with a word instead of a boolean: `fail_on_error: true` is
    /// `failure_posture: closed` and `fail_on_error: false` (or an
    /// omitted key) is `failure_posture: open`. Still parsed, and still
    /// the value used when `failure_posture` is absent, so existing
    /// configs are unaffected. Setting both keys to values that disagree
    /// is a config-load error.
    ///
    /// Read through [`Self::failure_posture()`], never directly.
    #[serde(default)]
    pub fail_on_error: Option<bool>,
    /// What the pipeline does with the response when this transform
    /// fails.
    ///
    /// - `closed` (what `fail_on_error: true` resolves to): replace the
    ///   body with a generic error instead of forwarding bytes the
    ///   transform could not produce.
    /// - `open` (the default, and what `fail_on_error: false` resolves
    ///   to): skip the failed transform and continue with the next one.
    /// - `degraded` is rejected at config load: admitting the response
    ///   while marking the transform guarantee as waived has no defined
    ///   semantics here yet.
    /// - `observe` is rejected at config load: a transform that failed
    ///   produced no transformed body whose effect could be
    ///   shadow-recorded.
    ///
    /// This is the failure axis only. What happens to a body larger
    /// than `max_body_size` (the transform is skipped) is a separate
    /// axis and is not governed by this key.
    #[serde(default)]
    pub failure_posture: Option<FailureMode>,
    /// Max body size to buffer for this transform (default 10MB).
    #[serde(default = "default_max_body")]
    pub max_body_size: usize,
    /// Whether this transform is disabled.
    #[serde(default)]
    pub disabled: bool,
    /// The remaining fields are passed to the specific transform.
    #[serde(flatten)]
    pub config: serde_json::Value,
}

impl TransformConfig {
    /// Effective failure posture for this transform.
    ///
    /// The explicit `failure_posture` key wins. When it is absent the
    /// legacy [`Self::fail_on_error`] boolean is converted, so a config
    /// written before the key existed keeps its exact behaviour:
    /// `fail_on_error: true` is [`FailureMode::Closed`] and the default
    /// `false` is [`FailureMode::Open`].
    ///
    /// This is the only supported read path. Do not branch on
    /// `fail_on_error` directly; the polarity conversion belongs in one
    /// place.
    pub fn failure_posture(&self) -> FailureMode {
        self.failure_posture
            .unwrap_or_else(|| FailureMode::from_fail_closed(self.fail_on_error.unwrap_or(false)))
    }

    /// True when the operator wrote a posture on this attachment.
    ///
    /// [`Self::failure_posture`] cannot answer this, because its default
    /// and an explicit `failure_posture: open` are the same value. A
    /// bundle transform needs the difference: its manifest posture
    /// applies unless the attachment overrides it, and an attachment
    /// that says nothing must not be read as saying `open` (WOR-2268).
    #[must_use]
    pub fn has_explicit_failure_posture(&self) -> bool {
        self.failure_posture.is_some() || self.fail_on_error.is_some()
    }

    /// Reject a failure axis that says two things at once, or that says
    /// something meaningless for this site.
    pub fn validate_failure_posture(&self) -> anyhow::Result<()> {
        let Some(posture) = self.failure_posture else {
            return Ok(());
        };
        if posture == FailureMode::Observe {
            anyhow::bail!(
                "transform {}: `failure_posture: observe` is not meaningful here. \
                 This posture applies when the transform could not run, so there is \
                 no transformed body whose effect could be shadow-recorded. Use \
                 `open` to skip the failed transform or `closed` to fail the \
                 response.",
                self.transform_type
            );
        }
        if posture == FailureMode::Degraded {
            anyhow::bail!(
                "transform {}: `failure_posture: degraded` is not supported here. \
                 Admitting the response while marking the transform guarantee as \
                 waived has no defined semantics for this site yet. Use `open` to \
                 skip the failed transform or `closed` to fail the response.",
                self.transform_type
            );
        }
        if let Some(fail_on_error) = self.fail_on_error {
            let legacy = FailureMode::from_fail_closed(fail_on_error);
            if legacy != posture {
                anyhow::bail!(
                    "transform {}: fail_on_error: {fail_on_error} and failure_posture: \
                     {} disagree; fail_on_error: {fail_on_error} means failure_posture: \
                     {}. Remove fail_on_error and keep failure_posture",
                    self.transform_type,
                    posture.as_label(),
                    legacy.as_label()
                );
            }
        }
        Ok(())
    }
}

// --- CompiledTransform (pipeline entry) ---

/// A compiled transform with its pipeline metadata.
#[derive(Debug)]
pub struct CompiledTransform {
    /// The transform variant to apply.
    pub transform: Transform,
    /// Content-Type substrings this transform applies to (empty matches all).
    pub content_types: Vec<String>,
    /// What the pipeline does with the response when this transform
    /// fails. Resolved once at config load from the explicit
    /// `failure_posture` key or the legacy `fail_on_error` boolean
    /// ([`TransformConfig::failure_posture`]). Only [`FailureMode::Closed`]
    /// and [`FailureMode::Open`] survive validation.
    pub failure_posture: FailureMode,
    /// Maximum body size, in bytes, before the transform is skipped.
    pub max_body_size: usize,
}

impl CompiledTransform {
    /// Check if this transform should apply to the given content type.
    pub fn matches_content_type(&self, content_type: Option<&str>) -> bool {
        if self.content_types.is_empty() {
            return true; // No filter means apply to all.
        }
        match content_type {
            Some(ct) => self
                .content_types
                .iter()
                .any(|allowed| ct.contains(allowed)),
            None => false,
        }
    }

    /// Apply this transform to a body buffer, respecting content-type filters.
    pub fn apply(&self, body: &mut BytesMut, content_type: Option<&str>) -> anyhow::Result<()> {
        if !self.matches_content_type(content_type) {
            return Ok(());
        }
        self.transform.apply(body, content_type)
    }
}

// --- LuaJsonTransform ---

/// Lua-based JSON transform.
///
/// Executes a Lua script that receives the JSON body as a global `body`
/// variable and must return a modified JSON value. The script runs in a
/// sandboxed Lua VM with no filesystem or network access.
#[derive(Debug)]
pub struct LuaJsonTransform {
    /// Lua source code executed against the JSON body.
    pub script: String,
}

impl LuaJsonTransform {
    /// Build a LuaJsonTransform from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        struct Config {
            #[serde(alias = "lua_script")]
            script: String,
        }
        let cfg: Config = serde_json::from_value(value)?;
        Ok(Self { script: cfg.script })
    }

    /// Apply the Lua script to the JSON body.
    ///
    /// Supports two script formats:
    /// 1. **Function format** (Go-compatible): script defines `modify_json(data, ctx)`.
    ///    The function receives the parsed JSON body and a context table.
    /// 2. **Global format** (legacy): script uses a `body` global variable directly.
    ///
    /// The function format is tried first. If `modify_json` is not defined, the
    /// engine falls back to the global format.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        self.apply_with_context(body, serde_json::json!({}))
    }

    /// Apply the Lua script with a caller-supplied per-request context.
    pub fn apply_with_context(
        &self,
        body: &mut BytesMut,
        ctx: serde_json::Value,
    ) -> anyhow::Result<()> {
        let json: serde_json::Value = serde_json::from_slice(body)?;
        let engine = sbproxy_extension::lua::LuaEngine::new()?;

        // Try function format first: modify_json(data, ctx)
        let result =
            match engine.call_function(&self.script, "modify_json", vec![json.clone(), ctx]) {
                Ok(r) => r,
                Err(_) => {
                    // Fall back to global format: body as a global variable
                    let engine = sbproxy_extension::lua::LuaEngine::new()?;
                    let mut globals = std::collections::HashMap::new();
                    globals.insert("body".to_string(), json);
                    engine.execute(&self.script, globals)?
                }
            };

        body.clear();
        serde_json::to_writer(&mut body.writer(), &result)?;
        Ok(())
    }
}

// --- JavaScriptTransform ---

/// JavaScript-based body transform using JsEngine (QuickJS).
///
/// The script must define a function (default name: `transform`) that receives
/// the raw body string and returns the modified string. If the function returns
/// a non-string value it is JSON-serialized before writing back to the buffer.
///
/// Example script:
/// ```js
/// function transform(body) {
///     return body.toUpperCase();
/// }
/// ```
#[derive(Debug)]
pub struct JavaScriptTransform {
    /// JavaScript source executed against the body.
    pub script: String,
    /// Name of the entrypoint function (defaults to `transform`).
    pub function_name: Option<String>,
}

impl JavaScriptTransform {
    /// Build a JavaScriptTransform from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        struct Config {
            script: String,
            function_name: Option<String>,
        }
        let cfg: Config = serde_json::from_value(value)?;
        Ok(Self {
            script: cfg.script,
            function_name: cfg.function_name,
        })
    }

    /// Apply the JavaScript transform using JsEngine.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        self.apply_with_context(body, serde_json::json!({}))
    }

    /// Apply the JavaScript transform with a caller-supplied per-request context.
    pub fn apply_with_context(
        &self,
        body: &mut BytesMut,
        ctx: serde_json::Value,
    ) -> anyhow::Result<()> {
        let engine = sbproxy_extension::js::JsEngine::new()?;
        let input = String::from_utf8_lossy(body).to_string();
        let func = self.function_name.as_deref().unwrap_or("transform");

        let result = engine.call_function(
            &self.script,
            func,
            vec![serde_json::Value::String(input), ctx],
        )?;

        let output = match result {
            serde_json::Value::String(s) => s,
            other => serde_json::to_string(&other)?,
        };

        body.clear();
        body.extend_from_slice(output.as_bytes());
        Ok(())
    }
}

// --- JsJsonTransform ---

/// JavaScript-based JSON transform using JsEngine (QuickJS).
///
/// The script must define a function (default name: `modify_json`) that receives
/// the parsed JSON body as a JavaScript object and returns the modified value.
/// The result is serialized back to JSON and replaces the buffer contents.
///
/// Example script:
/// ```js
/// function modify_json(data) {
///     data.processed = true;
///     data.count = data.count * 2;
///     return data;
/// }
/// ```
#[derive(Debug)]
pub struct JsJsonTransform {
    /// JavaScript source executed against the parsed JSON body.
    pub script: String,
    /// Name of the entrypoint function (defaults to `modify_json`).
    pub function_name: Option<String>,
}

impl JsJsonTransform {
    /// Build a JsJsonTransform from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        struct Config {
            #[serde(alias = "js_script")]
            script: String,
            function_name: Option<String>,
        }
        let cfg: Config = serde_json::from_value(value)?;
        Ok(Self {
            script: cfg.script,
            function_name: cfg.function_name,
        })
    }

    /// Apply the JS JSON transform using JsEngine.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        self.apply_with_context(body, serde_json::json!({}))
    }

    /// Apply the JS JSON transform with a caller-supplied per-request context.
    pub fn apply_with_context(
        &self,
        body: &mut BytesMut,
        ctx: serde_json::Value,
    ) -> anyhow::Result<()> {
        let input: serde_json::Value = serde_json::from_slice(body)?;
        let engine = sbproxy_extension::js::JsEngine::new()?;
        let func = self.function_name.as_deref().unwrap_or("modify_json");

        let result = engine.call_function(&self.script, func, vec![input, ctx])?;

        let output = serde_json::to_vec(&result)?;
        body.clear();
        body.extend_from_slice(&output);
        Ok(())
    }
}

// --- WasmTransform ---

/// WebAssembly-based body transform using a sandboxed WASI module.
///
/// The module receives the response body on stdin and returns the
/// transformed body on stdout. Any wasm32-wasi binary works without
/// custom glue; see `docs/wasm-development.md` for the authoring
/// contract and Rust + TinyGo recipes.
///
/// Sandbox limits (memory cap, wall-clock timeout) are configured on
/// the underlying [`sbproxy_extension::wasm::WasmConfig`]; defaults
/// are 16 MiB / 1 s.
///
/// Example config:
/// ```yaml
/// transforms:
///   - type: wasm
///     module_path: /opt/sbproxy/wasm/echo.wasm
///     timeout_ms: 500
/// ```
#[derive(Debug)]
pub struct WasmTransform {
    /// Display name used in metrics + logs (defaults to the module
    /// file stem when `module_path` is set, otherwise "inline").
    pub name: String,
    /// Pre-compiled module + sandbox config. Compilation happens once
    /// at config-load time; per-request we only pay for instantiation
    /// and execution.
    runtime: sbproxy_extension::wasm::WasmRuntime,
}

impl WasmTransform {
    /// Build a `WasmTransform` from a generic JSON config value.
    ///
    /// Either `module_path` (filesystem path to a `.wasm`) or
    /// `module_bytes` (inline bytes) must be set; failing to set
    /// either is an error so misconfigured pipelines fail loudly at
    /// startup instead of silently accepting traffic with a no-op.
    ///
    /// An authored `allowed_hosts:` is refused. See the inline note
    /// below for why refusing beats keeping the key.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        // WOR-2319: `allowed_hosts:` parsed for years and was never
        // enforced. It could not have been: a module gets no sockets
        // at all here (no WASI networking, no host callout function),
        // so there is no call for an allowlist to sit in front of.
        // A key that names a security boundary nothing checks is worse
        // than no key, because an operator who writes it believes the
        // boundary exists. `WasmConfig` does not set
        // `deny_unknown_fields`, so deleting the field alone would have
        // turned "parsed and inert" into "ignored and silent"; refusing
        // keeps the removal loud, the way the load balancer refuses
        // `sticky:`.
        anyhow::ensure!(
            value.get("allowed_hosts").is_none(),
            "wasm transform `allowed_hosts:` was removed: it was never enforced. WASM modules \
             have no network surface at all here (no WASI sockets, no host callout), so the \
             allowlist described a boundary nothing checked. Remove the key. To restrict what a \
             module can reach, keep the reaching on the proxy side: gate the origin with an \
             `expression` policy, or route the callout through an origin the proxy controls."
        );
        let cfg: sbproxy_extension::wasm::WasmConfig = serde_json::from_value(value)?;
        if cfg.module_path.is_none() && cfg.module_bytes.is_none() {
            anyhow::bail!("wasm transform requires either module_path or module_bytes");
        }
        let name = cfg
            .module_path
            .as_deref()
            .and_then(|p| std::path::Path::new(p).file_stem())
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "inline".to_string());
        let runtime = sbproxy_extension::wasm::WasmRuntime::new(cfg)?;
        Ok(Self { name, runtime })
    }

    /// Apply the WASM transform: feed `body` into the module's stdin,
    /// replace `body` with whatever the module wrote to stdout.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        let output = self.runtime.execute("transform", body)?;
        body.clear();
        body.extend_from_slice(&output);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_dependence_split_is_pinned() {
        // The response cache's ingest pass and the SWR refresh both
        // rely on this split: a variant marked independent may have
        // its output stored and replayed to other requesters, and may
        // be recomputed with no request in scope. Moving a variant
        // from dependent to independent is a cache-safety claim and
        // must be made here deliberately, with the dispatcher's ctx
        // arms in `sbproxy-core` reviewed alongside.
        let dependent = [
            serde_json::json!({"type": "html_to_markdown"}),
            serde_json::json!({"type": "citation_block"}),
            serde_json::json!({"type": "json_envelope"}),
            serde_json::json!({"type": "cel", "headers": [
                {"op": "set", "name": "x-test", "value_expr": "'v'"}
            ]}),
            serde_json::json!({"type": "a2a_agent_card_rewrite"}),
            serde_json::json!({"type": "lua_json", "script": "function modify_json(d, c) return d end"}),
            serde_json::json!({"type": "javascript", "script": "export function transform(b) { return b; }"}),
            serde_json::json!({"type": "js_json", "script": "export function modify_json(d) { return d; }"}),
        ];
        for config in dependent {
            let name = config["type"].as_str().unwrap().to_owned();
            let compiled = crate::compile::compile_transform(&config)
                .unwrap_or_else(|e| panic!("{name} should compile: {e}"));
            assert!(compiled.request_dependent(), "{name} must be dependent");
        }
        let independent = [
            serde_json::json!({"type": "json", "set": {"a": 1}}),
            serde_json::json!({"type": "replace_strings", "replacements": [
                {"find": "raw", "replace": "clean"}
            ]}),
            serde_json::json!({"type": "noop"}),
            serde_json::json!({"type": "payload_limit", "max_size": 1024}),
            serde_json::json!({"type": "boilerplate"}),
        ];
        for config in independent {
            let name = config["type"].as_str().unwrap().to_owned();
            let compiled = crate::compile::compile_transform(&config)
                .unwrap_or_else(|e| panic!("{name} should compile: {e}"));
            assert!(!compiled.request_dependent(), "{name} must be independent");
        }
    }

    // --- Transform enum basics ---

    #[test]
    fn noop_transform_type() {
        let transform = Transform::Noop;
        assert_eq!(transform.transform_type(), "noop");
    }

    #[test]
    fn transform_debug_noop() {
        assert_eq!(format!("{:?}", Transform::Noop), "Noop");
    }

    #[test]
    fn json_transform_type() {
        let t = Transform::Json(JsonTransform {
            set: Default::default(),
            remove: vec![],
            rename: Default::default(),
        });
        assert_eq!(t.transform_type(), "json");
    }

    #[test]
    fn json_projection_transform_type() {
        let t = Transform::JsonProjection(JsonProjectionTransform {
            fields: vec!["id".into()],
            exclude: false,
        });
        assert_eq!(t.transform_type(), "json_projection");
    }

    #[test]
    fn json_schema_transform_type() {
        let t = Transform::JsonSchema(
            JsonSchemaTransform::from_config(serde_json::json!({"schema": {}})).unwrap(),
        );
        assert_eq!(t.transform_type(), "json_schema");
    }

    // --- Transform::apply dispatch ---

    #[test]
    fn apply_noop_leaves_body_unchanged() {
        let mut body = BytesMut::from(&b"{\"a\":1}"[..]);
        Transform::Noop.apply(&mut body, None).unwrap();
        assert_eq!(&body[..], b"{\"a\":1}");
    }

    #[test]
    fn apply_dispatches_to_json_transform() {
        let t = Transform::Json(JsonTransform {
            set: [("added".into(), serde_json::json!(true))]
                .into_iter()
                .collect(),
            remove: vec!["x".into()],
            rename: Default::default(),
        });
        let mut body = BytesMut::from(&b"{\"x\":1,\"y\":2}"[..]);
        t.apply(&mut body, Some("application/json")).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(result.get("x").is_none());
        assert_eq!(result["added"], true);
        assert_eq!(result["y"], 2);
    }

    // --- TransformConfig deserialization ---

    #[test]
    fn transform_config_defaults() {
        let json = serde_json::json!({
            "type": "json",
            "set": {"foo": "bar"}
        });
        let cfg: TransformConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.transform_type, "json");
        assert!(cfg.content_types.is_empty());
        assert_eq!(cfg.fail_on_error, None);
        assert_eq!(cfg.failure_posture(), FailureMode::Open);
        assert_eq!(cfg.max_body_size, 10 * 1024 * 1024);
        assert!(!cfg.disabled);
    }

    #[test]
    fn transform_config_with_all_fields() {
        let json = serde_json::json!({
            "type": "json_projection",
            "content_types": ["application/json"],
            "fail_on_error": true,
            "max_body_size": 1024,
            "disabled": true,
            "fields": ["id", "name"]
        });
        let cfg: TransformConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.transform_type, "json_projection");
        assert_eq!(cfg.content_types, vec!["application/json"]);
        assert_eq!(cfg.fail_on_error, Some(true));
        assert_eq!(cfg.failure_posture(), FailureMode::Closed);
        assert_eq!(cfg.max_body_size, 1024);
        assert!(cfg.disabled);
    }

    // --- failure_posture (WOR-2183) ---

    fn transform_config(value: serde_json::Value) -> TransformConfig {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn legacy_fail_on_error_still_selects_the_posture() {
        // An absent key, an explicit false, and an explicit true keep the
        // exact meanings they had before `failure_posture` existed.
        for (config, expected) in [
            (serde_json::json!({"type": "json"}), FailureMode::Open),
            (
                serde_json::json!({"type": "json", "fail_on_error": false}),
                FailureMode::Open,
            ),
            (
                serde_json::json!({"type": "json", "fail_on_error": true}),
                FailureMode::Closed,
            ),
        ] {
            let cfg = transform_config(config.clone());
            assert_eq!(cfg.failure_posture(), expected, "{config}");
            cfg.validate_failure_posture()
                .expect("legacy-only is valid");
        }
    }

    #[test]
    fn explicit_failure_posture_wins_over_the_legacy_default() {
        let cfg = transform_config(serde_json::json!({
            "type": "json",
            "failure_posture": "closed",
        }));
        assert_eq!(cfg.failure_posture(), FailureMode::Closed);
        cfg.validate_failure_posture()
            .expect("posture alone is valid");
    }

    #[test]
    fn agreeing_fail_on_error_and_failure_posture_parse() {
        for (fail_on_error, posture, expected) in [
            (true, "closed", FailureMode::Closed),
            (false, "open", FailureMode::Open),
        ] {
            let cfg = transform_config(serde_json::json!({
                "type": "json",
                "fail_on_error": fail_on_error,
                "failure_posture": posture,
            }));
            cfg.validate_failure_posture()
                .expect("a redundant but consistent pair stays valid");
            assert_eq!(cfg.failure_posture(), expected);
        }
    }

    #[test]
    fn conflicting_fail_on_error_and_failure_posture_is_a_config_error() {
        for (fail_on_error, posture) in [(true, "open"), (false, "closed")] {
            let cfg = transform_config(serde_json::json!({
                "type": "json",
                "fail_on_error": fail_on_error,
                "failure_posture": posture,
            }));
            let msg = cfg
                .validate_failure_posture()
                .expect_err("disagreeing spellings must fail at config load")
                .to_string();
            assert!(msg.contains("fail_on_error"), "{msg}");
            assert!(msg.contains("failure_posture"), "{msg}");
            assert!(msg.contains("json"), "{msg}");
        }
    }

    #[test]
    fn observe_failure_posture_is_rejected_for_transforms() {
        let msg = transform_config(serde_json::json!({
            "type": "template",
            "failure_posture": "observe",
        }))
        .validate_failure_posture()
        .expect_err("observe must not validate")
        .to_string();
        assert!(msg.contains("observe"), "{msg}");
        assert!(msg.contains("template"), "{msg}");
    }

    #[test]
    fn degraded_failure_posture_is_rejected_for_transforms() {
        // The degraded semantics for this site are undecided; until they
        // are, the word must not parse here.
        let msg = transform_config(serde_json::json!({
            "type": "template",
            "failure_posture": "degraded",
        }))
        .validate_failure_posture()
        .expect_err("degraded must not validate")
        .to_string();
        assert!(msg.contains("degraded"), "{msg}");
        assert!(msg.contains("not supported"), "{msg}");
    }

    // --- CompiledTransform content-type matching ---

    #[test]
    fn compiled_transform_matches_all_when_empty() {
        let ct = CompiledTransform {
            transform: Transform::Noop,
            content_types: vec![],
            failure_posture: FailureMode::Open,
            max_body_size: 1024,
        };
        assert!(ct.matches_content_type(Some("text/html")));
        assert!(ct.matches_content_type(Some("application/json")));
        assert!(ct.matches_content_type(None));
    }

    #[test]
    fn compiled_transform_matches_specific_content_type() {
        let ct = CompiledTransform {
            transform: Transform::Noop,
            content_types: vec!["application/json".into()],
            failure_posture: FailureMode::Open,
            max_body_size: 1024,
        };
        assert!(ct.matches_content_type(Some("application/json")));
        assert!(ct.matches_content_type(Some("application/json; charset=utf-8")));
        assert!(!ct.matches_content_type(Some("text/html")));
        assert!(!ct.matches_content_type(None));
    }

    #[test]
    fn compiled_transform_skips_non_matching_content_type() {
        let ct = CompiledTransform {
            transform: Transform::Json(JsonTransform {
                set: [("injected".into(), serde_json::json!(true))]
                    .into_iter()
                    .collect(),
                remove: vec![],
                rename: Default::default(),
            }),
            content_types: vec!["application/json".into()],
            failure_posture: FailureMode::Open,
            max_body_size: 1024,
        };
        let mut body = BytesMut::from(&b"{\"a\":1}"[..]);
        // text/html does not match, so body should be unchanged.
        ct.apply(&mut body, Some("text/html")).unwrap();
        assert_eq!(&body[..], b"{\"a\":1}");
    }

    // --- LuaJsonTransform tests ---

    #[test]
    fn lua_json_transform_type() {
        let t = Transform::LuaJson(LuaJsonTransform {
            script: "return body".to_string(),
        });
        assert_eq!(t.transform_type(), "lua_json");
    }

    #[test]
    fn lua_json_from_config() {
        let t = LuaJsonTransform::from_config(serde_json::json!({
            "script": "body.added = true\nreturn body"
        }))
        .unwrap();
        assert_eq!(t.script, "body.added = true\nreturn body");
    }

    #[test]
    fn lua_json_from_config_missing_script_errors() {
        let result = LuaJsonTransform::from_config(serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn lua_json_apply_modifies_body() {
        let t = LuaJsonTransform::from_config(serde_json::json!({
            "script": "body.added = true\nreturn body"
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"{\"x\":1}"[..]);
        t.apply(&mut body).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["x"], 1);
        assert_eq!(result["added"], true);
    }

    #[test]
    fn lua_json_apply_with_context_exposes_request_aipref() {
        let t = LuaJsonTransform::from_config(serde_json::json!({
            "script": r#"
                function modify_json(data, ctx)
                  data.train = ctx.request.aipref.train
                  data.search = ctx.request.aipref.search
                  data.ai_input = ctx.request.aipref.ai_input
                  return data
                end
            "#
        }))
        .unwrap();
        let ctx = serde_json::json!({
            "request": {
                "aipref": {
                    "train": false,
                    "search": true,
                    "ai_input": false
                }
            }
        });
        let mut body = BytesMut::from(&b"{}"[..]);

        t.apply_with_context(&mut body, ctx).unwrap();

        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["train"], false);
        assert_eq!(result["search"], true);
        assert_eq!(result["ai_input"], false);
    }

    #[test]
    fn lua_json_apply_returns_new_value() {
        let t = LuaJsonTransform::from_config(serde_json::json!({
            "script": "return {status = \"ok\", count = 42}"
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"{}"[..]);
        t.apply(&mut body).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["count"], 42);
    }

    #[test]
    fn lua_json_apply_invalid_json_body_errors() {
        let t = LuaJsonTransform {
            script: "return body".to_string(),
        };
        let mut body = BytesMut::from(&b"not json"[..]);
        assert!(t.apply(&mut body).is_err());
    }

    #[test]
    fn lua_json_apply_bad_script_errors() {
        let t = LuaJsonTransform {
            script: "this is not valid lua !!!".to_string(),
        };
        let mut body = BytesMut::from(&b"{}"[..]);
        assert!(t.apply(&mut body).is_err());
    }

    // --- JavaScriptTransform tests ---

    // --- JavaScriptTransform tests ---

    #[test]
    fn javascript_transform_type() {
        let t = Transform::JavaScript(JavaScriptTransform {
            script: "function transform(b) { return b; }".to_string(),
            function_name: None,
        });
        assert_eq!(t.transform_type(), "javascript");
    }

    #[test]
    fn javascript_from_config() {
        let t = JavaScriptTransform::from_config(serde_json::json!({
            "script": "function transform(b) { return b; }"
        }))
        .unwrap();
        assert_eq!(t.script, "function transform(b) { return b; }");
        assert!(t.function_name.is_none());
    }

    #[test]
    fn javascript_from_config_with_function_name() {
        let t = JavaScriptTransform::from_config(serde_json::json!({
            "script": "function process(b) { return b.toUpperCase(); }",
            "function_name": "process"
        }))
        .unwrap();
        assert_eq!(t.function_name.as_deref(), Some("process"));
    }

    #[test]
    fn javascript_from_config_missing_script_errors() {
        let result = JavaScriptTransform::from_config(serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn javascript_apply_transforms_body() {
        let t = JavaScriptTransform::from_config(serde_json::json!({
            "script": "function transform(body) { return body.toUpperCase(); }"
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"hello world"[..]);
        t.apply(&mut body).unwrap();
        assert_eq!(&body[..], b"HELLO WORLD");
    }

    #[test]
    fn javascript_apply_with_context_exposes_request_aipref() {
        let t = JavaScriptTransform::from_config(serde_json::json!({
            "script": r#"
                function transform(body, ctx) {
                  return JSON.stringify({
                    body,
                    train: ctx.request.aipref.train,
                    search: ctx.request.aipref.search,
                    ai_input: ctx.request.aipref.ai_input
                  });
                }
            "#
        }))
        .unwrap();
        let ctx = serde_json::json!({
            "request": {
                "aipref": {
                    "train": false,
                    "search": true,
                    "ai_input": false
                }
            }
        });
        let mut body = BytesMut::from(&b"hello"[..]);

        t.apply_with_context(&mut body, ctx).unwrap();

        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["body"], "hello");
        assert_eq!(result["train"], false);
        assert_eq!(result["search"], true);
        assert_eq!(result["ai_input"], false);
    }

    #[test]
    fn javascript_apply_returns_string_result() {
        let t = JavaScriptTransform::from_config(serde_json::json!({
            "script": "function transform(body) { return body.replace('foo', 'bar'); }"
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"foo baz foo"[..]);
        t.apply(&mut body).unwrap();
        assert_eq!(&body[..], b"bar baz foo");
    }

    #[test]
    fn javascript_apply_with_custom_function_name() {
        let t = JavaScriptTransform::from_config(serde_json::json!({
            "script": "function process(body) { return body + '!'; }",
            "function_name": "process"
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"hello"[..]);
        t.apply(&mut body).unwrap();
        assert_eq!(&body[..], b"hello!");
    }

    // --- JsJsonTransform tests ---

    #[test]
    fn js_json_transform_type() {
        let t = Transform::JsJson(JsJsonTransform {
            script: "function modify_json(d) { return d; }".to_string(),
            function_name: None,
        });
        assert_eq!(t.transform_type(), "js_json");
    }

    #[test]
    fn js_json_from_config() {
        let t = JsJsonTransform::from_config(serde_json::json!({
            "script": "function modify_json(d) { return d; }"
        }))
        .unwrap();
        assert_eq!(t.script, "function modify_json(d) { return d; }");
        assert!(t.function_name.is_none());
    }

    #[test]
    fn js_json_from_config_with_js_script_alias() {
        let t = JsJsonTransform::from_config(serde_json::json!({
            "js_script": "function modify_json(d) { return d; }"
        }))
        .unwrap();
        assert!(!t.script.is_empty());
    }

    #[test]
    fn js_json_from_config_missing_script_errors() {
        let result = JsJsonTransform::from_config(serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn js_json_apply_modifies_body() {
        let t = JsJsonTransform::from_config(serde_json::json!({
            "script": "function modify_json(data) { data.added = true; return data; }"
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"{\"x\":1}"[..]);
        t.apply(&mut body).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["x"], 1);
        assert_eq!(result["added"], true);
    }

    #[test]
    fn js_json_apply_with_context_exposes_request_aipref() {
        let t = JsJsonTransform::from_config(serde_json::json!({
            "script": r#"
                function modify_json(data, ctx) {
                  data.train = ctx.request.aipref.train;
                  data.search = ctx.request.aipref.search;
                  data.ai_input = ctx.request.aipref.ai_input;
                  return data;
                }
            "#
        }))
        .unwrap();
        let ctx = serde_json::json!({
            "request": {
                "aipref": {
                    "train": false,
                    "search": true,
                    "ai_input": false
                }
            }
        });
        let mut body = BytesMut::from(&b"{}"[..]);

        t.apply_with_context(&mut body, ctx).unwrap();

        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["train"], false);
        assert_eq!(result["search"], true);
        assert_eq!(result["ai_input"], false);
    }

    #[test]
    fn js_json_apply_doubles_count() {
        let t = JsJsonTransform::from_config(serde_json::json!({
            "script": "function modify_json(data) { data.count = data.count * 2; return data; }"
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"{\"count\":5}"[..]);
        t.apply(&mut body).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["count"], 10);
    }

    #[test]
    fn js_json_apply_with_custom_function_name() {
        let t = JsJsonTransform::from_config(serde_json::json!({
            "script": "function transform_json(data) { data.transformed = true; return data; }",
            "function_name": "transform_json"
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"{\"x\":1}"[..]);
        t.apply(&mut body).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["transformed"], true);
    }

    #[test]
    fn js_json_apply_invalid_json_body_errors() {
        let t = JsJsonTransform {
            script: "function modify_json(d) { return d; }".to_string(),
            function_name: None,
        };
        let mut body = BytesMut::from(&b"not json"[..]);
        assert!(t.apply(&mut body).is_err());
    }

    // --- Debug fmt ---

    #[test]
    fn transform_debug_lua_json() {
        let t = Transform::LuaJson(LuaJsonTransform {
            script: "return body".to_string(),
        });
        let debug = format!("{:?}", t);
        assert!(debug.contains("LuaJson"));
    }

    #[test]
    fn transform_debug_javascript() {
        let t = Transform::JavaScript(JavaScriptTransform {
            script: "function transform(b) { return b; }".to_string(),
            function_name: None,
        });
        let debug = format!("{:?}", t);
        assert!(debug.contains("JavaScript"));
    }

    #[test]
    fn transform_debug_js_json() {
        let t = Transform::JsJson(JsJsonTransform {
            script: "function modify_json(d) { return d; }".to_string(),
            function_name: None,
        });
        let debug = format!("{:?}", t);
        assert!(debug.contains("JsJson"));
    }

    // --- Plugin dispatch regression test ---

    use sbproxy_plugin::{PluginKind, PluginRegistration};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Mock handler that records its call count and rewrites the body.
    struct RecordingTransformHandler {
        calls: Arc<AtomicUsize>,
    }

    impl TransformHandler for RecordingTransformHandler {
        fn transform_type(&self) -> &'static str {
            "test-recording-transform"
        }

        fn apply<'a>(
            &'a self,
            body: &'a mut bytes::BytesMut,
            _content_type: Option<&'a str>,
            _ctx: &'a TransformContext<'a>,
        ) -> Pin<Box<dyn std::future::Future<Output = sbproxy_plugin::PluginResult<()>> + Send + 'a>>
        {
            let calls = self.calls.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                body.clear();
                body.extend_from_slice(b"transformed");
                Ok(())
            })
        }
    }

    inventory::submit! {
        PluginRegistration {
            kind: PluginKind::Transform,
            name: "test-recording-transform",
            factory: |_config| Ok(Box::new(())),
        }
    }

    #[test]
    fn plugin_apply_dispatches_to_handler() {
        let calls = Arc::new(AtomicUsize::new(0));
        let handler = RecordingTransformHandler {
            calls: calls.clone(),
        };
        let t = Transform::Plugin(crate::PluginTransform::linked(Box::new(handler)));
        let mut body = BytesMut::from(&b"original"[..]);
        t.apply(&mut body, Some("text/plain")).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(&body[..], b"transformed");
    }

    #[test]
    fn typed_plugin_apply_does_not_require_generic_registration() {
        struct UnregisteredHandler;
        impl TransformHandler for UnregisteredHandler {
            fn transform_type(&self) -> &'static str {
                "unregistered-transform"
            }
            fn apply<'a>(
                &'a self,
                _body: &'a mut bytes::BytesMut,
                _content_type: Option<&'a str>,
                _ctx: &'a TransformContext<'a>,
            ) -> Pin<
                Box<dyn std::future::Future<Output = sbproxy_plugin::PluginResult<()>> + Send + 'a>,
            > {
                Box::pin(async { Ok(()) })
            }
        }

        let t = Transform::Plugin(crate::PluginTransform::linked(Box::new(
            UnregisteredHandler,
        )));
        let mut body = BytesMut::from(&b"x"[..]);
        t.apply(&mut body, None)
            .expect("the compiled typed handler is the registration proof");
    }

    // --- WOR-168 plugin dispatch reliability tests ---
    //
    // Pre-WOR-168, `dispatch_plugin` drove the plugin future with
    // `futures::executor::block_on` and had no panic / timeout
    // protection. A plugin that panicked would abort the Pingora
    // worker, and a plugin that hung would tie up the worker
    // indefinitely. The current dispatcher runs the future on a
    // dedicated multi-thread runtime with a `PLUGIN_TRANSFORM_TIMEOUT`
    // wall-clock cap and a `catch_unwind` guard, surfacing both
    // failure modes as a typed `TransformError::Plugin`.

    /// A plugin that panics inside its future should surface a
    /// `TransformError::Plugin { detail: "panicked" }` instead of
    /// aborting the worker.
    #[test]
    fn plugin_apply_catches_panics() {
        struct PanickingHandler;
        impl TransformHandler for PanickingHandler {
            fn transform_type(&self) -> &'static str {
                "test-panicking-transform"
            }
            fn apply<'a>(
                &'a self,
                _body: &'a mut bytes::BytesMut,
                _content_type: Option<&'a str>,
                _ctx: &'a TransformContext<'a>,
            ) -> Pin<
                Box<dyn std::future::Future<Output = sbproxy_plugin::PluginResult<()>> + Send + 'a>,
            > {
                Box::pin(async {
                    panic!("plugin oops");
                })
            }
        }

        inventory::submit! {
            sbproxy_plugin::PluginRegistration {
                kind: sbproxy_plugin::PluginKind::Transform,
                name: "test-panicking-transform",
                factory: |_config| Ok(Box::new(())),
            }
        }

        let t = Transform::Plugin(crate::PluginTransform::linked(Box::new(PanickingHandler)));
        let mut body = BytesMut::from(&b"x"[..]);
        let err = t.apply(&mut body, None).unwrap_err();
        let typed = err.downcast_ref::<TransformError>().expect(
            "plugin panic must surface as TransformError::Plugin, not the original anyhow::Error",
        );
        match typed {
            TransformError::Plugin { plugin, detail } => {
                assert_eq!(plugin, "test-panicking-transform");
                assert!(detail.contains("panic"), "detail: {detail}");
            }
            other => panic!("expected Plugin error variant, got {:?}", other),
        }
    }

    /// A plugin whose future never completes should be cut off at the
    /// dispatcher's wall-clock cap and surface a
    /// `TransformError::Plugin { detail: "timed out after Nms" }`.
    ///
    /// Driven through `dispatch_plugin_within` with a short cap rather than
    /// through the production `PLUGIN_TRANSFORM_TIMEOUT` of 5s, which this test
    /// used to wait out in full. The cap is the contract under test, and it is
    /// still a real deadline on the real clock; only the deadline moves closer.
    #[test]
    fn plugin_apply_times_out_slow_future() {
        // Short enough to keep the test fast, long enough that a loaded runner
        // cannot mistake scheduling delay for the plugin finishing.
        const TEST_CAP: std::time::Duration = std::time::Duration::from_millis(250);
        struct SlowHandler;
        impl TransformHandler for SlowHandler {
            fn transform_type(&self) -> &'static str {
                "test-slow-transform"
            }
            fn apply<'a>(
                &'a self,
                _body: &'a mut bytes::BytesMut,
                _content_type: Option<&'a str>,
                _ctx: &'a TransformContext<'a>,
            ) -> Pin<
                Box<dyn std::future::Future<Output = sbproxy_plugin::PluginResult<()>> + Send + 'a>,
            > {
                Box::pin(async {
                    // Sleep well beyond the cap the test installs so the
                    // timeout branch is the one that fires.
                    tokio::time::sleep(TEST_CAP * 10).await;
                    Ok(())
                })
            }
        }

        inventory::submit! {
            sbproxy_plugin::PluginRegistration {
                kind: sbproxy_plugin::PluginKind::Transform,
                name: "test-slow-transform",
                factory: |_config| Ok(Box::new(())),
            }
        }

        let handler = SlowHandler;
        let mut body = BytesMut::from(&b"x"[..]);
        let started = std::time::Instant::now();
        let err = dispatch_plugin_within(&handler, &mut body, None, TEST_CAP).unwrap_err();
        let elapsed = started.elapsed();
        // Two-sided: the cap must have fired (the handler would otherwise have
        // slept ten times as long and returned Ok), and it must not have taken
        // wildly longer than the cap. The upper bound keeps generous slack for
        // a loaded runner.
        assert!(
            elapsed >= TEST_CAP,
            "the cap must be a real deadline, not an instant failure (elapsed: {elapsed:?})",
        );
        assert!(
            elapsed < TEST_CAP * 8,
            "dispatcher must cap slow plugin futures (elapsed: {elapsed:?})",
        );
        let typed = err
            .downcast_ref::<TransformError>()
            .expect("slow plugin must surface as TransformError::Plugin");
        match typed {
            TransformError::Plugin { plugin, detail } => {
                assert_eq!(plugin, "test-slow-transform");
                assert!(detail.contains("timed out"), "detail: {detail}");
            }
            other => panic!("expected Plugin error variant, got {:?}", other),
        }
    }

    // --- wasm `allowed_hosts:` is removed and refused (WOR-2319) ---
    //
    // The key parsed and was never enforced. `WasmConfig` does not set
    // `deny_unknown_fields`, so a plain field deletion would have made
    // an authored key silently vanish. These pin the refusal.

    #[test]
    fn wasm_allowed_hosts_is_refused_at_config_compile() {
        let error = WasmTransform::from_config(serde_json::json!({
            "type": "wasm",
            "module_path": "/opt/sbproxy/wasm/echo.wasm",
            "allowed_hosts": ["api.example.com"]
        }))
        .expect_err("an authored allowed_hosts must fail config compilation, not sit inert");

        let message = error.to_string();
        assert!(
            message.contains("allowed_hosts"),
            "the error must name the removed key: '{message}'"
        );
        assert!(
            message.contains("never enforced"),
            "the error must say the key did nothing: '{message}'"
        );
        assert!(
            message.contains("no network surface"),
            "the error must say why it could not have been enforced: '{message}'"
        );
    }

    #[test]
    fn wasm_allowed_hosts_is_refused_before_the_module_is_loaded() {
        // The refusal must not depend on a readable `.wasm`: an
        // operator who authored both a bad path and the dead key should
        // still be told about the key, and config compile should never
        // touch the filesystem to reject it.
        let error = WasmTransform::from_config(serde_json::json!({
            "type": "wasm",
            "module_path": "/nonexistent/definitely-not-here.wasm",
            "allowed_hosts": []
        }))
        .expect_err("an empty allowed_hosts list is still an authored key");

        assert!(
            error.to_string().contains("allowed_hosts"),
            "an empty list must be refused too: '{error}'"
        );
    }

    #[test]
    fn wasm_transform_without_allowed_hosts_still_reports_the_real_problem() {
        // The refusal must not swallow the pre-existing validation.
        let error = WasmTransform::from_config(serde_json::json!({
            "type": "wasm"
        }))
        .expect_err("neither module_path nor module_bytes is still an error");

        assert!(
            error.to_string().contains("module_path"),
            "unrelated configs must keep their own error: '{error}'"
        );
    }
}
