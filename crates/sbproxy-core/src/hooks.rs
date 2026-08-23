//! Optional hook traits exposed by the pipeline.
//!
//! `CompiledPipeline` owns an [`Hooks`] bundle of `Option<Arc<dyn TraitName>>`
//! slots. Stock classifier configuration installs intent and quality slots;
//! otherwise builds without a linked extension leave every slot `None` and
//! request paths fall through. Extensions register a single
//! [`PipelineLifecycleHook`] via the `register_startup_hook!` macro and may
//! populate the remaining slots with concrete implementations.
//!
//! Semantic caching is not a hook. It is compiled per action into
//! [`crate::semantic_cache_runtime::SemanticCacheRuntimeRegistry`] and owned
//! by the pipeline, so the request path reaches it directly rather than
//! through an optional slot.
//!
//! Fail-open is the convention throughout. Traits that can fail typically
//! return `Option<T>` and expect callers to log at debug and continue when
//! `None` is returned.

use async_trait::async_trait;
use bytes::Bytes;
use sbproxy_cache::AtRestPosture;
use std::collections::HashMap;
use std::sync::Arc;

// ============================================================================
// Header redaction policy
// ============================================================================

/// Lower-cased header names the request pipeline drops before populating
/// header snapshots on hook surfaces (`ClassifyRequest::headers`).
///
/// Redaction is enforced at the snapshot site so hook implementations do not
/// observe credential material from built-in carriers. Runtime snapshots also
/// consult the config-aware sensitive-header set, which includes every
/// `key_management.inbound.headers[].name` and
/// `provider_hints[].header`.
///
/// Names are matched case-insensitively against
/// `pingora_http::HeaderName::as_str()`, which is already lower-cased on
/// HTTP/2 and HTTP/3 and folded by Pingora on HTTP/1.1.
pub const REDACTED_REQUEST_HEADERS: &[&str] = &["authorization", "cookie", "proxy-authorization"];

// ============================================================================
// Startup hook
// ============================================================================

/// One-shot lifecycle hook that wires optional implementations into a
/// freshly compiled pipeline.
///
/// Exactly one implementation is registered per binary using the
/// `register_startup_hook!` macro and collected through `inventory`. Binaries
/// that register none leave all other hook slots as `None`.
///
/// `on_startup` runs once at process boot; `on_reload` runs on every
/// hot-reload after the new pipeline is compiled but before it is swapped
/// in as the live pipeline.
#[async_trait]
pub trait PipelineLifecycleHook: Send + Sync {
    /// Populate optional slots on the freshly compiled pipeline at
    /// process boot. Returning an error aborts startup.
    async fn on_startup(
        &self,
        pipeline: &mut crate::pipeline::CompiledPipeline,
    ) -> anyhow::Result<()>;

    /// Re-populate optional slots on a reloaded pipeline. Called after
    /// the new `CompiledPipeline` is built from reloaded config, before
    /// it goes live.
    ///
    /// Returning an error rejects the candidate. The published pipeline
    /// and its extension registry remain the same generation.
    async fn on_reload(
        &self,
        pipeline: &mut crate::pipeline::CompiledPipeline,
    ) -> anyhow::Result<()>;
}

// ============================================================================
// Classification hooks
// ============================================================================

/// Input to [`PromptClassifierHook::classify_prompt`].
///
/// Carries the fields a classifier needs to label the prompt
/// (origin id, model id, prompt text, and relevant request headers).
#[derive(Debug, Clone)]
pub struct ClassifyRequest {
    /// Origin identifier the request is being routed to.
    pub origin: String,
    /// Optional model identifier selected by upstream routing.
    pub model_id: Option<String>,
    /// Raw prompt text submitted by the client.
    pub prompt: String,
    /// Snapshot of the inbound request headers, with credential
    /// carriers stripped.
    ///
    /// The proxy populates this from the live Pingora request just
    /// before invoking the classifier. Header names are lower-cased to
    /// match HTTP/2 and HTTP/3 framing. Values come straight from the
    /// wire and may contain operator-controlled secrets in non-redacted
    /// header names; implementations should not log them verbatim.
    ///
    /// Headers listed in [`REDACTED_REQUEST_HEADERS`] are dropped
    /// before the snapshot is built and never reach the classifier.
    /// The contract is "what the caller sees minus credentials"; if
    /// hook implementations need a header that is currently redacted,
    /// raise the contract change rather than fishing the value out
    /// elsewhere.
    pub headers: HashMap<String, String>,
}

/// Labels and confidence returned by a classifier.
///
/// `labels` and `scores` come straight from the classifier sidecar;
/// `confidence` is the top-label confidence in `[0.0, 1.0]`. Consumers
/// typically gate downstream decisions on a confidence threshold.
#[derive(Debug, Clone)]
pub struct ClassifyVerdict {
    /// Ordered labels assigned to the prompt by the classifier.
    pub labels: Vec<String>,
    /// Per-label confidence scores returned by the classifier.
    pub scores: HashMap<String, f32>,
    /// Top-label confidence in the closed range `[0.0, 1.0]`.
    pub confidence: f32,
}

/// Classifies an incoming prompt through an external classifier sidecar.
///
/// Extensions may supply a gRPC-backed implementation; the slot otherwise
/// remains `None`. Implementations must be fail-open: any transport,
/// deadline, or decode error should yield `None` so the request can
/// continue unannotated.
#[async_trait]
pub trait PromptClassifierHook: Send + Sync {
    /// Classify `req`. Returns `None` on any error (transport, deadline,
    /// parse) so callers can log at debug and continue. A `Some` result
    /// may still carry empty `labels` if the classifier was unable to
    /// decide.
    async fn classify_prompt(&self, req: &ClassifyRequest) -> Option<ClassifyVerdict>;
}

/// Coarse intent bucket used for routing decisions.
///
/// Producers (classifier, heuristic fallback) pick one of these
/// per prompt; consumers (model routers, cost optimizers) key on this to
/// choose a provider or model family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentCategory {
    /// Software development, debugging, and code generation.
    Coding,
    /// Image, video, or other multimodal visual understanding.
    Vision,
    /// Data analysis, reasoning, or evaluation tasks.
    Analysis,
    /// Summarization or extractive condensation of content.
    Summarization,
    /// General-purpose conversational or open-ended use.
    General,
}

/// Detects the coarse intent of an incoming prompt.
///
/// Typically backed by a lightweight classifier or keyword heuristic.
/// Fail-open: return `None` to mean "unknown", not "general".
#[async_trait]
pub trait IntentDetectionHook: Send + Sync {
    /// Return the detected intent for `prompt`, or `None` if the hook
    /// declines to decide.
    async fn detect(&self, prompt: &str) -> Option<IntentCategory>;
}

/// Input to [`QualityScoringHook::score_providers`].
///
/// Carries the prompt and the set of provider identifiers the router is
/// currently considering. The scoring hook narrows / reranks the list.
#[derive(Debug, Clone)]
pub struct QualityRequest {
    /// Origin identifier the request is being routed to.
    pub origin: String,
    /// Optional model identifier selected before reranking.
    pub model_id: Option<String>,
    /// Raw prompt text used to inform quality scoring.
    pub prompt: String,
    /// Provider identifiers the router is considering.
    pub candidate_providers: Vec<String>,
}

/// Single provider's quality score, normalized into a per-prompt ranking.
///
/// Scores are comparable only within a single `score_providers` response;
/// do not persist or compare across calls.
#[derive(Debug, Clone)]
pub struct QualityScore {
    /// Provider identifier the score applies to.
    pub provider: String,
    /// Relative quality score for this provider on the current prompt.
    pub score: f64,
}

/// Scores provider candidates for a given prompt so the router can pick
/// the highest-quality option for this specific request.
///
/// Optional and fail-open: returning `None` means "no opinion, use the
/// router's default ordering."
#[async_trait]
pub trait QualityScoringHook: Send + Sync {
    /// Minimum score a provider must reach to be eligible for selection.
    ///
    /// Hook implementations that do not expose a threshold retain the
    /// historical `0.0` behavior. Stock classifier hooks override this with
    /// the validated operator-configured value.
    fn minimum_score(&self) -> f64 {
        0.0
    }

    /// Score each provider in `req.candidate_providers` for `req.prompt`.
    ///
    /// Returning `None` defers to the caller's default ordering. A `Some`
    /// response may contain fewer entries than the candidate list if the
    /// hook excluded some providers.
    async fn score_providers(&self, req: &QualityRequest) -> Option<Vec<QualityScore>>;
}

// ============================================================================
// Stream safety hook
// ============================================================================

/// Per-session context handed to [`StreamSafetyHook::start_session`].
///
/// The hook receives the origin, model id, and the set of safety rule ids
/// the caller wants enforced for this stream.
#[derive(Debug, Clone)]
pub struct StreamSafetyCtx {
    /// Origin identifier this stream belongs to.
    pub origin: String,
    /// Optional model identifier producing the stream.
    pub model_id: Option<String>,
    /// Identifiers of safety rules to enforce for the session.
    pub rules: Vec<String>,
}

/// Bidirectional channel wrapper returned by a started safety session.
///
/// The caller writes response chunks into `tx` as they are streamed from
/// the upstream and reads verdicts from `rx`. A verdict with `allow=false`
/// instructs the caller to terminate the stream; verdicts may arrive out
/// of band with respect to chunk boundaries.
pub struct StreamSafetyChannel {
    /// Sender used by the proxy to push response chunks into the safety session.
    pub tx: tokio::sync::mpsc::Sender<Bytes>,
    /// Receiver yielding safety verdicts for the in-flight stream.
    pub rx: tokio::sync::mpsc::Receiver<StreamSafetyVerdict>,
}

/// Single verdict emitted during a streaming session.
///
/// `allow=false` signals the caller to abort the response. `reason`
/// carries an operator-facing label (safe to log, not safe to surface to
/// end users verbatim).
#[derive(Debug, Clone)]
pub struct StreamSafetyVerdict {
    /// Whether the stream should be allowed to continue.
    pub allow: bool,
    /// Optional operator-facing reason for the verdict.
    pub reason: Option<String>,
}

/// Opens a streaming safety session that validates response chunks as
/// they are emitted by the upstream model.
///
/// Optional and fail-open. Returning `None` from `start_session` means
/// "no safety check for this request" and the stream is forwarded as-is.
#[async_trait]
pub trait StreamSafetyHook: Send + Sync {
    /// Start a safety session for the request described by `ctx`.
    ///
    /// Returns a [`StreamSafetyChannel`] whose `tx` accepts response
    /// chunks and whose `rx` yields verdicts. Dropping the channel ends
    /// the session.
    async fn start_session(&self, ctx: StreamSafetyCtx) -> Option<StreamSafetyChannel>;
}

// ============================================================================
// Aggregate: Hooks bundle owned by CompiledPipeline
// ============================================================================

/// Bundle of all optional hook slots owned by [`crate::pipeline::CompiledPipeline`].
///
/// Every slot defaults to `None`. Stock classifier config can populate intent
/// and quality, while a registered lifecycle extension can populate or replace
/// slots from its [`PipelineLifecycleHook::on_startup`] implementation.
/// Request-path code checks each slot before dispatching and no-ops when `None`.
#[derive(Default, Clone)]
pub struct Hooks {
    /// Lifecycle hook that populates the other slots. Registered via
    /// `inventory` and collected by [`crate::hook_registry::collect_startup_hook`].
    pub startup: Option<Arc<dyn PipelineLifecycleHook>>,
    /// Prompt classification (labels + confidence).
    pub prompt_classifier: Option<Arc<dyn PromptClassifierHook>>,
    /// Coarse intent detection used by model routers.
    pub intent_detection: Option<Arc<dyn IntentDetectionHook>>,
    /// Provider quality scoring used for router reranking.
    pub quality_scoring: Option<Arc<dyn QualityScoringHook>>,
    /// Streaming-response safety supervision.
    pub stream_safety: Option<Arc<dyn StreamSafetyHook>>,
    /// Cache surfaces injected by a test so the boot-time at-rest check
    /// keeps its fatal branch covered. No hook registers a surface today
    /// (see [`Hooks::cache_surfaces`]), so without this the guard would
    /// only ever be exercised against an empty list.
    #[cfg(test)]
    pub test_cache_surfaces: Vec<(&'static str, AtRestPosture)>,
}

impl Hooks {
    /// Every installed hook cache surface with its declared at-rest
    /// posture, paired with the config path an operator would edit to fix
    /// it.
    ///
    /// Read by the boot-time check in the server lifecycle module.
    /// Surfaces that are not caches are not listed: a classifier or a
    /// router holds no entries to leak.
    ///
    /// No hook currently holds cache entries. The semantic cache is
    /// compiled into
    /// [`crate::semantic_cache_runtime::SemanticCacheRuntimeRegistry`]
    /// rather than registered here, and it declares its own backend
    /// posture through that registry, so this list is empty in every
    /// current build. The seam stays because the boot check is the right
    /// place to refuse a future hook that would write prompts and
    /// responses somewhere durable in the clear.
    pub fn cache_surfaces(&self) -> Vec<(&'static str, AtRestPosture)> {
        #[cfg(test)]
        {
            self.test_cache_surfaces.clone()
        }
        #[cfg(not(test))]
        {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Hooks::default ---

    #[test]
    fn hooks_default_leaves_every_slot_none() {
        let hooks = Hooks::default();
        assert!(hooks.startup.is_none());
        assert!(hooks.prompt_classifier.is_none());
        assert!(hooks.intent_detection.is_none());
        assert!(hooks.quality_scoring.is_none());
        assert!(hooks.stream_safety.is_none());
    }

    /// The semantic cache and the streaming recorder are no longer hook
    /// slots, so no hook holds cache entries and the boot-time at-rest
    /// check has nothing to inspect.
    #[test]
    fn default_hooks_declare_no_cache_surface() {
        assert!(Hooks::default().cache_surfaces().is_empty());
    }
}
