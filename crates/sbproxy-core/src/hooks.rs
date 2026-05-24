//! Enterprise hook traits exposed by the OSS pipeline.
//!
//! `CompiledPipeline` owns an [`Hooks`] bundle of `Option<Arc<dyn TraitName>>`
//! slots. OSS builds leave every slot `None` and the request path falls
//! through without annotation. Enterprise crates register a single
//! [`EnterpriseStartupHook`] via the `register_startup_hook!` macro; the
//! startup hook populates the remaining slots with concrete implementations
//! (gRPC classifier client, semantic cache, etc.).
//!
//! Fail-open is the convention throughout. Traits that can fail typically
//! return `Option<T>` and expect callers to log at debug and continue when
//! `None` is returned.
//!
//! See the design spec at
//! `docs/superpowers/specs/2026-04-22-sbproxy-grpc-classifier-integration-design.md`.

use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;

// ============================================================================
// Header redaction policy
// ============================================================================

/// Lower-cased header names the request pipeline drops before populating
/// header snapshots on hook surfaces (`ClassifyRequest::headers`,
/// `LookupRequest::request_headers`).
///
/// Redaction is enforced at the snapshot site so hook implementations
/// never observe raw credential material. The set is deliberately
/// minimal: it covers the three credential carriers that any HTTP
/// request can plausibly carry. Hook implementations that need finer
/// redaction (e.g. cookie-name allow-listing, custom bearer headers)
/// should redact further on their side rather than asking the proxy to
/// expand this set.
///
/// Names are matched case-insensitively against
/// `pingora_http::HeaderName::as_str()`, which is already lower-cased on
/// HTTP/2 and HTTP/3 and folded by Pingora on HTTP/1.1.
pub const REDACTED_REQUEST_HEADERS: &[&str] = &["authorization", "cookie", "proxy-authorization"];

// ============================================================================
// Startup hook
// ============================================================================

/// One-shot lifecycle hook that wires enterprise implementations into a
/// freshly compiled pipeline.
///
/// Exactly one implementation is registered per binary using the
/// `register_startup_hook!` macro and collected through `inventory`. OSS
/// binaries register none and all other hook slots remain `None`.
///
/// `on_startup` runs once at process boot; `on_reload` runs on every
/// hot-reload after the new pipeline is compiled but before it is swapped
/// in as the live pipeline.
#[async_trait]
pub trait EnterpriseStartupHook: Send + Sync {
    /// Populate enterprise slots on the freshly compiled pipeline at
    /// process boot. Returning an error aborts startup.
    async fn on_startup(
        &self,
        pipeline: &mut crate::pipeline::CompiledPipeline,
    ) -> anyhow::Result<()>;

    /// Re-populate enterprise slots on a reloaded pipeline. Called after
    /// the new `CompiledPipeline` is built from reloaded config, before
    /// it goes live. Returning an error causes the reload to be aborted
    /// and the previous pipeline stays in place.
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
/// Carries the fields the enterprise classifier needs to label the prompt
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

/// Labels + confidence returned by the enterprise classifier.
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
/// Enterprise builds supply a gRPC-backed implementation; OSS leaves the
/// slot as `None`. Implementations must be fail-open: any transport,
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
/// Producers (enterprise classifier, heuristic fallback) pick one of these
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
/// Enterprise-only. Fail-open: returning `None` means "no opinion, use
/// the router's default ordering."
#[async_trait]
pub trait QualityScoringHook: Send + Sync {
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
/// Enterprise-only. Returning `None` from `start_session` means "no
/// safety check for this request" and the stream is forwarded as-is.
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
// Semantic lookup hook
// ============================================================================

/// Input to [`SemanticLookupHook::lookup`].
///
/// Carries everything the semantic cache needs to compose a key and
/// match against stored entries: origin, optional model id, the raw
/// prompt, the full request headers/body, and method/path for response
/// faithfulness.
#[derive(Debug, Clone)]
pub struct LookupRequest {
    /// Origin identifier for cache scoping.
    pub origin: String,
    /// Optional model identifier used as part of the cache key.
    pub model_id: Option<String>,
    /// Raw prompt text used to compute the embedding.
    pub prompt: String,
    /// Snapshot of the inbound request headers, with credential
    /// carriers stripped.
    ///
    /// Populated from the live Pingora request the same way as
    /// [`ClassifyRequest::headers`]: header names are lower-cased and
    /// the entries listed in [`REDACTED_REQUEST_HEADERS`] are dropped
    /// before the snapshot reaches the cache. Cache key templates that
    /// reference `{header.x}` placeholders read from this map.
    pub request_headers: HashMap<String, String>,
    /// Request body bytes used for keying when prompts are non-trivial.
    pub request_body: Bytes,
    /// HTTP method of the original request.
    pub method: String,
    /// Request path used for cache faithfulness against the cached response.
    pub path: String,
}

/// A cached response replayed on a semantic hit.
///
/// Represents the full upstream response minus transport framing. Served
/// verbatim to the client; callers should add a `X-Cache: HIT` style
/// header if they want observability.
#[derive(Debug, Clone)]
pub struct CachedResponse {
    /// HTTP status code of the cached response.
    pub status: u16,
    /// Cached response headers keyed by name.
    pub headers: HashMap<String, String>,
    /// Cached response body bytes.
    pub body: Bytes,
    /// Wall-clock time the entry was stored.
    pub cached_at: std::time::SystemTime,
}

/// Input to [`SemanticLookupHook::store`] carried over from the
/// matching `lookup` call.
///
/// The `key` is the opaque string returned in [`LookupOutcome::miss_key`]
/// so the response-capture path can store without re-running the
/// embedding + LSH pipeline.
#[derive(Debug, Clone)]
pub struct StoreRequest {
    /// Origin identifier for cache scoping.
    pub origin: String,
    /// Optional model identifier scoping the cache entry.
    pub model_id: Option<String>,
    /// Opaque cache key returned previously from a `lookup` miss.
    pub key: String,
}

/// Scope selector for [`SemanticLookupHook::purge`].
///
/// Lets operators clear the cache broadly (`All`), by origin, or by key
/// prefix / exact key. Implementations return the number of entries
/// actually evicted.
#[derive(Debug, Clone)]
pub enum PurgeScope {
    /// Purge every cache entry across all origins.
    All,
    /// Purge entries for a single origin.
    Origin(String),
    /// Purge entries whose key starts with the given prefix.
    KeyPrefix(String),
    /// Purge a single entry matching the exact key.
    KeyExact(String),
}

/// How a cached response should be replayed back to the client.
///
/// Most cached responses are buffered: the proxy writes the response
/// header followed by the full body in a single `write_response_body`
/// call. Streaming responses (SSE, chat-completions with `stream=true`)
/// can opt into being replayed as a chunked stream so the client sees
/// SSE framing rather than a one-shot blob.
///
/// The OSS forwarding path currently only honours [`ResponseMode::Buffered`];
/// the streamed-replay path is gated on a separate follow-up that will
/// teach `handle_ai_proxy` to dispatch on this enum and emit chunks
/// paced by the configured strategy. Enterprise implementations may
/// already set this to [`ResponseMode::Streamed`] today: the OSS proxy
/// will fall back to a buffered replay until the forwarding-path change
/// lands. See `docs/roadmap.md` (F3.26) for tracking.
///
/// The variant carries the chunk list and pacing strategy so the OSS
/// forwarding path can emit chunks back-to-back without re-parsing the
/// SSE framing. Recorder implementations are responsible for splitting
/// the captured byte stream into the chunk vector.
#[derive(Debug, Clone, Default)]
pub enum ResponseMode {
    /// Replay the cached response as a single buffered body write.
    #[default]
    Buffered,
    /// Replay the cached response as a chunked SSE stream.
    Streamed {
        /// Ordered chunk list produced by the recorder. Each entry is
        /// the raw bytes of one SSE chunk, including any trailing
        /// `\n\n` framing that the recorder chose to keep with the
        /// chunk. The OSS replay path writes these in order.
        chunks: Vec<Bytes>,
        /// How aggressively to emit chunks back to the client.
        pacing: ReplayPacing,
    },
}

/// Pacing strategy for streamed cache replay.
///
/// Affects how `handle_ai_proxy` schedules `write_response_body` calls
/// when replaying a [`ResponseMode::Streamed`] hit. The OSS forwarding
/// path will dispatch on this once the streamed-replay follow-up
/// lands; enterprise recorders may already set the field today.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ReplayPacing {
    /// Emit every cached chunk back-to-back. Targets a TTFB measured
    /// in single-digit milliseconds on a warm cache.
    #[default]
    AsFastAsPossible,
    /// Emit chunks with their original inter-chunk delays (recorder's
    /// best-effort approximation), or a fixed natural-pacing budget
    /// when the recorder did not capture per-chunk timing.
    Natural,
}

/// Outcome of a [`SemanticLookupHook::lookup`] call.
///
/// On a cache hit `hit` carries the cached response. On a miss, `hit` is
/// `None` and `miss_key` carries the composed cache key so the caller can
/// use it later (e.g. in the response-capture path) to populate the cache
/// via `store` without re-running the embedding + LSH pipeline.
///
/// `cacheable_status` and `max_response_size` come from the hook's
/// per-origin / server-default view so the caller can apply the same
/// gates the hook would apply on write (status allow-list + body-size
/// cap) without duplicating that configuration.
///
/// `response_mode` defaults to [`ResponseMode::Buffered`], matching the
/// pre-streamed-replay forwarding behaviour. Enterprise streaming-cache
/// implementations may set [`ResponseMode::Streamed`] when the cached
/// entry was captured from an SSE response and the operator opted into
/// streamed replay. The OSS forwarding path currently always replays
/// buffered; honouring `Streamed` is tracked separately under F3.26.
#[derive(Debug, Clone, Default)]
pub struct LookupOutcome {
    /// Some when the cache returned a live entry for this request.
    pub hit: Option<CachedResponse>,
    /// Composed cache key to use on subsequent `store` calls. Populated
    /// on misses (and None when the lookup bypassed before key computation,
    /// e.g. disabled origin or empty prompt).
    pub miss_key: Option<String>,
    /// Status codes eligible for caching. Empty => caller default (`[200]`).
    pub cacheable_status: Vec<u16>,
    /// Upper bound on response body size that may be cached. `None` =>
    /// caller default (unbounded).
    pub max_response_size: Option<usize>,
    /// How the cached response should be replayed (buffered vs streamed).
    /// Defaults to [`ResponseMode::Buffered`]. The OSS forwarding path
    /// currently honours only `Buffered`; `Streamed` is wired through
    /// for enterprise recorders ahead of the OSS replay-path follow-up.
    pub response_mode: ResponseMode,
}

/// Semantic (embedding-based) response cache.
///
/// Enterprise-only. The OSS pipeline carries only a literal response
/// cache (`sbproxy_cache::CacheStore`); this hook layers semantic
/// similarity on top so near-duplicate prompts can share a cached
/// response.
///
/// Implementations must be fail-open: errors on `lookup` should surface
/// as "miss" (empty `LookupOutcome`) rather than bubbling up. `store`
/// and `purge` return errors, but callers typically log and continue.
#[async_trait]
pub trait SemanticLookupHook: Send + Sync {
    /// Perform a semantic cache lookup.
    ///
    /// Returns a [`LookupOutcome`] rather than a bare `Option<CachedResponse>`
    /// so the caller can also learn the miss key (for a later `store` call)
    /// and the effective per-origin gating policy without having to
    /// re-derive any of that state itself.
    async fn lookup(&self, req: &LookupRequest) -> LookupOutcome;

    /// Store `resp` under the key previously returned as
    /// [`LookupOutcome::miss_key`]. Callers typically invoke this from the
    /// response-capture path after validating that the response is
    /// cacheable (status allow-list, body-size cap).
    async fn store(&self, req: StoreRequest, resp: CachedResponse) -> anyhow::Result<()>;

    /// Purge entries matching `scope`. Returns the number of entries
    /// evicted. Used by the admin API for manual cache invalidation.
    async fn purge(&self, scope: PurgeScope) -> anyhow::Result<u64>;
}

// ============================================================================
// Stream cache recorder hook
// ============================================================================

/// Per-session context handed to [`StreamCacheRecorderHook::start_session`].
///
/// Carries the routing identity (hostname, origin id, request id) plus a
/// pre-derived semantic cache key passed through verbatim from the
/// pre-existing semantic-lookup machinery (`LookupOutcome::miss_key`).
/// The OSS proxy never recomputes embeddings, key templates, or LSH
/// buckets here; if the enterprise side needs more signals it can
/// extend the carried `policy` blob.
#[derive(Debug, Clone)]
pub struct StreamCacheCtx {
    /// Origin hostname this stream belongs to.
    pub hostname: String,
    /// Origin identifier for cache scoping (typically the origin index
    /// rendered as a string, matching other hook surfaces).
    pub origin_id: String,
    /// Correlation id for the in-flight request, propagated from the
    /// per-request context. Useful for joining recorder events back to
    /// the request log.
    pub request_id: String,
    /// Optional semantic cache key derived by the enterprise lookup
    /// machinery (mirrors [`LookupOutcome::miss_key`]). `None` when the
    /// caller could not derive a key (e.g. empty prompt, lookup
    /// disabled). Implementations typically refuse recording when this
    /// is `None`.
    pub semantic_key: Option<String>,
    /// Optional model identifier in flight on this stream.
    pub model_id: Option<String>,
    /// Opaque enterprise policy blob copied from the AI handler's
    /// `semantic_cache.streaming` config (e.g. `replay_pacing`). The OSS
    /// proxy does not validate or interpret this value; the enterprise
    /// recorder reads whatever shape it expects.
    pub policy: serde_json::Value,
}

/// Single event sent by the proxy down a recorder session channel.
///
/// Implementations receive a stream that is exactly one `End` event
/// preceded by zero or more `Chunk` events. The proxy guarantees the
/// terminal `End` is sent at most once per session, even on cancellation
/// or error.
#[derive(Debug, Clone)]
pub enum StreamCacheEvent {
    /// One forwarded SSE chunk. The bytes are a copy of what was written
    /// to the client and may include partial events; the recorder is
    /// responsible for any framing-aware reassembly.
    Chunk(Bytes),
    /// Terminal event for the session.
    ///
    /// `complete=true` means the upstream stream finished cleanly and
    /// every byte was delivered to the client. `complete=false` covers
    /// every other terminal condition the proxy can observe: client
    /// cancel, upstream error, mid-stream abort, or the recorder being
    /// dropped before `finish` is called.
    End {
        /// Whether the recording represents a clean end-of-stream.
        complete: bool,
    },
}

/// Default capacity for the bounded recorder channel.
///
/// Sized for ~1 second of headroom at 1k events/sec on a typical SSE
/// stream. The receiver lives inside the enterprise recorder and is
/// expected to drain at least as fast as the upstream produces chunks;
/// when it temporarily falls behind, the proxy drops the chunk and
/// increments `sbproxy_hooks_channel_dropped_total{reason="channel_full"}`
/// rather than buffering without bound and risking OOM under load.
/// Enterprise call sites that want a different bound can construct
/// their own [`tokio::sync::mpsc::channel`] of any size and assign the
/// sender to [`StreamCacheChannel::tx`] directly.
pub const STREAM_CACHE_CHANNEL_CAPACITY: usize = 1024;

/// Channel handed to the proxy when a recorder session starts.
///
/// The proxy owns `tx` and sends one [`StreamCacheEvent::Chunk`] per
/// forwarded SSE chunk, followed by exactly one terminal
/// [`StreamCacheEvent::End`]. The receiver lives inside the enterprise
/// implementation; OSS code never reads from it.
///
/// Sends are non-blocking and use [`tokio::sync::mpsc::Sender::try_send`]
/// so a slow or unreachable receiver never stalls the hot path. A
/// closed channel (the enterprise side dropped the receiver early)
/// is not an error: the proxy increments
/// `sbproxy_hooks_channel_dropped_total{reason="receiver_closed"}` and
/// stops sending. A full channel surfaces as
/// `sbproxy_hooks_channel_dropped_total{reason="channel_full"}`.
pub struct StreamCacheChannel {
    /// Sender used by the proxy to push events into the recorder session.
    ///
    /// Bounded at [`STREAM_CACHE_CHANNEL_CAPACITY`] by default;
    /// enterprise implementations that want a different bound can
    /// build a [`tokio::sync::mpsc::channel`] of any size and assign
    /// the sender here.
    pub tx: tokio::sync::mpsc::Sender<StreamCacheEvent>,
}

/// RAII guard that fans SSE stream events into a [`StreamCacheChannel`]
/// and emits a terminal `End` event exactly once.
///
/// The proxy creates one of these per recorder session. Calling
/// [`StreamCacheGuard::chunk`] forwards a copy of the chunk to the
/// recorder. Calling [`StreamCacheGuard::finish`] sends
/// `End { complete: true }`. Dropping the guard without calling `finish`
/// sends `End { complete: false }` so the enterprise impl can
/// distinguish a partial recording (client cancel, upstream error,
/// mid-stream abort) from a clean recording.
///
/// `chunk` and `finish` swallow `SendError`: a closed channel means the
/// enterprise side dropped the recorder, which is an explicit "stop
/// recording" signal, not a fatal error.
pub struct StreamCacheGuard {
    channel: StreamCacheChannel,
    finished: bool,
}

impl StreamCacheGuard {
    /// Wrap an open [`StreamCacheChannel`] returned by
    /// [`StreamCacheRecorderHook::start_session`].
    pub fn new(channel: StreamCacheChannel) -> Self {
        Self {
            channel,
            finished: false,
        }
    }

    /// Forward a single chunk. Best-effort and non-blocking: the
    /// underlying channel is bounded at [`STREAM_CACHE_CHANNEL_CAPACITY`]
    /// and a full buffer or closed receiver causes the chunk to be
    /// dropped with a `sbproxy_hooks_channel_dropped_total{reason}`
    /// increment. The recorder is enterprise-only and explicitly
    /// fail-open: dropping chunks is preferable to stalling the
    /// proxy hot path.
    pub fn chunk(&self, bytes: Bytes) {
        if let Err(err) = self.channel.tx.try_send(StreamCacheEvent::Chunk(bytes)) {
            record_stream_cache_drop(&err);
        }
    }

    /// Send the terminal `End { complete: true }` event. After this call
    /// the guard no longer emits a terminal event on drop.
    ///
    /// Calling `finish` more than once is a no-op. The terminal event
    /// is best-effort: if the receiver has hung up or the channel is
    /// at capacity, the drop is counted against
    /// `sbproxy_hooks_channel_dropped_total` and the guard moves on.
    pub fn finish(mut self) {
        if !self.finished {
            self.finished = true;
            if let Err(err) = self
                .channel
                .tx
                .try_send(StreamCacheEvent::End { complete: true })
            {
                record_stream_cache_drop(&err);
            }
        }
    }
}

impl Drop for StreamCacheGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.finished = true;
            if let Err(err) = self
                .channel
                .tx
                .try_send(StreamCacheEvent::End { complete: false })
            {
                record_stream_cache_drop(&err);
            }
        }
    }
}

/// Map a `TrySendError` from the recorder channel into a
/// `sbproxy_hooks_channel_dropped_total` increment. Lives outside the
/// guard impl so both the chunk path and the terminal-event paths
/// can share the classification.
fn record_stream_cache_drop(err: &tokio::sync::mpsc::error::TrySendError<StreamCacheEvent>) {
    let reason = match err {
        tokio::sync::mpsc::error::TrySendError::Full(_) => "channel_full",
        tokio::sync::mpsc::error::TrySendError::Closed(_) => "receiver_closed",
    };
    sbproxy_observe::metrics::record_channel_drop("hooks", reason);
}

/// Records a streaming AI response into a downstream cache for later
/// replay.
///
/// Enterprise-only. The OSS proxy's only job is to fan SSE chunks into
/// the channel returned by `start_session` and emit a terminal `End`
/// event when the stream finishes (or aborts). All policy decisions
/// (deterministic tool calls only, image data by reference only,
/// replay pacing, eviction, persistence) live in the enterprise
/// implementation and are out of scope for OSS.
///
/// Returning `None` from `start_session` means "do not record this
/// stream" (e.g. the caller could not derive a semantic key, or the
/// recorder is disabled for this origin). The proxy proceeds with
/// normal SSE forwarding without any recording overhead.
#[async_trait]
pub trait StreamCacheRecorderHook: Send + Sync {
    /// Start a recording session for the SSE response described by
    /// `ctx`. Returns a [`StreamCacheChannel`] when the recorder
    /// accepts the session, or `None` to skip recording for this
    /// stream. The proxy guarantees exactly one terminal
    /// [`StreamCacheEvent::End`] per accepted session.
    async fn start_session(&self, ctx: StreamCacheCtx) -> Option<StreamCacheChannel>;
}

// ============================================================================
// Aggregate: Hooks bundle owned by CompiledPipeline
// ============================================================================

/// Bundle of all enterprise hook slots owned by [`crate::pipeline::CompiledPipeline`].
///
/// Every slot defaults to `None`. OSS binaries leave all slots empty;
/// enterprise binaries populate them from their
/// [`EnterpriseStartupHook::on_startup`] implementation. Request-path
/// code checks each slot before dispatching and no-ops when `None`.
#[derive(Default, Clone)]
pub struct Hooks {
    /// Lifecycle hook that populates the other slots. Registered via
    /// `inventory` and collected by [`crate::hook_registry::collect_startup_hook`].
    pub startup: Option<Arc<dyn EnterpriseStartupHook>>,
    /// Prompt classification (labels + confidence).
    pub prompt_classifier: Option<Arc<dyn PromptClassifierHook>>,
    /// Coarse intent detection used by model routers.
    pub intent_detection: Option<Arc<dyn IntentDetectionHook>>,
    /// Provider quality scoring used for router reranking.
    pub quality_scoring: Option<Arc<dyn QualityScoringHook>>,
    /// Streaming-response safety supervision.
    pub stream_safety: Option<Arc<dyn StreamSafetyHook>>,
    /// Semantic (embedding-based) response cache.
    pub semantic_lookup: Option<Arc<dyn SemanticLookupHook>>,
    /// Streaming semantic-cache recorder. When wired, every AI SSE
    /// response that exposes a derivable semantic key is fanned into
    /// the recorder's channel for later replay. The OSS pipeline never
    /// decides what to do with the recorded chunks; it just forwards
    /// them.
    pub stream_cache_recorder: Option<Arc<dyn StreamCacheRecorderHook>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::sync::mpsc;

    // --- Hooks::default ---

    #[test]
    fn hooks_default_leaves_every_slot_none() {
        let hooks = Hooks::default();
        assert!(hooks.startup.is_none());
        assert!(hooks.prompt_classifier.is_none());
        assert!(hooks.intent_detection.is_none());
        assert!(hooks.quality_scoring.is_none());
        assert!(hooks.stream_safety.is_none());
        assert!(hooks.semantic_lookup.is_none());
        assert!(
            hooks.stream_cache_recorder.is_none(),
            "OSS default must leave stream_cache_recorder unwired"
        );
    }

    // --- LookupOutcome / ResponseMode defaults ---

    /// `LookupOutcome::default()` must keep the buffered-replay shape
    /// so existing OSS forwarding logic sees no behavioural change
    /// when the streamed-replay enum variant lands.
    #[test]
    fn lookup_outcome_default_is_buffered() {
        let outcome = LookupOutcome::default();
        assert!(matches!(outcome.response_mode, ResponseMode::Buffered));
        assert!(outcome.hit.is_none());
        assert!(outcome.miss_key.is_none());
        assert!(outcome.cacheable_status.is_empty());
        assert!(outcome.max_response_size.is_none());
    }

    /// Recorders may construct a `Streamed` variant directly. Verify
    /// the chunk list and pacing are carried verbatim so the future OSS
    /// replay path can drain the chunks in order.
    #[test]
    fn lookup_outcome_streamed_carries_chunks_and_pacing() {
        let chunks = vec![
            Bytes::from_static(b"data: a\n\n"),
            Bytes::from_static(b"data: b\n\n"),
        ];
        let outcome = LookupOutcome {
            response_mode: ResponseMode::Streamed {
                chunks: chunks.clone(),
                pacing: ReplayPacing::Natural,
            },
            ..Default::default()
        };
        match outcome.response_mode {
            ResponseMode::Streamed {
                chunks: got,
                pacing,
            } => {
                assert_eq!(got, chunks);
                assert_eq!(pacing, ReplayPacing::Natural);
            }
            ResponseMode::Buffered => panic!("expected Streamed variant"),
        }
    }

    // --- StreamCacheRecorderHook contract ---

    /// Recorder that captures every event it receives, used to assert
    /// the OSS proxy honours the channel contract.
    struct MockRecorder {
        accept: bool,
        seen_ctx: Mutex<Option<StreamCacheCtx>>,
        // Holds the receiver half so we can drain it after the guard
        // is dropped without racing the test thread.
        rx: Mutex<Option<mpsc::Receiver<StreamCacheEvent>>>,
    }

    impl MockRecorder {
        fn new(accept: bool) -> Self {
            Self {
                accept,
                seen_ctx: Mutex::new(None),
                rx: Mutex::new(None),
            }
        }

        fn drain(&self) -> Vec<StreamCacheEvent> {
            let mut rx = self
                .rx
                .lock()
                .unwrap()
                .take()
                .expect("recorder receiver already drained");
            let mut out = Vec::new();
            while let Ok(ev) = rx.try_recv() {
                out.push(ev);
            }
            out
        }
    }

    #[async_trait]
    impl StreamCacheRecorderHook for MockRecorder {
        async fn start_session(&self, ctx: StreamCacheCtx) -> Option<StreamCacheChannel> {
            *self.seen_ctx.lock().unwrap() = Some(ctx);
            if !self.accept {
                return None;
            }
            let (tx, rx) = mpsc::channel(STREAM_CACHE_CHANNEL_CAPACITY);
            *self.rx.lock().unwrap() = Some(rx);
            Some(StreamCacheChannel { tx })
        }
    }

    fn fake_ctx() -> StreamCacheCtx {
        StreamCacheCtx {
            hostname: "ai.example.com".to_string(),
            origin_id: "0".to_string(),
            request_id: "req-test-1".to_string(),
            semantic_key: Some("sem-key-abc".to_string()),
            model_id: Some("gpt-4o-mini".to_string()),
            policy: serde_json::json!({"enabled": true, "replay_pacing": "natural"}),
        }
    }

    #[tokio::test]
    async fn recorder_sees_every_chunk_and_clean_terminal_end() {
        // Wire a MockRecorder, drive a fake SSE stream through the same
        // emit shape `relay_ai_stream` uses (start_session -> chunk per
        // upstream chunk -> finish on clean end), and assert the
        // recorder observed each chunk plus exactly one terminal
        // `End { complete: true }`.
        let recorder = std::sync::Arc::new(MockRecorder::new(true));

        let ctx = fake_ctx();
        let channel = recorder
            .start_session(ctx.clone())
            .await
            .expect("recorder accepted");
        let guard = StreamCacheGuard::new(channel);

        // Simulate the upstream SSE stream chunk loop.
        let chunks: Vec<Bytes> = vec![
            Bytes::from_static(b"data: {\"id\":\"1\"}\n\n"),
            Bytes::from_static(b"data: {\"id\":\"2\"}\n\n"),
            Bytes::from_static(b"data: [DONE]\n\n"),
        ];
        for c in &chunks {
            guard.chunk(c.clone());
        }
        // Clean end-of-stream.
        guard.finish();

        // Context fields must round-trip into the hook unchanged.
        let seen = recorder.seen_ctx.lock().unwrap().clone().expect("ctx set");
        assert_eq!(seen.hostname, "ai.example.com");
        assert_eq!(seen.origin_id, "0");
        assert_eq!(seen.request_id, "req-test-1");
        assert_eq!(seen.semantic_key.as_deref(), Some("sem-key-abc"));
        assert_eq!(seen.model_id.as_deref(), Some("gpt-4o-mini"));
        assert_eq!(seen.policy["replay_pacing"], "natural");

        // Drain and shape-check the events.
        let events = recorder.drain();
        assert_eq!(
            events.len(),
            chunks.len() + 1,
            "expected one chunk per upstream chunk plus a terminal End"
        );
        for (i, c) in chunks.iter().enumerate() {
            match &events[i] {
                StreamCacheEvent::Chunk(b) => assert_eq!(b, c),
                other => panic!("event {i} should be Chunk, got {other:?}"),
            }
        }
        match events.last().expect("terminal event present") {
            StreamCacheEvent::End { complete } => {
                assert!(*complete, "clean finish must report complete=true");
            }
            other => panic!("last event should be End, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn recorder_sees_partial_terminal_end_when_guard_dropped_mid_stream() {
        // If the proxy's per-request context is dropped before the
        // stream finishes (client cancel, upstream error, mid-stream
        // abort), the guard's Drop impl must still emit exactly one
        // terminal `End { complete: false }`.
        let recorder = std::sync::Arc::new(MockRecorder::new(true));

        let channel = recorder
            .start_session(fake_ctx())
            .await
            .expect("recorder accepted");

        {
            let guard = StreamCacheGuard::new(channel);
            guard.chunk(Bytes::from_static(b"data: partial\n\n"));
            // Simulated mid-stream cancellation: drop without finish.
        }

        let events = recorder.drain();
        assert_eq!(events.len(), 2, "expected 1 chunk + 1 terminal End");
        match &events[0] {
            StreamCacheEvent::Chunk(b) => {
                assert_eq!(b.as_ref(), b"data: partial\n\n");
            }
            other => panic!("expected Chunk, got {other:?}"),
        }
        match &events[1] {
            StreamCacheEvent::End { complete } => {
                assert!(!*complete, "drop without finish must report complete=false");
            }
            other => panic!("expected End, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn recorder_returning_none_skips_recording() {
        // When `start_session` returns None the OSS proxy must not call
        // anything else. We simulate by simply not constructing a guard.
        let recorder = std::sync::Arc::new(MockRecorder::new(false));
        let result = recorder.start_session(fake_ctx()).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn guard_finish_is_idempotent_against_closed_channel() {
        // If the enterprise side drops its receiver early (an explicit
        // "stop recording" signal), `chunk` and `finish` must not
        // panic; they swallow SendError silently.
        let (tx, rx) = mpsc::channel(STREAM_CACHE_CHANNEL_CAPACITY);
        drop(rx);
        let guard = StreamCacheGuard::new(StreamCacheChannel { tx });
        guard.chunk(Bytes::from_static(b"x"));
        guard.finish(); // no panic, no error
    }

    /// Scrape the `sbproxy_hooks_channel_dropped_total{reason}` value
    /// from the global Prometheus registry, returning 0 when no
    /// counter exists yet. The lazy-init in `record_channel_drop`
    /// means the metric is absent until the first drop fires.
    ///
    /// The `get_*` accessors are deprecated in prometheus 0.14 in
    /// favour of `name()` / `value()` / `metric()`, but the new
    /// `Counter::value()` accessor on the inner `MessageField<Counter>`
    /// is the only way to extract the f64 sample. We keep the
    /// deprecated `MetricFamily::get_*` calls for label inspection
    /// and silence the warning locally; the bridge is well-defined
    /// and stable across the 0.14 line.
    #[allow(deprecated)]
    fn hooks_drop_total(reason: &str) -> u64 {
        for mf in prometheus::gather() {
            if mf.get_name() != "sbproxy_hooks_channel_dropped_total" {
                continue;
            }
            for m in mf.get_metric() {
                let matches = m
                    .get_label()
                    .iter()
                    .any(|lp| lp.get_name() == "reason" && lp.get_value() == reason);
                if matches {
                    // `m.get_counter()` returns `&MessageField<Counter>`
                    // which derefs to `&Counter`; `Counter::value()`
                    // yields the f64 sample value.
                    return m.get_counter().value() as u64;
                }
            }
        }
        0
    }

    /// WOR-169: a bounded recorder channel that fills past its
    /// capacity must drop the overflowing send AND increment
    /// `sbproxy_hooks_channel_dropped_total{reason="channel_full"}`.
    /// Verifies the documented backpressure policy directly.
    #[tokio::test]
    async fn channel_full_drops_chunk_and_increments_counter() {
        // Capacity 2 keeps the test fast while still exercising the
        // "full" branch of `TrySendError`. We deliberately do NOT
        // drain the receiver so the channel saturates.
        let (tx, _rx) = mpsc::channel(2);
        let guard = StreamCacheGuard::new(StreamCacheChannel { tx });

        let before = hooks_drop_total("channel_full");
        // Fill the channel to capacity (slots 1 and 2).
        guard.chunk(Bytes::from_static(b"a"));
        guard.chunk(Bytes::from_static(b"b"));
        // Third chunk has nowhere to land: channel is full, receiver
        // is still alive. The send must be dropped silently and the
        // "channel_full" counter must tick.
        guard.chunk(Bytes::from_static(b"c"));
        let after = hooks_drop_total("channel_full");

        assert!(
            after > before,
            "channel_full counter must increment by at least 1 (before={before}, after={after})"
        );
        // The guard's drop attempt for the terminal End will also
        // see the full channel and tick the same counter, which is
        // fine; we only care that the chunk drop was counted.
    }

    /// WOR-169: when the receiver hangs up, the next send must be
    /// dropped AND counted under the `receiver_closed` label rather
    /// than `channel_full`. Keeps the two failure modes
    /// distinguishable on the dashboard.
    #[tokio::test]
    async fn receiver_closed_drops_send_and_increments_counter() {
        let (tx, rx) = mpsc::channel(STREAM_CACHE_CHANNEL_CAPACITY);
        drop(rx); // explicit "stop recording" signal from the enterprise side
        let guard = StreamCacheGuard::new(StreamCacheChannel { tx });

        let before = hooks_drop_total("receiver_closed");
        guard.chunk(Bytes::from_static(b"x"));
        let after = hooks_drop_total("receiver_closed");

        assert!(
            after > before,
            "receiver_closed counter must increment by at least 1 (before={before}, after={after})"
        );
    }
}
