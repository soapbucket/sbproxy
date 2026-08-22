//! HTTP client for forwarding requests to AI providers.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use sbproxy_security::egress::{
    evaluate_hop, record_egress_refused, CachedSystemResolver, EgressAuthorizer, EgressDenied,
    EgressPurpose, HostResolver, RedirectRule,
};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::ai_metrics;
use crate::aws_sigv4::AwsSigV4Signer;
use crate::compression::{SummarizationOutput, SummarizerError};
use crate::handler::AiHandlerConfig;
use crate::provider::ProviderConfig;
use crate::providers::{get_provider_info, ProviderFormat};
use crate::routing::{provider_allowed_by_policy, Router};
use crate::translators;
use crate::usage_sink::{LlmUsageEvent, UsageSink};

/// Default upper bound on shadow requests in flight per `AiClient`.
pub const DEFAULT_SHADOW_MAX_INFLIGHT: usize = 16;
/// Process-wide shadow memory reservation budget per `AiClient`.
///
/// Admission reserves twice the serialized request size plus twice the
/// response metadata cap for each task. This covers the request clone and
/// transient response translation without allowing task count and per-task
/// buffers to multiply into an unbounded resident-memory claim.
pub const DEFAULT_SHADOW_MEMORY_BUDGET_BYTES: usize = 64 * 1024 * 1024;

/// Minimum interval between rate-limited shadow-overflow WARN log
/// lines. Bursts above this rate are coalesced into a single line.
const SHADOW_OVERFLOW_WARN_INTERVAL: Duration = Duration::from_secs(60);
/// Maximum response bytes retained for shadow usage metadata parsing.
/// The response is still drained so the connection can be reused.
const MAX_SHADOW_RESPONSE_METADATA_BYTES: usize = 1024 * 1024;
const PROVIDER_RETRY_BASE_DELAY: Duration = Duration::from_millis(100);
const PROVIDER_RETRY_MAX_DELAY: Duration = Duration::from_secs(2);
const PROVIDER_RETRY_JITTER_PCT: u64 = 25;

/// One outbound credential scheme, applied to a fully built request
/// immediately before it goes on the wire.
///
/// # Contract
///
/// This is the seam every non-bearer credential scheme plugs into, so
/// these rules are the contract rather than an implementation detail
/// of the one scheme that exists today,
/// [`crate::aws_sigv4::AwsSigV4Signer`].
///
/// 1. **Position.** `send_governed` calls [`OutboundSigner::sign`]
///    immediately before each `Client::execute`. Nothing between that
///    call and the socket mutates the request except the headers hyper
///    writes itself (`host`, `content-length`, `accept-encoding`). A
///    scheme that covers a header therefore has to be able to
///    guarantee that header's value, and has to leave the ones hyper
///    owns alone.
/// 2. **Per attempt, per hop.** `sign` runs again on every retry and
///    again on every redirect hop, after the URL has been rewritten to
///    the next target. A credential bound to a host, a path, or a body
///    is always bound to the one being sent, never to the previous
///    one. Any code that mutates a request has to run above this
///    boundary; nothing below it may touch the body.
/// 3. **Idempotence.** The same request object reaches `sign` more
///    than once, because a same-origin redirect replays it. An
///    implementation overwrites every header it owns rather than
///    appending, and never lets one application's output become the
///    next application's input.
/// 4. **Fail closed.** An error from `sign` fails the attempt. There
///    is no unsigned fallback, and a refusing implementation leaves no
///    partially applied credential behind.
/// 5. **Secrecy.** No implementation puts credential material into a
///    log line, an error string, a `Debug` render, a metric label, or
///    a panic message, and every header it writes is marked sensitive
///    so `strip_sensitive_headers` drops it on a cross-origin hop.
///
/// A scheme that needs to see what the upstream said (an expiry
/// signal, a challenge, a clock reading) implements
/// [`OutboundSigner::observe_response`], called once per response with
/// the status, the headers, and the round-trip time. It runs on the
/// request path, so it must not block.
#[async_trait::async_trait]
pub trait OutboundSigner: Send + Sync + std::fmt::Debug {
    /// Stable label for this scheme, for logs and diagnostics. Never
    /// derived from a credential value.
    fn scheme(&self) -> &'static str;

    /// Apply this scheme's credential to `request` in place.
    ///
    /// # Errors
    ///
    /// Any failure fails the attempt; there is no unsigned fallback.
    async fn sign(&self, request: &mut reqwest::Request) -> Result<()>;

    /// Observe one upstream response. Ignored by default.
    fn observe_response(
        &self,
        _status: reqwest::StatusCode,
        _headers: &reqwest::header::HeaderMap,
        _round_trip: Duration,
    ) {
    }
}

/// Per-provider outbound signers, built on first use.
///
/// Building a signer can cost an STS round trip, so it happens once
/// per provider rather than once per request. A config reload replaces
/// the whole [`AiClient`] (see `sbproxy_core::server::reload_ai_client`),
/// which drops this cache with it, so a provider name is a sufficient
/// key: an entry can never outlive the `aws_sigv4:` block that
/// produced it.
#[derive(Default)]
struct SignerCache {
    built: tokio::sync::Mutex<std::collections::HashMap<String, Arc<AwsSigV4Signer>>>,
}

impl SignerCache {
    /// The signer for `provider`, or `None` when the provider carries
    /// no `aws_sigv4:` block.
    ///
    /// Absence of the block is what selects verbatim credential
    /// pass-through, so there is no runtime branch in which an
    /// unsigned provider acquires a signer or a signed provider also
    /// forwards a static credential header.
    async fn signer_for(&self, provider: &ProviderConfig) -> Result<Option<Arc<AwsSigV4Signer>>> {
        let Some(config) = provider.aws_sigv4.as_ref() else {
            return Ok(None);
        };
        // Fail closed on a block that cannot sign, before anything
        // dials AWS with it. This is the only place that check runs
        // today: the handler's per-provider validation loop
        // (`AiHandlerConfig::from_config`, alongside `validate_base_url`)
        // is where it belongs, so the operator learns at config load
        // rather than on the first request, and adding it there is the
        // one follow-up this lane could not land itself.
        provider
            .validate_aws_sigv4()
            .map_err(|reason| anyhow::anyhow!("provider {}: {reason}", provider.name))?;
        let mut built = self.built.lock().await;
        if let Some(existing) = built.get(provider.name.as_str()) {
            return Ok(Some(existing.clone()));
        }
        let signer = Arc::new(
            AwsSigV4Signer::build(config, provider.effective_provider_type())
                .await
                .map_err(anyhow::Error::new)?,
        );
        debug!(
            provider = %provider.name,
            scheme = %OutboundSigner::scheme(signer.as_ref()),
            "built an outbound request signer for provider"
        );
        built.insert(provider.name.as_str().to_string(), signer.clone());
        Ok(Some(signer))
    }
}

/// Borrow an optional signer as the trait object `send_governed` takes.
fn as_signer(signer: &Option<Arc<AwsSigV4Signer>>) -> Option<&dyn OutboundSigner> {
    signer.as_deref().map(|s| s as &dyn OutboundSigner)
}

/// Supervisor for shadow / side-by-side eval tasks.
///
/// Owns bounded task and memory semaphores so a slow or hung shadow provider
/// can never accumulate unbounded background work or retained response
/// buffers. Each spawned task wraps `run_shadow_request` in
/// `tokio::time::timeout`; when the timeout elapses the future is dropped
/// (which aborts the in-flight reqwest connection) and the
/// `sbproxy_ai_shadow_timeout_total` counter ticks. When either admission
/// resource is exhausted the supervisor logs at WARN at most once per minute
/// and ticks `sbproxy_ai_shadow_dropped_total`.
pub struct ShadowSupervisor {
    semaphore: Arc<Semaphore>,
    memory: Arc<Semaphore>,
    max_inflight: usize,
    max_memory_bytes: usize,
    /// Unix-epoch nanoseconds of the last overflow WARN log. `0`
    /// means "never logged"; `AtomicI64` because `Instant` is not
    /// portable to atomics and a wall-clock skew of a few seconds is
    /// fine for log-rate-limiting.
    last_warn_unix_nanos: AtomicI64,
}

impl ShadowSupervisor {
    /// Build a supervisor with the given in-flight bound.
    pub fn new(max_inflight: usize) -> Self {
        Self::with_memory_budget(max_inflight, DEFAULT_SHADOW_MEMORY_BUDGET_BYTES)
    }

    fn with_memory_budget(max_inflight: usize, max_memory_bytes: usize) -> Self {
        let bound = max_inflight.max(1);
        Self {
            semaphore: Arc::new(Semaphore::new(bound)),
            memory: Arc::new(Semaphore::new(max_memory_bytes)),
            max_inflight: bound,
            max_memory_bytes,
            last_warn_unix_nanos: AtomicI64::new(0),
        }
    }

    /// Maximum concurrent shadow tasks this supervisor will admit.
    pub fn max_inflight(&self) -> usize {
        self.max_inflight
    }

    /// Number of shadow slots currently free.
    pub fn available(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Try to admit one shadow task. Returns the owned permit on
    /// success; on overflow, ticks `sbproxy_ai_shadow_dropped_total`,
    /// emits a rate-limited WARN, and returns `None`.
    #[cfg(test)]
    fn try_admit(&self) -> Option<ShadowPermit> {
        self.try_admit_request(0)
    }

    fn try_admit_request(&self, request_bytes: usize) -> Option<ShadowPermit> {
        let slot = match self.semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return self.reject_admission(),
        };
        let memory_bytes = shadow_memory_reservation(request_bytes);
        if memory_bytes > self.max_memory_bytes {
            return self.reject_admission();
        }
        let memory_permits = match u32::try_from(memory_bytes) {
            Ok(permits) => permits,
            Err(_) => return self.reject_admission(),
        };
        let memory = match self.memory.clone().try_acquire_many_owned(memory_permits) {
            Ok(permit) => permit,
            Err(_) => return self.reject_admission(),
        };
        Some(ShadowPermit {
            _slot: slot,
            _memory: memory,
        })
    }

    fn reject_admission<T>(&self) -> Option<T> {
        ai_metrics::record_shadow_dropped(ai_metrics::ShadowDropReason::Saturated);
        self.maybe_warn_overflow();
        None
    }

    #[cfg(test)]
    fn available_memory_bytes(&self) -> usize {
        self.memory.available_permits()
    }
}

struct ShadowPermit {
    _slot: tokio::sync::OwnedSemaphorePermit,
    _memory: tokio::sync::OwnedSemaphorePermit,
}

fn shadow_memory_reservation(request_bytes: usize) -> usize {
    request_bytes
        .saturating_mul(2)
        .saturating_add(MAX_SHADOW_RESPONSE_METADATA_BYTES.saturating_mul(2))
}

impl ShadowSupervisor {
    /// Emit at most one overflow WARN per
    /// `SHADOW_OVERFLOW_WARN_INTERVAL`. Concurrent overflows are
    /// coalesced via a CAS on `last_warn_unix_nanos`.
    fn maybe_warn_overflow(&self) {
        let now_nanos = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(i64::MAX);
        let interval_nanos = SHADOW_OVERFLOW_WARN_INTERVAL.as_nanos() as i64;
        loop {
            let last = self.last_warn_unix_nanos.load(Ordering::Relaxed);
            if last != 0 && now_nanos.saturating_sub(last) < interval_nanos {
                return;
            }
            // CAS so only one racer per window emits the WARN.
            if self
                .last_warn_unix_nanos
                .compare_exchange(last, now_nanos, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                warn!(
                    target: "sbproxy_ai_shadow",
                    max_inflight = self.max_inflight,
                    max_memory_bytes = self.max_memory_bytes,
                    "shadow supervisor capacity exhausted; dropping shadow request (rate-limited)"
                );
                return;
            }
        }
    }
}

impl Default for ShadowSupervisor {
    fn default() -> Self {
        Self::new(DEFAULT_SHADOW_MAX_INFLIGHT)
    }
}

/// RAII guard that decrements the in-flight gauge when dropped.
struct ShadowInflightGuard;

impl ShadowInflightGuard {
    fn enter() -> Self {
        ai_metrics::inc_shadow_inflight();
        Self
    }
}

impl Drop for ShadowInflightGuard {
    fn drop(&mut self) {
        ai_metrics::dec_shadow_inflight();
    }
}

/// Result of trying to enqueue one configured shadow request.
///
/// This vocabulary is deliberately closed so callers can make
/// deterministic assertions without parsing logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowDispatchOutcome {
    /// The handler has no shadow block.
    NotConfigured,
    /// The request surface is outside the v1 chat-evaluation allowlist.
    UnsupportedSurface,
    /// Streaming shadowing is intentionally unsupported.
    StreamingSkipped,
    /// The configured probabilistic sampler did not select this request.
    SampledOut,
    /// The named shadow provider was absent from the handler provider list.
    ProviderNotFound,
    /// Credential-scoped provider policy disallowed the shadow provider.
    ProviderNotAllowed,
    /// Prompt-training opt-out disallowed the configured shadow provider.
    PromptTrainingDisallowed,
    /// Purpose-scoped egress is active and shadow transport cannot honor it.
    EgressDenied,
    /// The bounded shadow supervisor had no free slot.
    Saturated,
    /// The shadow task was admitted and spawned.
    Spawned,
}

/// Request-scoped usage attribution copied into a completed shadow event.
///
/// The event and sinks are owned by the background task, keeping
/// shadow accounting separate from the primary budget and governance
/// path. Recording is implemented alongside the usage-sink wiring.
#[derive(Debug, Clone)]
pub struct ShadowUsageRecord {
    event: LlmUsageEvent,
    sinks: Vec<Arc<dyn UsageSink>>,
}

#[derive(Debug, Clone, Copy)]
enum ShadowAttribution {
    Shadow,
}

impl ShadowAttribution {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
        }
    }
}

impl ShadowUsageRecord {
    /// Build shadow accounting from the request's governed identity.
    pub fn new(mut event: LlmUsageEvent, sinks: Vec<Arc<dyn UsageSink>>) -> Self {
        event.provider.clear();
        event.model.clear();
        event.prompt_tokens = 0;
        event.completion_tokens = 0;
        event.total_tokens = 0;
        event.cost_usd = 0.0;
        event.latency_ms = 0;
        event.status = 0;
        // Never derive the ledger dedup key from a caller-controlled
        // correlation header. A different primary request could otherwise
        // deliberately choose that derived value and suppress this event.
        //
        // The primary's id is still worth carrying, as data: `shadow_of`
        // is what lets a report put the primary row and its N target
        // rows side by side. It is not the key, and nothing derives the
        // key from it.
        //
        // The key itself is minted in `record`, once per target, not
        // here. This record is cloned per target, so minting here would
        // give every target row the same id and collapse N rows to one
        // on ledger replay.
        event.shadow_of = event.request_id.take();
        event.request_id = None;
        event.tag = Some(ShadowAttribution::Shadow.as_str().to_string());
        event.engine_version = None;
        // WOR-2223: a shadow call is an extra evaluation copy, not the
        // caller's completion, so it belongs to neither serving lane. Left
        // in place, the primary's lane fields would make the value report
        // count a second completion the operator never asked for: a local
        // saving if the primary was served locally, a cloud spill if it
        // was not.
        event.logical_model = None;
        event.served_model = None;
        Self { event, sinks }
    }

    fn record(mut self, provider: String, model: String, result: ShadowCallResult) {
        // Minted per call, so each target's row is a distinct ledger
        // entry. See the note in `new`.
        self.event.request_id = Some(format!("{:032x}:shadow", rand::random::<u128>()));
        let usage = crate::budget::AiUsage::Tokens {
            input: result.prompt_tokens,
            output: result.completion_tokens,
            cached_input: 0,
            cache_creation: 0,
        };
        self.event.provider = provider;
        self.event.model = model;
        self.event.prompt_tokens = result.prompt_tokens;
        self.event.completion_tokens = result.completion_tokens;
        self.event.total_tokens = result
            .prompt_tokens
            .saturating_add(result.completion_tokens);
        self.event.cost_usd = crate::budget::estimate_cost_for_usage(&self.event.model, &usage);
        self.event.latency_ms = result.latency_ms;
        self.event.status = result.status;
        self.event.finish_reason = result.finish_reason;
        for sink in &self.sinks {
            sink.record(&self.event);
        }
    }
}

#[derive(Debug, Clone)]
struct ShadowCallResult {
    status: u16,
    latency_ms: u64,
    prompt_tokens: u64,
    completion_tokens: u64,
    /// The target's terminal `finish_reason`, already parsed by
    /// [`parse_shadow_metadata`] for the log line and previously
    /// discarded. It is the cheapest disagreement signal there is: a
    /// target that answered `length` where the primary answered `stop`
    /// truncated, and no amount of cost comparison says that.
    finish_reason: Option<String>,
}

struct PreparedShadowRequest {
    permit: ShadowPermit,
    http: reqwest::Client,
    /// WOR-2648: a shadow copy is a real, billable upstream call, so a
    /// SigV4 provider's shadow leg is signed exactly like its primary.
    /// It reaches AWS as a genuine `InvokeModel` and appears in
    /// CloudTrail as one; `x-sbproxy-shadow: 1` marks it on the wire.
    signers: Arc<SignerCache>,
    provider: ProviderConfig,
    path: String,
    body: serde_json::Value,
    http_timeout: Duration,
    task_timeout: Duration,
    task_timeout_ms: u64,
    usage_provider: String,
    usage_model: String,
    reasoning_outcome: &'static str,
    usage: Option<ShadowUsageRecord>,
    quota_attempt: Option<crate::quota_pool::QuotaPoolAttemptGuard>,
}

/// HTTP client that forwards AI requests to upstream providers.
pub struct AiClient {
    http: reqwest::Client,
    shadow_supervisor: Arc<ShadowSupervisor>,
    /// Optional purpose-scoped egress authorizer. `None` preserves
    /// legacy ungated provider calls (omitted `proxy.egress` config).
    egress: Option<EgressAuthorizer>,
    /// Per-provider outbound request signers, built on first use.
    signers: Arc<SignerCache>,
}

impl AiClient {
    /// Create a new AI client with a shared reqwest::Client and a
    /// default-sized shadow supervisor (`DEFAULT_SHADOW_MAX_INFLIGHT`
    /// in-flight slots).
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                // WOR-2165: redirects are followed by `send_governed`,
                // which re-authorizes each hop. Letting the client
                // follow them would carry the provider credential to a
                // host no gate ever saw.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("AI HTTP client builder failed; cannot enforce the request timeout"),
            shadow_supervisor: Arc::new(ShadowSupervisor::default()),
            egress: None,
            signers: Arc::new(SignerCache::default()),
        }
    }

    /// Attach a purpose-scoped egress authorizer. When set, every
    /// provider URL is authorized for [`EgressPurpose::AiProvider`]
    /// before any I/O (fail closed).
    pub fn with_egress(mut self, authorizer: EgressAuthorizer) -> Self {
        self.egress = Some(authorizer);
        self
    }

    /// Create a new AI client with a custom shadow supervisor. Used
    /// by unit tests that need to drive overflow / timeout behavior
    /// at controlled queue depths.
    pub fn with_shadow_supervisor(supervisor: Arc<ShadowSupervisor>) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                // WOR-2165: redirects are followed by `send_governed`,
                // which re-authorizes each hop. Letting the client
                // follow them would carry the provider credential to a
                // host no gate ever saw.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("AI HTTP client builder failed; cannot enforce the request timeout"),
            shadow_supervisor: supervisor,
            egress: None,
            signers: Arc::new(SignerCache::default()),
        }
    }

    /// Authorize `url` for AI provider egress when an authorizer is
    /// configured. Returns the closed [`EgressDenied`] vocabulary.
    pub fn authorize_provider_url(
        &self,
        url: &str,
        resolver: &dyn HostResolver,
    ) -> Result<(), EgressDenied> {
        let Some(auth) = &self.egress else {
            return Ok(());
        };
        auth.authorize(EgressPurpose::AiProvider, url, resolver)
            .map(|_| ())
    }

    /// Gate one provider URL before any I/O, attributing a refusal to
    /// `provider_name`.
    ///
    /// WOR-2165: the resolver is [`CachedSystemResolver`], a live
    /// answer, not the fixed synthetic pin this gate used to run
    /// against. The synthetic address was always public and always
    /// resolvable, so `allow_private` and `DnsResolutionFailed` could
    /// not fire and the check asserted only what the URL string said.
    /// Nothing resolves when no authorizer is attached, which is every
    /// production call site today, so the live resolver costs nothing
    /// until an operator turns egress on.
    fn gate_provider_url(&self, url: &str, provider_name: &str) -> Result<()> {
        use sbproxy_security::egress::{record_egress_seen, EgressSightingStatus};
        // WOR-2476: every provider endpoint this client touches lands in
        // the egress inventory, whether an authorizer is configured or
        // not. "Ungated" is the honest status when no authorizer is
        // attached; without it the report would claim "allowed" for
        // endpoints nothing ever approved.
        if self.egress.is_none() {
            record_egress_seen(
                EgressPurpose::AiProvider,
                url,
                provider_name,
                EgressSightingStatus::Ungated,
                None,
            );
            return Ok(());
        }
        match self.authorize_provider_url(url, &CachedSystemResolver) {
            Ok(()) => {
                record_egress_seen(
                    EgressPurpose::AiProvider,
                    url,
                    provider_name,
                    EgressSightingStatus::Allowed,
                    None,
                );
                Ok(())
            }
            Err(e) => {
                record_egress_seen(
                    EgressPurpose::AiProvider,
                    url,
                    provider_name,
                    EgressSightingStatus::Denied,
                    Some(e),
                );
                record_egress_refused(EgressPurpose::AiProvider, e, "unset", provider_name);
                Err(anyhow::anyhow!("egress denied: {e:?}"))
            }
        }
    }

    /// Send one already-built provider request under the governed
    /// redirect contract (WOR-2165).
    /// Boxed body. Every await on the AI request path is inlined into
    /// one state machine on a Pingora worker thread, whose stack is the
    /// std default of 2MB, and that machine was already within a few
    /// hundred kilobytes of it. Adding the signer lookup and the signed
    /// hop loop pushed it over, so an AI request aborted the worker
    /// thread with a stack overflow before it reached a provider.
    /// Boxing here puts this subtree on the heap and takes the frame
    /// back under the limit. Unit tests never caught it because they
    /// call this off a test runtime with a much larger stack; only the
    /// e2e harness runs the real Pingora thread.
    async fn send_provider_request(
        &self,
        mut request: reqwest::Request,
        provider: &ProviderConfig,
    ) -> Result<reqwest::Response> {
        Box::pin(async move {
            apply_provider_timeout(&mut request, provider);
            let signer = self.signers.signer_for(provider).await?;
            send_governed(
                &self.http,
                self.egress.as_ref(),
                &provider.name,
                as_signer(&signer),
                request,
            )
            .await
        })
        .await
    }

    /// Borrow the shadow supervisor (test + diagnostic accessor).
    pub fn shadow_supervisor(&self) -> &Arc<ShadowSupervisor> {
        &self.shadow_supervisor
    }

    /// Best-effort, non-blocking admission for one non-streaming
    /// shadow copy. All policy and capacity failures suppress only the
    /// shadow copy; they never reject or await the primary request.
    // Keep policy and accounting inputs explicit at this one dispatch boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn try_spawn_shadow(
        &self,
        config: &AiHandlerConfig,
        path: &str,
        body: &serde_json::Value,
        is_stream: bool,
        allowed_providers: &[String],
        blocked_providers: &[String],
        disallow_prompt_training: bool,
        usage: Option<ShadowUsageRecord>,
    ) -> Vec<ShadowDispatchOutcome> {
        match self.prepare_shadows(
            config,
            path,
            body,
            is_stream,
            allowed_providers,
            blocked_providers,
            disallow_prompt_training,
            usage,
            None,
        ) {
            Ok(prepared) => prepared
                .into_iter()
                .map(|target| match target {
                    Ok(prepared) => Self::spawn_prepared_shadow(prepared),
                    Err(outcome) => outcome,
                })
                .collect(),
            Err(outcome) => vec![outcome],
        }
    }

    /// Apply every ordinary shadow gate, reserve one quota unit, then spawn.
    ///
    /// Sampled-out, unsupported, policy-blocked, egress-blocked, and saturated
    /// copies return without touching the quota pool. A closed quota error is
    /// returned before a background provider call starts. The reservation
    /// settles inside the task immediately before transport send.
    #[allow(clippy::too_many_arguments)]
    pub async fn try_spawn_shadow_with_quota(
        &self,
        config: &AiHandlerConfig,
        path: &str,
        body: &serde_json::Value,
        is_stream: bool,
        allowed_providers: &[String],
        blocked_providers: &[String],
        disallow_prompt_training: bool,
        usage: Option<ShadowUsageRecord>,
        quota: &crate::quota_pool::QuotaPoolAdmission,
        quota_reservation_prefix: &str,
    ) -> std::result::Result<Vec<ShadowDispatchOutcome>, crate::quota_pool::PoolError> {
        let targets = match self.prepare_shadows(
            config,
            path,
            body,
            is_stream,
            allowed_providers,
            blocked_providers,
            disallow_prompt_training,
            usage,
            None,
        ) {
            Ok(targets) => targets,
            Err(outcome) => return Ok(vec![outcome]),
        };
        let mut outcomes = Vec::with_capacity(targets.len());
        for (index, target) in targets.into_iter().enumerate() {
            let mut prepared = match target {
                Ok(prepared) => prepared,
                Err(outcome) => {
                    outcomes.push(outcome);
                    continue;
                }
            };
            // One reservation per target, distinctly named: the pool
            // dedups by reservation id, so reusing the request's single
            // `:shadow` id across N targets would reserve one unit for
            // N billable calls.
            prepared.quota_attempt = Some(
                quota
                    .reserve_attempt(&format!("{quota_reservation_prefix}:shadow:{index}"))
                    .await?,
            );
            outcomes.push(Self::spawn_prepared_shadow(prepared));
        }
        Ok(outcomes)
    }

    /// Queue quota admission and shadow transport without delaying the caller.
    ///
    /// All synchronous shadow gates and bounded supervisor admission complete
    /// before this returns. The detached task reserves quota, then launches the
    /// provider call, which settles immediately before send. A closed quota
    /// failure suppresses the optional copy.
    #[allow(clippy::too_many_arguments)]
    pub fn try_spawn_shadow_with_quota_detached(
        &self,
        config: &AiHandlerConfig,
        path: &str,
        body: &serde_json::Value,
        is_stream: bool,
        allowed_providers: &[String],
        blocked_providers: &[String],
        disallow_prompt_training: bool,
        usage: Option<ShadowUsageRecord>,
        quota: crate::quota_pool::QuotaPoolAdmission,
        quota_reservation_prefix: &str,
    ) -> Vec<ShadowDispatchOutcome> {
        self.try_spawn_shadow_with_quota_detached_impl(
            config,
            path,
            body,
            is_stream,
            allowed_providers,
            blocked_providers,
            disallow_prompt_training,
            usage,
            quota,
            quota_reservation_prefix,
            None,
        )
    }

    /// Queue a governed shadow while preserving safety facts captured before
    /// lossy request transformations.
    #[allow(clippy::too_many_arguments)]
    pub fn try_spawn_shadow_with_quota_detached_with_reasoning_eligibility(
        &self,
        config: &AiHandlerConfig,
        path: &str,
        body: &serde_json::Value,
        is_stream: bool,
        allowed_providers: &[String],
        blocked_providers: &[String],
        disallow_prompt_training: bool,
        usage: Option<ShadowUsageRecord>,
        quota: crate::quota_pool::QuotaPoolAdmission,
        quota_reservation_prefix: &str,
        reasoning_eligibility: crate::reasoning::ReasoningEligibility,
    ) -> Vec<ShadowDispatchOutcome> {
        self.try_spawn_shadow_with_quota_detached_impl(
            config,
            path,
            body,
            is_stream,
            allowed_providers,
            blocked_providers,
            disallow_prompt_training,
            usage,
            quota,
            quota_reservation_prefix,
            Some(reasoning_eligibility),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_spawn_shadow_with_quota_detached_impl(
        &self,
        config: &AiHandlerConfig,
        path: &str,
        body: &serde_json::Value,
        is_stream: bool,
        allowed_providers: &[String],
        blocked_providers: &[String],
        disallow_prompt_training: bool,
        usage: Option<ShadowUsageRecord>,
        quota: crate::quota_pool::QuotaPoolAdmission,
        quota_reservation_prefix: &str,
        reasoning_eligibility: Option<crate::reasoning::ReasoningEligibility>,
    ) -> Vec<ShadowDispatchOutcome> {
        let targets = match self.prepare_shadows(
            config,
            path,
            body,
            is_stream,
            allowed_providers,
            blocked_providers,
            disallow_prompt_training,
            usage,
            reasoning_eligibility,
        ) {
            Ok(targets) => targets,
            Err(outcome) => return vec![outcome],
        };
        let mut outcomes = Vec::with_capacity(targets.len());
        for (index, target) in targets.into_iter().enumerate() {
            let mut prepared = match target {
                Ok(prepared) => prepared,
                Err(outcome) => {
                    outcomes.push(outcome);
                    continue;
                }
            };
            let reservation_id = format!("{quota_reservation_prefix}:shadow:{index}");
            let quota = quota.clone();
            tokio::spawn(async move {
                match quota.reserve_attempt(&reservation_id).await {
                    Ok(attempt) => {
                        prepared.quota_attempt = Some(attempt);
                        Self::spawn_prepared_shadow(prepared);
                    }
                    Err(error) => {
                        warn!(
                            error = %error,
                            "quota admission suppressed optional shadow request"
                        );
                    }
                }
            });
            outcomes.push(ShadowDispatchOutcome::Spawned);
        }
        outcomes
    }

    /// Apply the request-level shadow gates once, then prepare one
    /// request per configured target.
    ///
    /// `Err` carries a refusal that is true of the whole request (no
    /// shadow block, an ineligible surface, a stream); those never
    /// reach a target. `Ok` carries one entry per target, in config
    /// order, each already resolved to either a prepared request or
    /// its own per-target refusal.
    ///
    /// Sampling draws **once** here and every target compares against
    /// that draw. Independent per-target draws would give disjoint
    /// populations, and two targets whose measured cost and latency
    /// come from different requests are not comparable, which is the
    /// entire point of running two.
    #[allow(clippy::too_many_arguments)]
    fn prepare_shadows(
        &self,
        config: &AiHandlerConfig,
        path: &str,
        body: &serde_json::Value,
        is_stream: bool,
        allowed_providers: &[String],
        blocked_providers: &[String],
        disallow_prompt_training: bool,
        usage: Option<ShadowUsageRecord>,
        reasoning_eligibility: Option<crate::reasoning::ReasoningEligibility>,
    ) -> std::result::Result<
        Vec<std::result::Result<PreparedShadowRequest, ShadowDispatchOutcome>>,
        ShadowDispatchOutcome,
    > {
        let Some(shadow_cfg) = config.shadow.as_ref() else {
            return Err(ShadowDispatchOutcome::NotConfigured);
        };
        if !crate::handler::classify_surface("POST", path).supports_shadow_eval() {
            return Err(ShadowDispatchOutcome::UnsupportedSurface);
        }
        if is_stream {
            ai_metrics::record_shadow_dropped(ai_metrics::ShadowDropReason::Streaming);
            return Err(ShadowDispatchOutcome::StreamingSkipped);
        }
        let draw: f32 = rand::random();
        Ok(shadow_cfg
            .targets
            .iter()
            .map(|target| {
                self.prepare_shadow_target(
                    config,
                    target,
                    draw,
                    path,
                    body,
                    allowed_providers,
                    blocked_providers,
                    disallow_prompt_training,
                    usage.clone(),
                    reasoning_eligibility,
                )
            })
            .collect())
    }

    /// Everything that is decided per target: sampling against the
    /// request's one draw, provider resolution and policy, reasoning
    /// policy, and admission.
    ///
    /// Admission runs once per target, so N targets take N slots out
    /// of the one process-wide task and memory ceiling rather than
    /// multiplying it by the length of the config.
    #[allow(clippy::too_many_arguments)]
    fn prepare_shadow_target(
        &self,
        config: &AiHandlerConfig,
        shadow_cfg: &crate::handler::AiShadowTarget,
        draw: f32,
        path: &str,
        body: &serde_json::Value,
        allowed_providers: &[String],
        blocked_providers: &[String],
        disallow_prompt_training: bool,
        usage: Option<ShadowUsageRecord>,
        reasoning_eligibility: Option<crate::reasoning::ReasoningEligibility>,
    ) -> std::result::Result<PreparedShadowRequest, ShadowDispatchOutcome> {
        let sampled = if shadow_cfg.sample_rate >= 1.0 {
            true
        } else if shadow_cfg.sample_rate <= 0.0 {
            false
        } else {
            draw < shadow_cfg.sample_rate
        };
        if !sampled {
            return Err(ShadowDispatchOutcome::SampledOut);
        }

        let Some(shadow_provider) = config
            .providers
            .iter()
            .find(|provider| provider.name == shadow_cfg.provider)
        else {
            ai_metrics::record_shadow_dropped(ai_metrics::ShadowDropReason::ProviderNotFound);
            warn!(
                provider = %shadow_cfg.provider,
                "shadow target not found in providers list"
            );
            return Err(ShadowDispatchOutcome::ProviderNotFound);
        };
        let shadow_provider = shadow_provider.clone();

        if !provider_allowed_by_policy(
            shadow_provider.name.as_str(),
            allowed_providers,
            blocked_providers,
        ) {
            ai_metrics::record_shadow_dropped(ai_metrics::ShadowDropReason::ProviderNotAllowed);
            debug!(
                provider = %shadow_provider.name,
                "credential provider policy suppressed shadow request"
            );
            return Err(ShadowDispatchOutcome::ProviderNotAllowed);
        }

        if disallow_prompt_training && !shadow_provider.no_prompt_training {
            ai_metrics::record_shadow_dropped(
                ai_metrics::ShadowDropReason::PromptTrainingDisallowed,
            );
            debug!(
                provider = %shadow_provider.name,
                "prompt-training opt-out suppressed shadow request"
            );
            return Err(ShadowDispatchOutcome::PromptTrainingDisallowed);
        }

        // The shadow transport uses reqwest directly and cannot yet consume
        // the egress authorizer's DNS pins or re-authorize redirect targets.
        // Fail closed whenever purpose-scoped egress is active instead of
        // pretending that an initial URL check secures the whole call.
        if self.egress.is_some() {
            ai_metrics::record_shadow_dropped(ai_metrics::ShadowDropReason::EgressDenied);
            warn!(
                provider = %shadow_provider.name,
                "egress-authorized shadow transport is unavailable; suppressing shadow request"
            );
            return Err(ShadowDispatchOutcome::EgressDenied);
        }

        let mut body_owned = if let Some(model) = shadow_cfg.model.as_ref() {
            let mut body = body.clone();
            if let Some(object) = body.as_object_mut() {
                object.insert(
                    "model".to_string(),
                    serde_json::Value::String(model.clone()),
                );
            }
            body
        } else {
            body.clone()
        };
        if let Some(model) = body_owned
            .get("model")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
        {
            if let Some(object) = body_owned.as_object_mut() {
                object.insert(
                    "model".to_string(),
                    serde_json::Value::String(shadow_provider.map_model(&model)),
                );
            }
        }
        let reasoning_model = body_owned
            .get("model")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        let reasoning = match reasoning_eligibility {
            Some(eligibility) => crate::reasoning::apply_reasoning_policy_with_eligibility(
                config.reasoning,
                &shadow_provider,
                &reasoning_model,
                &mut body_owned,
                eligibility,
            ),
            None => crate::reasoning::apply_reasoning_policy(
                config.reasoning,
                &shadow_provider,
                &reasoning_model,
                &mut body_owned,
            ),
        };
        let request_bytes = serialized_json_len(&body_owned);
        let Some(permit) = self.shadow_supervisor.try_admit_request(request_bytes) else {
            return Err(ShadowDispatchOutcome::Saturated);
        };
        let http_timeout_ms = shadow_cfg.timeout_ms;
        let task_timeout_ms = shadow_cfg.task_timeout_ms;
        let http_timeout = Duration::from_millis(http_timeout_ms);
        let task_timeout = Duration::from_millis(task_timeout_ms);
        let usage_provider = shadow_provider.name.as_str().to_string();
        let usage_model = body_owned
            .get("model")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        Ok(PreparedShadowRequest {
            permit,
            http: self.http.clone(),
            signers: self.signers.clone(),
            provider: shadow_provider,
            path: path.to_string(),
            body: body_owned,
            http_timeout,
            task_timeout,
            task_timeout_ms,
            usage_provider,
            usage_model,
            reasoning_outcome: reasoning.outcome_label(),
            usage,
            quota_attempt: None,
        })
    }

    fn spawn_prepared_shadow(prepared: PreparedShadowRequest) -> ShadowDispatchOutcome {
        let PreparedShadowRequest {
            permit,
            http,
            signers,
            provider,
            path,
            body,
            http_timeout,
            task_timeout,
            task_timeout_ms,
            usage_provider,
            usage_model,
            reasoning_outcome,
            usage,
            quota_attempt,
        } = prepared;
        tokio::spawn(async move {
            let _permit = permit;
            let _gauge = ShadowInflightGuard::enter();
            ai_metrics::record_reasoning_policy_attempt(&provider.name, reasoning_outcome);
            match tokio::time::timeout(
                task_timeout,
                run_shadow_request(
                    http,
                    signers,
                    provider,
                    path,
                    body,
                    http_timeout,
                    quota_attempt,
                ),
            )
            .await
            {
                Ok(result) => {
                    // Recorded here, beside the usage row, rather than
                    // inside `run_shadow_request`: the timeout arm below
                    // never reaches that function, and a target whose
                    // calls all time out is exactly the one an operator
                    // needs to see on this counter.
                    ai_metrics::record_shadow_call(
                        &usage_provider,
                        result.status,
                        result.finish_reason.as_deref(),
                        result.latency_ms as f64 / 1000.0,
                    );
                    if let Some(usage) = usage {
                        usage.record(usage_provider, usage_model, result);
                    }
                }
                Err(_) => {
                    ai_metrics::record_shadow_timeout();
                    ai_metrics::record_shadow_call(
                        &usage_provider,
                        504,
                        None,
                        task_timeout_ms as f64 / 1000.0,
                    );
                    if let Some(usage) = usage {
                        usage.record(
                            usage_provider,
                            usage_model,
                            ShadowCallResult {
                                status: 504,
                                latency_ms: task_timeout_ms,
                                prompt_tokens: 0,
                                completion_tokens: 0,
                                finish_reason: None,
                            },
                        );
                    }
                    warn!(
                        target: "sbproxy_ai_shadow",
                        timeout_ms = task_timeout_ms,
                        "shadow request exceeded supervisor timeout; dropping"
                    );
                }
            }
        });
        ShadowDispatchOutcome::Spawned
    }

    /// Execute one bounded chat-completion call against exactly one provider.
    ///
    /// This is the below-pipeline boundary for internal context summaries. It
    /// deliberately has no router, handler configuration, semantic cache,
    /// shadow configuration, or compression callback, so an internal request
    /// cannot recursively enter ordinary AI dispatch. Credential governance
    /// and budget admission remain the responsibility of the request-scoped
    /// runtime adapter before this method is called.
    pub async fn summarize_internal(
        &self,
        provider: &ProviderConfig,
        model: &str,
        messages: &[serde_json::Value],
        target_summary_tokens: u64,
        timeout: Duration,
    ) -> Result<SummarizationOutput, SummarizerError> {
        let mapped_model = provider.map_model(model);
        let body = serde_json::json!({
            "model": mapped_model,
            "messages": messages,
            "max_tokens": target_summary_tokens,
            "stream": false,
        });
        let response_limit = target_summary_tokens
            .saturating_mul(32)
            .clamp(64 * 1024, 1024 * 1024) as usize;
        let operation = async {
            let mut response = self
                .forward_request(provider, "/v1/chat/completions", &body)
                .await
                .map_err(|_| SummarizerError::Provider)?;
            if !response.status().is_success() {
                return Err(SummarizerError::Provider);
            }

            let mut raw = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| SummarizerError::Provider)?
            {
                if raw.len().saturating_add(chunk.len()) > response_limit {
                    return Err(SummarizerError::InvalidOutput);
                }
                raw.extend_from_slice(&chunk);
            }
            let translated = translators::translate_response_bytes(provider_format(provider), &raw);
            parse_internal_summary(model, messages, &translated)
        };

        tokio::time::timeout(timeout, operation)
            .await
            .map_err(|_| SummarizerError::Timeout)?
    }

    /// Forward a chat completions request to the selected provider.
    ///
    /// Selects a provider via the router, maps the model name if configured,
    /// and sends the request with the correct auth headers.
    ///
    /// When the response status is 5xx, a transport-level error
    /// occurs, or the request times out, the failure is recorded
    /// against the provider's circuit breaker and outlier detector.
    /// Up to `max_attempts` (default 1) total tries fan across
    /// different providers; subsequent attempts skip providers the
    /// resilience layer has already ejected.
    pub async fn forward_chat_request(
        &self,
        config: &AiHandlerConfig,
        router: &Router,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response> {
        let is_stream = body
            .get("stream")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let _ = self.try_spawn_shadow(config, path, body, is_stream, &[], &[], false, None);

        // Race strategy: fan out to every eligible provider in
        // parallel, return the first 2xx, cancel the losers. The
        // resilience layer's record_provider_* signals still apply
        // to each leg so persistently slow providers eventually get
        // ejected from the eligible set.
        if router.is_race() {
            return self.forward_race(config, router, path, body).await;
        }

        let max_attempts = config.resilience_max_attempts();
        let mut last_err: Option<anyhow::Error> = None;
        let mut attempted_indices: Vec<usize> = Vec::with_capacity(max_attempts);

        for _ in 0..max_attempts {
            let provider_idx = router.select(&config.providers).ok_or_else(|| {
                last_err
                    .as_ref()
                    .map(|e| anyhow::anyhow!("all providers failed: {e}"))
                    .unwrap_or_else(|| anyhow::anyhow!("no enabled providers available"))
            })?;

            // If the resilience layer happens to keep selecting the
            // same provider (small pool, all others ejected) bail out
            // rather than retry the same dead provider repeatedly.
            if attempted_indices.contains(&provider_idx) && !attempted_indices.is_empty() {
                break;
            }
            attempted_indices.push(provider_idx);
            let provider = &config.providers[provider_idx];

            let per_provider_attempts = provider_retry_attempts(provider);
            for provider_attempt in 0..per_provider_attempts {
                let (attempt_body, reasoning_outcome) =
                    prepare_provider_attempt_body(config, provider, body);
                ai_metrics::record_reasoning_policy_attempt(&provider.name, reasoning_outcome);
                match self.forward_request(provider, path, &attempt_body).await {
                    Ok(resp) if resp.status().is_server_error() => {
                        let status = resp.status();
                        last_err = Some(anyhow::anyhow!(
                            "provider {} returned {}",
                            provider.name,
                            status
                        ));
                    }
                    Ok(resp) => {
                        router.record_provider_success(provider_idx, provider.name.as_str());
                        return Ok(resp);
                    }
                    Err(e) => {
                        last_err = Some(e);
                    }
                }

                if provider_attempt + 1 < per_provider_attempts {
                    let delay = provider_retry_backoff(provider_attempt + 1);
                    debug!(
                        provider = %provider.name,
                        attempt = provider_attempt + 1,
                        delay_ms = delay.as_millis(),
                        "AI provider retry backoff"
                    );
                    tokio::time::sleep(delay).await;
                }
            }

            router.record_provider_failure(provider_idx, provider.name.as_str());
            continue;
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no providers attempted")))
    }

    /// Forward a request to a specific provider.
    ///
    /// Builds the full URL from the provider's base URL + path,
    /// sets the auth header, and sends the JSON body. When the
    /// provider speaks a non-OpenAI wire format (Anthropic Messages
    /// API today), the body and path are translated before sending.
    /// Response bodies are returned untranslated; callers route them
    /// through `translators::translate_response_bytes` after reading.
    pub async fn forward_request(
        &self,
        provider: &ProviderConfig,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response> {
        self.forward_request_impl(provider, path, body, None).await
    }

    /// Forward a request after committing its already-reserved quota attempt.
    ///
    /// URL, egress, headers, translation, and the request builder are all
    /// prepared before quota settles immediately ahead of transport send.
    pub async fn forward_request_with_quota(
        &self,
        provider: &ProviderConfig,
        path: &str,
        body: &serde_json::Value,
        quota_attempt: crate::quota_pool::QuotaPoolAttemptGuard,
    ) -> Result<reqwest::Response> {
        self.forward_request_impl(provider, path, body, Some(quota_attempt))
            .await
    }

    async fn forward_request_impl(
        &self,
        provider: &ProviderConfig,
        path: &str,
        body: &serde_json::Value,
        quota_attempt: Option<crate::quota_pool::QuotaPoolAttemptGuard>,
    ) -> Result<reqwest::Response> {
        let format = provider_format(provider);
        let (translated_body, translated_path) =
            translators::translate_request(format, path, body, translate_options(provider));
        // Passthrough formats return `None`; send the original borrowed
        // body without a clone (WOR-1701).
        let send_body = translated_body.as_ref().unwrap_or(body);

        let base_url_owned = provider.effective_base_url();
        let base_url = base_url_owned.trim_end_matches('/');
        let url_string = build_url(base_url, &translated_path);
        self.gate_provider_url(&url_string, &provider.name)?;
        let url = reqwest::Url::parse(&url_string)?;

        let auth = provider_auth_header(provider)?;

        debug!(
            url = %url,
            provider = %provider.name,
            format = ?format,
            signed = provider.aws_sigv4.is_some(),
            "forwarding AI request to provider"
        );

        let mut req = self
            .http
            .post(url)
            .header("content-type", "application/json");
        if let Some((auth_header, auth_value)) = auth {
            req = req.header(auth_header, auth_value);
        }

        // Anthropic requires an api-version header; default the most
        // widely deployed value when the caller didn't set one.
        if matches!(format, ProviderFormat::Anthropic) {
            req = req.header("anthropic-version", "2023-06-01");
        }

        let req = req.json(send_body).build()?;
        commit_quota_attempt(quota_attempt).await?;
        let resp = self.send_provider_request(req, provider).await?;

        Ok(resp)
    }

    /// Forward a GET request to a specific provider (for /v1/models).
    pub async fn forward_get_request(
        &self,
        provider: &ProviderConfig,
        path: &str,
    ) -> Result<reqwest::Response> {
        self.forward_get_request_impl(provider, path, None).await
    }

    /// Forward a GET request after committing its reserved quota attempt.
    pub async fn forward_get_request_with_quota(
        &self,
        provider: &ProviderConfig,
        path: &str,
        quota_attempt: crate::quota_pool::QuotaPoolAttemptGuard,
    ) -> Result<reqwest::Response> {
        self.forward_get_request_impl(provider, path, Some(quota_attempt))
            .await
    }

    async fn forward_get_request_impl(
        &self,
        provider: &ProviderConfig,
        path: &str,
        quota_attempt: Option<crate::quota_pool::QuotaPoolAttemptGuard>,
    ) -> Result<reqwest::Response> {
        let base_url_owned = provider.effective_base_url();
        let base_url = base_url_owned.trim_end_matches('/');
        let url_string = build_url(base_url, path);
        self.gate_provider_url(&url_string, &provider.name)?;
        let url = reqwest::Url::parse(&url_string)?;

        let auth = provider_auth_header(provider)?;

        debug!(
            url = %url,
            provider = %provider.name,
            "forwarding AI GET request to provider"
        );

        let mut req = self.http.get(url);
        if let Some((auth_header, auth_value)) = auth {
            req = req.header(auth_header, auth_value);
        }
        let req = req.build()?;
        commit_quota_attempt(quota_attempt).await?;
        let resp = self.send_provider_request(req, provider).await?;

        Ok(resp)
    }

    /// Forward a request to a specific provider using the caller's HTTP
    /// method. Supports GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS.
    ///
    /// This is the method-aware analogue of [`AiClient::forward_request`]
    /// (POST only) and [`AiClient::forward_get_request`] (GET only). It
    /// supports the non-chat OpenAI surfaces (assistants, threads,
    /// batches, files, fine-tuning) where the API uses DELETE and other
    /// methods. The body is sent only when present; DELETE typically
    /// has no body.
    ///
    /// Translation through `translators::translate_request` is applied
    /// when a body is present and the provider speaks a non-OpenAI
    /// wire format; method-only requests (DELETE without body) are
    /// not translated.
    pub async fn forward_with_method(
        &self,
        provider: &ProviderConfig,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<reqwest::Response> {
        self.forward_with_method_impl(provider, method, path, body, None)
            .await
    }

    /// Forward with an arbitrary method after committing reserved quota.
    pub async fn forward_with_method_and_quota(
        &self,
        provider: &ProviderConfig,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
        quota_attempt: crate::quota_pool::QuotaPoolAttemptGuard,
    ) -> Result<reqwest::Response> {
        self.forward_with_method_impl(provider, method, path, body, Some(quota_attempt))
            .await
    }

    async fn forward_with_method_impl(
        &self,
        provider: &ProviderConfig,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
        quota_attempt: Option<crate::quota_pool::QuotaPoolAttemptGuard>,
    ) -> Result<reqwest::Response> {
        let format = provider_format(provider);

        // Translate body and path when the body is present and the
        // provider format diverges from OpenAI. Passthrough formats
        // return `None`, so `send_body` falls back to the original
        // borrowed body with no clone (WOR-1701).
        let (translated_body, translated_path) = match body {
            Some(b) => translators::translate_request(format, path, b, translate_options(provider)),
            None => (None, path.to_string()),
        };
        let send_body: Option<&serde_json::Value> = translated_body.as_ref().or(body);

        let base_url_owned = provider.effective_base_url();
        let base_url = base_url_owned.trim_end_matches('/');
        let url_string = build_url(base_url, &translated_path);
        self.gate_provider_url(&url_string, &provider.name)?;
        let url = reqwest::Url::parse(&url_string)?;

        let auth = provider_auth_header(provider)?;

        debug!(
            url = %url,
            method = %method,
            provider = %provider.name,
            format = ?format,
            "forwarding AI request to provider"
        );

        let reqwest_method = parse_http_method(method)?;

        let mut req = self.http.request(reqwest_method, url);
        if let Some((auth_header, auth_value)) = auth {
            req = req.header(auth_header, auth_value);
        }

        if matches!(format, ProviderFormat::Anthropic) {
            req = req.header("anthropic-version", "2023-06-01");
        }

        if let Some(sb) = send_body {
            req = req.header("content-type", "application/json").json(sb);
        }

        let req = req.build()?;
        commit_quota_attempt(quota_attempt).await?;
        let resp = self.send_provider_request(req, provider).await?;
        Ok(resp)
    }
}

fn parse_internal_summary(
    model: &str,
    input_messages: &[serde_json::Value],
    body: &[u8],
) -> Result<SummarizationOutput, SummarizerError> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| SummarizerError::InvalidOutput)?;
    let summary = value
        .get("choices")
        .and_then(serde_json::Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(serde_json::Value::as_str)
        .filter(|summary| !summary.trim().is_empty())
        .ok_or(SummarizerError::InvalidOutput)?
        .to_string();

    let usage = value.get("usage");
    let input_tokens = usage
        .and_then(|usage| usage.get("prompt_tokens"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| {
            crate::token_estimate::estimate_json_message_tokens(model, input_messages)
        });
    let output_tokens = usage
        .and_then(|usage| usage.get("completion_tokens"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| {
            crate::token_estimate::estimate_json_message_tokens(
                model,
                &[serde_json::json!({"role": "assistant", "content": summary})],
            )
        });

    Ok(SummarizationOutput {
        summary,
        input_tokens,
        output_tokens,
    })
}

impl AiClient {
    /// Forward a JSON request body byte-for-byte to a native
    /// upstream path, skipping the OpenAI Chat hub translation.
    ///
    /// Used by the native-format bypass: when the inbound client
    /// format equals the upstream provider's wire format, the gateway
    /// sends the inbound body directly to the upstream's native path
    /// rather than translating it through the hub and back. Adds the
    /// per-format request headers `forward_request` would normally
    /// add (today: `anthropic-version` for Anthropic upstreams).
    pub async fn forward_native_bypass(
        &self,
        provider: &ProviderConfig,
        method: &str,
        native_path: &str,
        body: bytes::Bytes,
    ) -> Result<reqwest::Response> {
        self.forward_native_bypass_impl(provider, method, native_path, body, None)
            .await
    }

    /// Forward a native-format body after committing reserved quota.
    pub async fn forward_native_bypass_with_quota(
        &self,
        provider: &ProviderConfig,
        method: &str,
        native_path: &str,
        body: bytes::Bytes,
        quota_attempt: crate::quota_pool::QuotaPoolAttemptGuard,
    ) -> Result<reqwest::Response> {
        self.forward_native_bypass_impl(provider, method, native_path, body, Some(quota_attempt))
            .await
    }

    async fn forward_native_bypass_impl(
        &self,
        provider: &ProviderConfig,
        method: &str,
        native_path: &str,
        body: bytes::Bytes,
        quota_attempt: Option<crate::quota_pool::QuotaPoolAttemptGuard>,
    ) -> Result<reqwest::Response> {
        let format = provider_format(provider);

        let base_url_owned = provider.effective_base_url();
        let base_url = base_url_owned.trim_end_matches('/');
        let url_string = build_url(base_url, native_path);
        self.gate_provider_url(&url_string, &provider.name)?;
        let url = reqwest::Url::parse(&url_string)?;
        let auth = provider_auth_header(provider)?;
        let reqwest_method = parse_http_method(method)?;

        debug!(
            url = %url,
            method = %method,
            provider = %provider.name,
            format = ?format,
            body_len = body.len(),
            "WOR-229 native bypass: forwarding inbound body to upstream native path"
        );

        let mut req = self
            .http
            .request(reqwest_method, url)
            .header("content-type", "application/json");
        if let Some((auth_header, auth_value)) = auth {
            req = req.header(auth_header, auth_value);
        }
        if matches!(format, ProviderFormat::Anthropic) {
            req = req.header("anthropic-version", "2023-06-01");
        }

        let req = req.body(body).build()?;
        commit_quota_attempt(quota_attempt).await?;
        let resp = self.send_provider_request(req, provider).await?;
        Ok(resp)
    }

    /// Forward a raw request body byte-for-byte with the caller's
    /// `Content-Type` preserved.
    ///
    /// Used for surfaces that the proxy must not parse or rewrite:
    /// `POST /v1/audio/transcriptions`, `POST /v1/images/edits`,
    /// `POST /v1/images/variations` (multipart bodies), and any
    /// inbound request with a non-JSON `Content-Type`. The body
    /// bytes are sent untranslated; provider-format translation
    /// applies only to JSON bodies routed through
    /// `forward_with_method` or `forward_request`.
    pub async fn forward_bytes(
        &self,
        provider: &ProviderConfig,
        method: &str,
        path: &str,
        body: bytes::Bytes,
        content_type: &str,
    ) -> Result<reqwest::Response> {
        self.forward_bytes_impl(provider, method, path, body, content_type, None)
            .await
    }

    /// Forward an opaque body after committing reserved quota.
    pub async fn forward_bytes_with_quota(
        &self,
        provider: &ProviderConfig,
        method: &str,
        path: &str,
        body: bytes::Bytes,
        content_type: &str,
        quota_attempt: crate::quota_pool::QuotaPoolAttemptGuard,
    ) -> Result<reqwest::Response> {
        self.forward_bytes_impl(
            provider,
            method,
            path,
            body,
            content_type,
            Some(quota_attempt),
        )
        .await
    }

    async fn forward_bytes_impl(
        &self,
        provider: &ProviderConfig,
        method: &str,
        path: &str,
        body: bytes::Bytes,
        content_type: &str,
        quota_attempt: Option<crate::quota_pool::QuotaPoolAttemptGuard>,
    ) -> Result<reqwest::Response> {
        let base_url_owned = provider.effective_base_url();
        let base_url = base_url_owned.trim_end_matches('/');
        let url_string = build_url(base_url, path);
        self.gate_provider_url(&url_string, &provider.name)?;
        let url = reqwest::Url::parse(&url_string)?;
        let auth = provider_auth_header(provider)?;
        let content_type_header = reqwest::header::HeaderValue::from_str(content_type)?;
        let reqwest_method = parse_http_method(method)?;

        debug!(
            url = %url,
            method = %method,
            provider = %provider.name,
            content_type = %content_type,
            body_len = body.len(),
            "forwarding AI raw-body request to provider"
        );

        let mut req = self
            .http
            .request(reqwest_method, url)
            .header("content-type", content_type_header);
        if let Some((auth_header, auth_value)) = auth {
            req = req.header(auth_header, auth_value);
        }
        let req = req.body(body).build()?;
        commit_quota_attempt(quota_attempt).await?;
        let resp = self.send_provider_request(req, provider).await?;
        Ok(resp)
    }
}

async fn commit_quota_attempt(
    quota_attempt: Option<crate::quota_pool::QuotaPoolAttemptGuard>,
) -> Result<()> {
    if let Some(attempt) = quota_attempt {
        attempt.commit().await.map_err(anyhow::Error::new)?;
    }
    Ok(())
}

/// The verbatim credential header for `provider`, or `None` when the
/// provider authenticates with a request signature instead.
///
/// WOR-2648: the bearer mode and the signing mode are structurally
/// exclusive rather than a runtime branch. A provider entry carrying an
/// `aws_sigv4:` block emits no static credential header at all, so
/// there is no path on which an operator string could ride alongside a
/// signature, and the "a signed provider never sends `api_key`"
/// property holds by construction. Config validation refuses the two
/// keys together, so this returning `None` is never a silently dropped
/// credential.
fn provider_auth_header(
    provider: &ProviderConfig,
) -> Result<Option<(reqwest::header::HeaderName, reqwest::header::HeaderValue)>> {
    if provider.aws_sigv4.is_some() {
        return Ok(None);
    }
    let (name, value) = provider.auth_header();
    let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())?;
    let mut value = reqwest::header::HeaderValue::from_str(&value)?;
    value.set_sensitive(true);
    Ok(Some((name, value)))
}

/// Parse an HTTP method string into a `reqwest::Method`. Accepts the
/// canonical methods case-insensitively; falls back to
/// `reqwest::Method::from_bytes` for non-standard verbs.
fn parse_http_method(method: &str) -> Result<reqwest::Method> {
    let upper = method.to_ascii_uppercase();
    match upper.as_str() {
        "GET" => Ok(reqwest::Method::GET),
        "POST" => Ok(reqwest::Method::POST),
        "PUT" => Ok(reqwest::Method::PUT),
        "DELETE" => Ok(reqwest::Method::DELETE),
        "PATCH" => Ok(reqwest::Method::PATCH),
        "HEAD" => Ok(reqwest::Method::HEAD),
        "OPTIONS" => Ok(reqwest::Method::OPTIONS),
        other => reqwest::Method::from_bytes(other.as_bytes())
            .map_err(|e| anyhow::anyhow!("unsupported HTTP method '{other}': {e}")),
    }
}

/// Strip every credential-bearing header before a cross-origin hop.
///
/// `provider_auth_header` marks the provider credential sensitive, so
/// the sensitivity flag is the authority here rather than a hardcoded
/// name list: providers authenticate with `Authorization`, `x-api-key`,
/// and `api-key` depending on the vendor, and the HTTP client only
/// strips the first of those on its own. `Authorization` and `Cookie`
/// are removed unconditionally in case a caller set one without the
/// flag.
pub(crate) fn strip_sensitive_headers(headers: &mut reqwest::header::HeaderMap) {
    let sensitive: Vec<reqwest::header::HeaderName> = headers
        .iter()
        .filter(|(_, value)| value.is_sensitive())
        .map(|(name, _)| name.clone())
        .collect();
    for name in sensitive {
        headers.remove(&name);
    }
    headers.remove(reqwest::header::AUTHORIZATION);
    headers.remove(reqwest::header::COOKIE);
}

fn apply_provider_timeout(request: &mut reqwest::Request, provider: &ProviderConfig) {
    if let Some(timeout_ms) = provider.timeout_ms {
        *request.timeout_mut() = Some(Duration::from_millis(timeout_ms));
    }
}

/// Send `request`, re-authorizing every redirect hop (WOR-2165).
///
/// The shared provider client no longer follows redirects on its own.
/// A provider dial carries an API key, and a host allowlist checked
/// once covers hop one only, so a 302 was enough to walk the credential
/// off the approved host. Each `Location` now runs back through
/// [`evaluate_hop`] before the next connect, bounded at
/// `sbproxy_security::egress::MAX_REDIRECT_HOPS`.
///
/// With no authorizer configured (every production call site today) the
/// rule is [`RedirectRule::SameOriginOnly`]: the operator named one
/// host, so that is the only host the chain may reach, and no DNS work
/// happens at all. With an authorizer, each hop is authorized against
/// the allowlist for [`EgressPurpose::AiProvider`] and credentials are
/// stripped when the hop crosses origin.
///
/// WOR-2648: this is also the signing boundary. `signer` runs against
/// the fully built request immediately before each `execute`, which is
/// the only place in the outbound path where the method, host, path,
/// headers, and body are all final and all still mutable. A signature
/// computed anywhere upstream would be invalidated by the redirect
/// rewrite below, and one computed downstream is impossible. See
/// [`OutboundSigner`] for the contract this position imposes on a
/// scheme.
async fn send_governed(
    http: &reqwest::Client,
    egress: Option<&EgressAuthorizer>,
    origin_label: &str,
    signer: Option<&dyn OutboundSigner>,
    mut request: reqwest::Request,
) -> Result<reqwest::Response> {
    let mut hop = 0usize;
    loop {
        // The signing boundary. This runs once per attempt and once per
        // hop, after `*replay.url_mut() = next.url` below has moved the
        // request to the next host and path, so the credential is
        // always bound to the request actually being sent.
        if let Some(signer) = signer {
            signer.sign(&mut request).await?;
        }
        // Clone before the send consumes the request so a hop can reuse
        // the method, headers, and body.
        let replay = request.try_clone();
        let from = request.url().clone();
        let started = std::time::Instant::now();
        // `without_url` rather than a bare `?`. A provider dial carries
        // an API key, some providers carry it in the query string, and a
        // `reqwest::Error`'s Display ends with `" for url ({url})"`. This
        // error becomes an `anyhow::Error` with no context of its own, so
        // its Display *is* the reqwest Display, and callers hand it to
        // `warn!(error = %error, ..)` and to pingora's `Error::because`
        // (WOR-2629). Stripping the URL rather than replacing the error
        // keeps the type, which `ai_transport_error_type` downcasts to
        // separate a timeout from a provider error.
        let resp = http
            .execute(request)
            .await
            .map_err(reqwest::Error::without_url)?;
        if let Some(signer) = signer {
            // Lets a scheme learn from the answer: SigV4 reads the
            // `Date` header off a rejection to measure local clock
            // skew, which is otherwise indistinguishable from a bad key.
            signer.observe_response(resp.status(), resp.headers(), started.elapsed());
        }
        if !resp.status().is_redirection() {
            return Ok(resp);
        }
        let Some(location) = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
        else {
            // A redirect status with no usable Location is not a hop.
            // Hand it back rather than inventing a destination.
            return Ok(resp);
        };
        hop += 1;
        let next = evaluate_hop(
            egress,
            EgressPurpose::AiProvider,
            &from,
            &location,
            hop,
            RedirectRule::SameOriginOnly,
            &CachedSystemResolver,
            origin_label,
        )
        .map_err(|denied| {
            record_egress_refused(EgressPurpose::AiProvider, denied, "unset", origin_label);
            anyhow::anyhow!("egress denied: {denied:?}")
        })?;
        let Some(mut replay) = replay else {
            // A non-replayable body (a stream) cannot be re-sent on the
            // hop. Returning the redirect response is honest; sending
            // the hop with the body silently dropped is not.
            return Ok(resp);
        };
        if next.strip_credentials {
            strip_sensitive_headers(replay.headers_mut());
        }
        *replay.url_mut() = next.url;
        request = replay;
    }
}

fn provider_retry_attempts(provider: &ProviderConfig) -> usize {
    provider.max_retries.unwrap_or(0).saturating_add(1).max(1) as usize
}

fn provider_retry_backoff(retry_number: usize) -> Duration {
    provider_retry_backoff_with_jitter(retry_number, rand::random::<u64>())
}

fn provider_retry_backoff_with_jitter(retry_number: usize, jitter_seed: u64) -> Duration {
    let exponent = retry_number.saturating_sub(1).min(10) as u32;
    let base_ms = (PROVIDER_RETRY_BASE_DELAY.as_millis() as u64)
        .saturating_mul(1_u64 << exponent)
        .min(PROVIDER_RETRY_MAX_DELAY.as_millis() as u64);
    let jitter_window = base_ms.saturating_mul(PROVIDER_RETRY_JITTER_PCT) / 100;
    let jitter = if jitter_window == 0 {
        0
    } else {
        jitter_seed % (jitter_window + 1)
    };
    Duration::from_millis(base_ms.saturating_add(jitter))
}

fn prepare_provider_attempt_body(
    config: &AiHandlerConfig,
    provider: &ProviderConfig,
    body: &serde_json::Value,
) -> (serde_json::Value, &'static str) {
    let mut attempt_body = body.clone();
    let logical_model = attempt_body
        .get("model")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let provider_model = provider.map_model(logical_model);
    if !logical_model.is_empty() {
        attempt_body["model"] = serde_json::Value::String(provider_model.clone());
    }
    let transform = crate::reasoning::apply_reasoning_policy(
        config.reasoning,
        provider,
        &provider_model,
        &mut attempt_body,
    );
    (attempt_body, transform.outcome_label())
}

impl AiClient {
    async fn forward_race(
        &self,
        config: &AiHandlerConfig,
        router: &Router,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response> {
        use futures::stream::{FuturesUnordered, StreamExt};

        let mut candidates = router.eligible_indices(&config.providers);
        if candidates.is_empty() {
            // WOR-2233: the race leg gets the same rule as every other
            // selection path. With every provider ejected the three
            // axes have nothing left to prefer, so racing the enabled
            // set beats refusing a request they could not individually
            // refuse.
            candidates = router.routable_candidate_indices(
                &config.providers,
                &(0..config.providers.len()).collect::<Vec<_>>(),
            );
        }
        if candidates.is_empty() {
            return Err(anyhow::anyhow!("no eligible providers for race"));
        }
        if candidates.len() == 1 {
            // No race needed; single provider just forwards.
            let idx = candidates[0];
            let p = &config.providers[idx];
            let (attempt_body, reasoning_outcome) = prepare_provider_attempt_body(config, p, body);
            ai_metrics::record_reasoning_policy_attempt(&p.name, reasoning_outcome);
            return match self.forward_request(p, path, &attempt_body).await {
                Ok(r) if r.status().is_server_error() => {
                    router.record_provider_failure(idx, p.name.as_str());
                    Err(anyhow::anyhow!(
                        "race fallback provider {} returned {}",
                        p.name,
                        r.status()
                    ))
                }
                Ok(r) => {
                    router.record_provider_success(idx, p.name.as_str());
                    Ok(r)
                }
                Err(e) => {
                    router.record_provider_failure(idx, p.name.as_str());
                    Err(e)
                }
            };
        }

        let mut tasks = FuturesUnordered::new();
        for idx in &candidates {
            let provider = config.providers[*idx].clone();
            let path_owned = path.to_string();
            let (body_owned, reasoning_outcome) =
                prepare_provider_attempt_body(config, &provider, body);
            let http = self.http.clone();
            let egress = self.egress.clone();
            // Resolved before the spawn so a provider whose credentials
            // cannot be built refuses the whole race rather than losing
            // one leg silently mid-flight.
            let signer = self.signers.signer_for(&provider).await?;
            let i = *idx;
            // Pre-authorize before spawning so an unlisted host is
            // denied without opening a connection.
            {
                let format = provider_format(&provider);
                let (_translated_body, translated_path) = translators::translate_request(
                    format,
                    &path_owned,
                    &body_owned,
                    translate_options(&provider),
                );
                let base_url_owned = provider.effective_base_url();
                let base_url = base_url_owned.trim_end_matches('/');
                let url = build_url(base_url, &translated_path);
                self.gate_provider_url(&url, &provider.name)?;
            }
            tasks.push(async move {
                let format = provider_format(&provider);
                let (translated_body, translated_path) = translators::translate_request(
                    format,
                    &path_owned,
                    &body_owned,
                    translate_options(&provider),
                );
                let send_body = translated_body.as_ref().unwrap_or(&body_owned);
                let base_url_owned = provider.effective_base_url();
                let base_url = base_url_owned.trim_end_matches('/');
                let url = build_url(base_url, &translated_path);
                // WOR-2165: mark the credential sensitive so a
                // cross-origin hop strips it, the same as every other
                // provider dial. The raw `provider.auth_header()` pair
                // this leg used to build did not.
                let mut req = match provider_auth_header(&provider) {
                    Ok(Some((auth_header, auth_value))) => http
                        .post(&url)
                        .header("content-type", "application/json")
                        .header(auth_header, auth_value),
                    Ok(None) => http.post(&url).header("content-type", "application/json"),
                    Err(error) => return (i, provider, Err(error)),
                };
                if matches!(format, ProviderFormat::Anthropic) {
                    req = req.header("anthropic-version", "2023-06-01");
                }
                ai_metrics::record_reasoning_policy_attempt(&provider.name, reasoning_outcome);
                let resp = match req.json(send_body).build() {
                    Ok(mut request) => {
                        apply_provider_timeout(&mut request, &provider);
                        send_governed(
                            &http,
                            egress.as_ref(),
                            &provider.name,
                            as_signer(&signer),
                            request,
                        )
                        .await
                    }
                    Err(error) => Err(anyhow::Error::new(error)),
                };
                (i, provider, resp)
            });
        }

        let mut last_err: Option<anyhow::Error> = None;
        while let Some((idx, provider, result)) = tasks.next().await {
            match result {
                Ok(resp) if resp.status().is_server_error() => {
                    router.record_provider_failure(idx, provider.name.as_str());
                    last_err = Some(anyhow::anyhow!(
                        "race leg {} returned {}",
                        provider.name,
                        resp.status()
                    ));
                    continue;
                }
                Ok(resp) => {
                    router.record_provider_success(idx, provider.name.as_str());
                    debug!(
                        provider = %provider.name,
                        "race leg won; cancelling {} losers",
                        candidates.len() - 1
                    );
                    // Drop the remaining FuturesUnordered to cancel
                    // the in-flight requests. Tokio cancels the
                    // pending sends; reqwest aborts the connection.
                    drop(tasks);
                    return Ok(resp);
                }
                Err(e) => {
                    router.record_provider_failure(idx, provider.name.as_str());
                    // WOR-2165: the leg now returns anyhow::Error (an
                    // egress refusal is not a transport error), so this
                    // is already the right type.
                    last_err = Some(e);
                    continue;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("race exhausted")))
    }
}

/// Result of one cascade dispatch.
///
/// Carries the response that was either accepted by a tier or
/// returned as the cascade's last attempt when the cost cap fired
/// before any tier accepted. Tests and the server-side relay
/// inspect [`Self::tier_index`] to learn which tier won.
#[derive(Debug)]
pub struct CascadeOutcome {
    /// Final HTTP status from the accepted tier.
    pub status: u16,
    /// Response headers from the accepted tier.
    pub headers: Vec<(String, String)>,
    /// Response body bytes (already translated to OpenAI shape when
    /// the upstream speaks a non-OpenAI wire format).
    pub body: bytes::Bytes,
    /// Name of the provider whose response is being returned.
    pub provider_name: String,
    /// Model id used for the chosen tier.
    pub model: String,
    /// Upstream wire format of the chosen tier.
    pub format: ProviderFormat,
    /// 0-based index of the tier whose response is being returned.
    pub tier_index: usize,
    /// `true` when the cascade exited because a tier's response
    /// scored at or above its `quality_threshold`; `false` when the
    /// cascade returned the last tier's response after exhausting
    /// tiers without acceptance (cost cap, or no tier met the bar).
    pub accepted: bool,
    /// Providers that received a request, in attempt order. Skipped or
    /// ineligible tiers are omitted.
    pub attempted_providers: Vec<String>,
    /// WOR-1845: prompt plus completion tokens consumed by every tier
    /// whose body was thrown away before this one, summed across
    /// attempts. Never includes the usage reported inside
    /// [`Self::body`], so a caller can add the two without double
    /// counting.
    ///
    /// A cascade that discards two attempts and serves the third has
    /// really spent all three. Leaving the first two out of the billing
    /// event under-bills the customer, and leaving them out of the
    /// governed-key settlement lets a caller exceed a strict allowance
    /// by forcing cascades. Reconcile against
    /// `discarded_tokens + usage(body)`.
    pub discarded_tokens: u64,
    /// WOR-1845: estimated USD spend for [`Self::discarded_tokens`],
    /// priced per attempt against that attempt's own model rather than
    /// the model that eventually won. Excludes [`Self::body`]'s cost
    /// for the same reason.
    pub discarded_cost_usd: f64,
}

impl AiClient {
    /// Dispatch a request using the cascade routing strategy. Walks
    /// `cascade.tiers` in order; for each tier:
    ///
    /// 1. Skip the tier when dispatching it would push the
    ///    cumulative estimated cost above `max_total_cost` (or
    ///    above the tier's `cost_cap`). Record an outcome of
    ///    `cost_cap`.
    /// 2. Send the request with the tier's `model` substituted
    ///    into the body's `model` field.
    /// 3. Read the response body bytes (consuming the response),
    ///    translate non-OpenAI shapes back to OpenAI Chat, and
    ///    look for a top-level `confidence_score` JSON number.
    /// 4. When the score is `>=` `quality_threshold` (or the field
    ///    is absent, which is treated as `1.0`), accept and
    ///    return the response. Record an outcome of `accepted`.
    /// 5. When the response is empty, returned a refusal, or
    ///    scored below the threshold, advance to the next tier.
    ///    Record an outcome of `retry` and remember the body so
    ///    the caller still has something to return when every
    ///    tier scores low.
    ///
    /// On a transport error or 5xx response, the dispatcher logs
    /// and advances to the next tier (the failure is also recorded
    /// against the resilience layer when the provider exists in
    /// the configured list). The cascade never short-circuits the
    /// request entirely; the caller always gets the most recent
    /// upstream response back, even when every tier disappointed.
    ///
    /// Streaming requests are out of scope: callers should detect
    /// `body.stream == true` and skip this method.
    // The cascade boundary deliberately receives policy, request, attribution,
    // and routing context together so every tier is governed consistently.
    #[allow(clippy::too_many_arguments)]
    pub async fn forward_cascade(
        &self,
        config: &AiHandlerConfig,
        cascade: &crate::routing::CascadeConfig,
        allowed_providers: &[String],
        path: &str,
        body: &serde_json::Value,
        tags: &crate::attribution::AttributionTags,
        surface: &str,
    ) -> Result<CascadeOutcome> {
        self.forward_cascade_with_policy(
            config,
            cascade,
            allowed_providers,
            &[],
            path,
            body,
            tags,
            surface,
        )
        .await
    }

    /// Dispatch a confidence cascade constrained by credential provider policy.
    #[allow(clippy::too_many_arguments)]
    pub async fn forward_cascade_with_policy(
        &self,
        config: &AiHandlerConfig,
        cascade: &crate::routing::CascadeConfig,
        allowed_providers: &[String],
        blocked_providers: &[String],
        path: &str,
        body: &serde_json::Value,
        tags: &crate::attribution::AttributionTags,
        surface: &str,
    ) -> Result<CascadeOutcome> {
        self.forward_cascade_with_policy_impl(
            config,
            cascade,
            allowed_providers,
            blocked_providers,
            path,
            body,
            tags,
            surface,
            None,
            "",
            None,
        )
        .await
    }

    /// Dispatch a confidence cascade with per-tier quota admission.
    ///
    /// Each tier reserves and commits immediately before its upstream call.
    /// The caller supplies a globally unique request prefix; the tier index is
    /// appended so retries never reuse one reservation.
    #[allow(clippy::too_many_arguments)]
    pub async fn forward_cascade_with_policy_and_quota(
        &self,
        config: &AiHandlerConfig,
        cascade: &crate::routing::CascadeConfig,
        allowed_providers: &[String],
        blocked_providers: &[String],
        path: &str,
        body: &serde_json::Value,
        tags: &crate::attribution::AttributionTags,
        surface: &str,
        quota: &crate::quota_pool::QuotaPoolAdmission,
        quota_reservation_prefix: &str,
    ) -> Result<CascadeOutcome> {
        self.forward_cascade_with_policy_impl(
            config,
            cascade,
            allowed_providers,
            blocked_providers,
            path,
            body,
            tags,
            surface,
            Some(quota),
            quota_reservation_prefix,
            None,
        )
        .await
    }

    /// Dispatch a quota-governed confidence cascade while preserving
    /// eligibility captured before lossy request transformations.
    #[allow(clippy::too_many_arguments)]
    pub async fn forward_cascade_with_policy_and_quota_with_reasoning_eligibility(
        &self,
        config: &AiHandlerConfig,
        cascade: &crate::routing::CascadeConfig,
        allowed_providers: &[String],
        blocked_providers: &[String],
        path: &str,
        body: &serde_json::Value,
        tags: &crate::attribution::AttributionTags,
        surface: &str,
        quota: &crate::quota_pool::QuotaPoolAdmission,
        quota_reservation_prefix: &str,
        reasoning_eligibility: crate::reasoning::ReasoningEligibility,
    ) -> Result<CascadeOutcome> {
        self.forward_cascade_with_policy_impl(
            config,
            cascade,
            allowed_providers,
            blocked_providers,
            path,
            body,
            tags,
            surface,
            Some(quota),
            quota_reservation_prefix,
            Some(reasoning_eligibility),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn forward_cascade_with_policy_impl(
        &self,
        config: &AiHandlerConfig,
        cascade: &crate::routing::CascadeConfig,
        allowed_providers: &[String],
        blocked_providers: &[String],
        path: &str,
        body: &serde_json::Value,
        tags: &crate::attribution::AttributionTags,
        surface: &str,
        quota: Option<&crate::quota_pool::QuotaPoolAdmission>,
        quota_reservation_prefix: &str,
        reasoning_eligibility: Option<crate::reasoning::ReasoningEligibility>,
    ) -> Result<CascadeOutcome> {
        if cascade.tiers.is_empty() {
            return Err(anyhow::anyhow!("cascade has no tiers"));
        }

        let mut last_outcome: Option<CascadeOutcome> = None;
        let mut total_cost_micros: u64 = 0;
        let mut attempted_providers: Vec<String> = Vec::new();
        // WOR-1845: usage consumed by attempts whose bodies were thrown
        // away. Each `CascadeOutcome` below is built with the totals as
        // they stand *before* its own attempt is folded in, because that
        // outcome's body is what the caller reconciles from. Folding the
        // current attempt in first would double count the one case where
        // the cascade exhausts its tiers and returns the last loser.
        let mut discarded_tokens: u64 = 0;
        let mut discarded_cost_usd: f64 = 0.0;
        let router = config.router();

        for (tier_idx, tier) in cascade.tiers.iter().enumerate() {
            // Cost cap gate. Both the cascade-level and per-tier
            // caps are evaluated against `estimate_cost_micros`
            // for the tier's model. The cap fires before dispatch
            // so a still-in-flight tier can finish even when its
            // completion would push us over the budget.
            let projected = total_cost_micros.saturating_add(estimate_cost_micros(&tier.model));
            let over_global = cascade.max_total_cost.is_some_and(|cap| projected > cap);
            let over_tier = tier.cost_cap.is_some_and(|cap| projected > cap);
            if over_global || over_tier {
                debug!(
                    tier = tier_idx,
                    provider = %tier.provider_id,
                    model = %tier.model,
                    projected_micros = projected,
                    global_cap = ?cascade.max_total_cost,
                    tier_cap = ?tier.cost_cap,
                    "cascade: skipping tier; would exceed cost cap"
                );
                ai_metrics::record_cascade_tier_outcome(tier_idx, "cost_cap");
                continue;
            }

            // Find the provider config for this tier, then apply the same
            // strict live resilience gate as ordinary dispatch. A cascade
            // must never revive an unhealthy, ejected, or breaker-blocked
            // provider merely because it appears in the configured tiers.
            let provider = match config.providers.iter().enumerate().find(|(idx, provider)| {
                provider.name == tier.provider_id
                    && cascade_provider_is_eligible(provider, allowed_providers, blocked_providers)
                    && !router
                        .eligible_candidate_indices(&config.providers, &[*idx])
                        .is_empty()
            }) {
                Some((_, provider)) => provider,
                None => {
                    warn!(
                        tier = tier_idx,
                        provider_id = %tier.provider_id,
                        "cascade: tier provider not found or ineligible; skipping"
                    );
                    ai_metrics::record_cascade_tier_outcome(tier_idx, "retry");
                    continue;
                }
            };

            // Build the per-tier body with the tier's model
            // substituted in. We do this before any model_map
            // remap because the tier-specified model is the
            // authoritative choice.
            let mut tier_body = body.clone();
            let provider_model = provider.map_model(&tier.model);
            if let Some(obj) = tier_body.as_object_mut() {
                obj.insert(
                    "model".to_string(),
                    serde_json::Value::String(provider_model.clone()),
                );
            }
            let policy = if matches!(surface, "chat_completions" | "messages" | "responses") {
                config.reasoning
            } else {
                crate::reasoning::ReasoningPolicy::Off
            };
            let reasoning = match reasoning_eligibility {
                Some(eligibility) => crate::reasoning::apply_reasoning_policy_with_eligibility(
                    policy,
                    provider,
                    &provider_model,
                    &mut tier_body,
                    eligibility,
                ),
                None => crate::reasoning::apply_reasoning_policy(
                    policy,
                    provider,
                    &provider_model,
                    &mut tier_body,
                ),
            };

            debug!(
                tier = tier_idx,
                provider = %provider.name,
                model = %tier.model,
                threshold = tier.quality_threshold,
                "cascade: dispatching tier"
            );

            attempted_providers.push(provider.name.to_string());
            let resp = if let Some(quota) = quota {
                let reservation_id = format!("{quota_reservation_prefix}:tier:{tier_idx}");
                let attempt = quota
                    .reserve_attempt(&reservation_id)
                    .await
                    .map_err(anyhow::Error::new)?;
                ai_metrics::record_reasoning_policy_attempt(
                    &provider.name,
                    reasoning.outcome_label(),
                );
                self.forward_request_with_quota(provider, path, &tier_body, attempt)
                    .await
            } else {
                ai_metrics::record_reasoning_policy_attempt(
                    &provider.name,
                    reasoning.outcome_label(),
                );
                self.forward_request(provider, path, &tier_body).await
            };
            let resp = match resp {
                Ok(r) => r,
                Err(error)
                    if error
                        .downcast_ref::<crate::quota_pool::PoolError>()
                        .is_some() =>
                {
                    return Err(error);
                }
                Err(e) => {
                    warn!(
                        tier = tier_idx,
                        provider = %provider.name,
                        error = %e,
                        "cascade: transport error; trying next tier"
                    );
                    ai_metrics::record_cascade_tier_outcome(tier_idx, "retry");
                    continue;
                }
            };

            let status = resp.status();
            let format = provider_format(provider);

            // Snapshot headers before consuming the body. We carry
            // a small whitelist back through `CascadeOutcome`; the
            // server-side relay re-applies them when writing the
            // response back to the client.
            let header_pairs: Vec<(String, String)> = resp
                .headers()
                .iter()
                .filter_map(|(k, v)| {
                    v.to_str()
                        .ok()
                        .map(|s| (k.as_str().to_string(), s.to_string()))
                })
                .collect();

            // Bound the read at 8 MiB so a misbehaving provider
            // cannot OOM the gateway. This is the same magnitude
            // used by `read_capped_response_body` in the server
            // when no explicit cap is configured.
            let raw_bytes = match resp.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    // Not `error = %e`: a reqwest Display ends with the
                    // provider URL, and some providers carry the API key
                    // in the query string (WOR-2629).
                    warn!(
                        tier = tier_idx,
                        provider = %provider.name,
                        error = %sbproxy_httpkit::request_error_summary(&e),
                        "cascade: body read failed; trying next tier"
                    );
                    ai_metrics::record_cascade_tier_outcome(tier_idx, "retry");
                    continue;
                }
            };

            total_cost_micros = projected;

            // Translate non-OpenAI shapes back to OpenAI Chat so the
            // confidence_score lookup runs uniformly. The translated
            // bytes are also what we hand back to the caller; the
            // gateway speaks OpenAI Chat to clients by default.
            let translated_vec =
                translators::translate_success_response_bytes(format, status.as_u16(), &raw_bytes);
            let translated = bytes::Bytes::from(translated_vec);

            // 5xx responses are treated as failure regardless of
            // body shape. The cascade falls through to the next
            // tier with the rationale that an upstream error is
            // not a quality verdict.
            if status.is_server_error() {
                warn!(
                    tier = tier_idx,
                    provider = %provider.name,
                    status = %status,
                    "cascade: tier returned 5xx; trying next"
                );
                ai_metrics::record_cascade_tier_outcome(tier_idx, "retry");
                let wasted = record_cascade_loser_waste(
                    &provider.name,
                    &tier.model,
                    surface,
                    tags,
                    translated.as_ref(),
                );
                last_outcome = Some(CascadeOutcome {
                    status: status.as_u16(),
                    headers: header_pairs,
                    body: translated,
                    provider_name: provider.name.to_string(),
                    model: tier.model.clone(),
                    format,
                    tier_index: tier_idx,
                    accepted: false,
                    attempted_providers: attempted_providers.clone(),
                    discarded_tokens,
                    discarded_cost_usd,
                });
                discarded_tokens = discarded_tokens.saturating_add(wasted.0);
                discarded_cost_usd += wasted.1;
                continue;
            }

            // Extract the quality signal. When `confidence_score`
            // is absent we treat the response as quality 1.0 and
            // accept. Empty or refusal-style responses force a
            // retry even when no score is present.
            let quality = extract_confidence_score(&translated);
            let is_refusal = response_is_empty_or_refused(&translated);

            if is_refusal {
                debug!(
                    tier = tier_idx,
                    provider = %provider.name,
                    "cascade: tier returned empty or refused response; trying next"
                );
                ai_metrics::record_cascade_tier_outcome(tier_idx, "retry");
                let wasted = record_cascade_loser_waste(
                    &provider.name,
                    &tier.model,
                    surface,
                    tags,
                    translated.as_ref(),
                );
                last_outcome = Some(CascadeOutcome {
                    status: status.as_u16(),
                    headers: header_pairs,
                    body: translated,
                    provider_name: provider.name.to_string(),
                    model: tier.model.clone(),
                    format,
                    tier_index: tier_idx,
                    accepted: false,
                    attempted_providers: attempted_providers.clone(),
                    discarded_tokens,
                    discarded_cost_usd,
                });
                discarded_tokens = discarded_tokens.saturating_add(wasted.0);
                discarded_cost_usd += wasted.1;
                continue;
            }

            if quality < tier.quality_threshold {
                debug!(
                    tier = tier_idx,
                    provider = %provider.name,
                    quality,
                    threshold = tier.quality_threshold,
                    "cascade: tier scored below threshold; trying next"
                );
                ai_metrics::record_cascade_tier_outcome(tier_idx, "retry");
                let wasted = record_cascade_loser_waste(
                    &provider.name,
                    &tier.model,
                    surface,
                    tags,
                    translated.as_ref(),
                );
                last_outcome = Some(CascadeOutcome {
                    status: status.as_u16(),
                    headers: header_pairs,
                    body: translated,
                    provider_name: provider.name.to_string(),
                    model: tier.model.clone(),
                    format,
                    tier_index: tier_idx,
                    accepted: false,
                    attempted_providers: attempted_providers.clone(),
                    discarded_tokens,
                    discarded_cost_usd,
                });
                discarded_tokens = discarded_tokens.saturating_add(wasted.0);
                discarded_cost_usd += wasted.1;
                continue;
            }

            // Accepted.
            ai_metrics::record_cascade_tier_outcome(tier_idx, "accepted");
            return Ok(CascadeOutcome {
                status: status.as_u16(),
                headers: header_pairs,
                body: translated,
                provider_name: provider.name.to_string(),
                model: tier.model.clone(),
                format,
                tier_index: tier_idx,
                accepted: true,
                attempted_providers,
                discarded_tokens,
                discarded_cost_usd,
            });
        }

        last_outcome
            .ok_or_else(|| anyhow::anyhow!("cascade exhausted without dispatching any tier"))
    }
}

/// Estimate the cost of one request to `model` in micro-USD. Wraps
/// [`crate::budget::estimate_cost`] with sensible default token
/// counts (`prompt_tokens=512`, `completion_tokens=512`) so the
/// cascade can compare projected spend across tiers before sending
/// the request. The exact token shape of an in-flight request is
/// not known until the response arrives; this estimate is a
/// reasonable mid-conversation default.
fn estimate_cost_micros(model: &str) -> u64 {
    let cost_dollars = crate::budget::estimate_cost(model, 512, 512);
    (cost_dollars * 1_000_000.0).round() as u64
}

/// Extract OpenAI-shaped `(prompt_tokens, completion_tokens)` from a
/// translated response body, returning `(0, 0)` when no usage block
/// is present. The cascade always translates upstream bodies back to
/// OpenAI Chat before this runs, so the `usage` shape is uniform.
fn extract_usage_tokens(body: &[u8]) -> (u64, u64) {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("usage").cloned())
        .map(|u| {
            let p = u.get("prompt_tokens").and_then(|x| x.as_u64()).unwrap_or(0);
            let c = u
                .get("completion_tokens")
                .and_then(|x| x.as_u64())
                .unwrap_or(0);
            (p, c)
        })
        .unwrap_or((0, 0))
}

/// WOR-1093: a cascade tier that returned a body but lost (5xx,
/// refusal, or below the quality threshold) still consumed upstream
/// tokens that bought no served outcome. Flag those tokens as
/// `failover_loser` waste, reusing the usage already present in the
/// translated body. A loser with no parseable usage records nothing.
///
/// WOR-1845: also returns the `(tokens, cost_usd)` it just flagged so
/// the dispatcher can aggregate every discarded attempt onto
/// [`CascadeOutcome`]. The waste metric alone leaves that spend out of
/// the billing ledger and out of the governed-key reservation, which
/// lets a caller walk past a strict allowance by forcing cascades.
/// Returns `(0, 0.0)` when the body carries no parseable usage.
fn record_cascade_loser_waste(
    provider: &str,
    model: &str,
    surface: &str,
    tags: &crate::attribution::AttributionTags,
    body: &[u8],
) -> (u64, f64) {
    let (prompt, completion) = extract_usage_tokens(body);
    let tokens = prompt.saturating_add(completion);
    if tokens == 0 {
        return (0, 0.0);
    }
    let cost = crate::budget::estimate_cost(model, prompt, completion);
    ai_metrics::record_waste(
        ai_metrics::WasteKind::FailoverLoser,
        provider,
        model,
        surface,
        tags,
        tokens,
        cost,
    );
    (tokens, cost)
}

/// Look for a top-level `confidence_score` JSON number in the
/// response body. Returns `1.0` when the field is absent or the
/// body is not JSON; returns `0.0` when the field is malformed.
fn extract_confidence_score(body: &[u8]) -> f32 {
    let v: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return 1.0,
    };
    match v.get("confidence_score") {
        Some(score) => score.as_f64().map(|f| f as f32).unwrap_or(0.0),
        None => 1.0,
    }
}

/// Detect empty or explicit-refusal responses. Returns `true` when
/// the body is empty, when no `choices[0].message.content` is
/// present, or when the content is whitespace only. Refusal
/// detection is intentionally conservative: only obvious empty
/// shapes count; classifier-based refusal detection is a follow-up.
fn response_is_empty_or_refused(body: &[u8]) -> bool {
    if body.is_empty() {
        return true;
    }
    let v: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let content = v
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"));
    match content {
        Some(serde_json::Value::String(s)) => s.trim().is_empty(),
        Some(serde_json::Value::Null) | None => true,
        _ => false,
    }
}

/// Fire a single shadow request at `provider`, log the metadata, and
/// drain the body so connections return to the pool.
async fn run_shadow_request(
    http: reqwest::Client,
    signers: Arc<SignerCache>,
    provider: ProviderConfig,
    path: String,
    body: serde_json::Value,
    timeout: std::time::Duration,
    quota_attempt: Option<crate::quota_pool::QuotaPoolAttemptGuard>,
) -> ShadowCallResult {
    let format = provider_format(&provider);
    let (translated_body, translated_path) =
        translators::translate_request(format, &path, &body, translate_options(&provider));
    let send_body = translated_body.as_ref().unwrap_or(&body);
    let base_url_owned = provider.effective_base_url();
    let base_url = base_url_owned.trim_end_matches('/');
    let started = std::time::Instant::now();
    let url_string = build_url(base_url, &translated_path);
    let url = match reqwest::Url::parse(&url_string) {
        Ok(url) => url,
        Err(error) => {
            warn!(provider = %provider.name, %error, "shadow request URL is invalid");
            return failed_shadow_call(started);
        }
    };
    let auth = match provider_auth_header(&provider) {
        Ok(header) => header,
        Err(error) => {
            warn!(provider = %provider.name, %error, "shadow request auth header is invalid");
            return failed_shadow_call(started);
        }
    };
    // WOR-2648: a shadow copy of a SigV4 provider is signed with the
    // same credential as the primary and reaches AWS as a real
    // `InvokeModel`. Excluding signed providers from shadow would be an
    // undocumented routing carve-out, and a shadow copy already costs
    // real money at every other vendor; `shadow:` is the switch for
    // operators who do not want the extra call.
    let signer = match signers.signer_for(&provider).await {
        Ok(signer) => signer,
        Err(error) => {
            warn!(provider = %provider.name, %error, "shadow request signer is unavailable");
            return failed_shadow_call(started);
        }
    };
    let mut req = http
        .post(url)
        .header("x-sbproxy-shadow", "1")
        .json(send_body)
        .timeout(timeout);
    if let Some((auth_header, auth_value)) = auth {
        req = req.header(auth_header, auth_value);
    }
    if matches!(format, ProviderFormat::Anthropic) {
        req = req.header("anthropic-version", "2023-06-01");
    }
    if let Err(error) = commit_quota_attempt(quota_attempt).await {
        warn!(
            provider = %provider.name,
            %error,
            "quota admission suppressed optional shadow request"
        );
        return failed_shadow_call(started);
    }
    // WOR-2165: a shadow copy carries the same provider credential as
    // the primary, so it follows redirects under the same governed
    // contract. `try_spawn_shadow` already suppresses the copy outright
    // when an authorizer is attached, so the hop rule here is always
    // the unconfigured one: same origin or nothing.
    let request = match req.build() {
        Ok(request) => request,
        Err(error) => {
            warn!(provider = %provider.name, %error, "shadow request could not be built");
            return failed_shadow_call(started);
        }
    };
    let mut resp =
        match send_governed(&http, None, &provider.name, as_signer(&signer), request).await {
            Ok(r) => r,
            // `transport_error`, not `e`: `send_governed` strips the URL
            // off the `reqwest::Error` before it becomes an
            // `anyhow::Error`, and the name says at the log site which
            // error is in hand rather than leaving the next reader to go
            // and check (WOR-2629).
            Err(transport_error) => {
                warn!(
                    provider = %provider.name,
                    error = %transport_error,
                    "shadow request transport error"
                );
                ai_metrics::record_provider_error(&provider.name, "transport");
                return failed_shadow_call(started);
            }
        };
    let status = resp.status();
    if !status.is_success() {
        let kind = if status.is_server_error() {
            "http_5xx"
        } else if status.is_client_error() {
            "http_4xx"
        } else {
            "http_other"
        };
        ai_metrics::record_provider_error(&provider.name, kind);
    }
    let mut raw_bytes = Vec::new();
    let mut total_response_bytes = 0_u64;
    let mut metadata_truncated = false;
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                total_response_bytes =
                    total_response_bytes.saturating_add(chunk.len().try_into().unwrap_or(u64::MAX));
                metadata_truncated |=
                    append_shadow_response_metadata(&mut raw_bytes, chunk.as_ref());
            }
            Ok(None) => break,
            Err(e) => {
                warn!(provider = %provider.name, error = %e, "shadow body drain failed");
                ai_metrics::record_provider_error(&provider.name, "transport");
                return ShadowCallResult {
                    status: status.as_u16(),
                    latency_ms: started.elapsed().as_millis() as u64,
                    prompt_tokens: 0,
                    completion_tokens: 0,
                    finish_reason: None,
                };
            }
        }
    }
    // Translate non-OpenAI shadow responses into OpenAI shape so the
    // metadata parsing below works uniformly across providers.
    let bytes_vec =
        translators::translate_success_response_bytes(format, status.as_u16(), &raw_bytes);
    let bytes: &[u8] = &bytes_vec;
    let elapsed = started.elapsed();
    let (prompt_tokens, completion_tokens, finish_reason) = parse_shadow_metadata(bytes);
    info!(
        target: "sbproxy_ai_shadow",
        provider = %provider.name,
        status = %status,
        latency_ms = elapsed.as_millis() as u64,
        bytes = total_response_bytes,
        metadata_truncated,
        prompt_tokens = ?prompt_tokens,
        completion_tokens = ?completion_tokens,
        finish_reason = ?finish_reason,
        "shadow response"
    );
    ShadowCallResult {
        status: status.as_u16(),
        latency_ms: elapsed.as_millis() as u64,
        prompt_tokens: prompt_tokens.unwrap_or(0),
        completion_tokens: completion_tokens.unwrap_or(0),
        finish_reason,
    }
}

fn failed_shadow_call(started: std::time::Instant) -> ShadowCallResult {
    ShadowCallResult {
        status: 0,
        latency_ms: started.elapsed().as_millis() as u64,
        prompt_tokens: 0,
        completion_tokens: 0,
        // A call that never produced a response has no finish reason.
        // `None` rather than a synthetic value, so a report counting
        // `length` truncations cannot pick up transport failures.
        finish_reason: None,
    }
}

fn append_shadow_response_metadata(buffer: &mut Vec<u8>, chunk: &[u8]) -> bool {
    let available = MAX_SHADOW_RESPONSE_METADATA_BYTES.saturating_sub(buffer.len());
    let retained = available.min(chunk.len());
    buffer.extend_from_slice(&chunk[..retained]);
    retained < chunk.len()
}

#[derive(Default)]
struct CountingWriter {
    bytes: usize,
}

impl std::io::Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.bytes = self.bytes.saturating_add(buffer.len());
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn serialized_json_len(value: &serde_json::Value) -> usize {
    let mut writer = CountingWriter::default();
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => writer.bytes,
        Err(_) => usize::MAX,
    }
}

/// Best-effort extraction of token counts and finish_reason from an
/// OpenAI-shaped response body. Returns `None`s when the upstream
/// shape differs.
/// Longest `finish_reason` a shadow row or log line will carry.
///
/// The value is copied out of a target's response body, and since it
/// started reaching a durable usage-ledger row as well as a log line it
/// needs a bound: a broken or hostile target can put a megabyte of text
/// in that field, up to the response metadata cap, and every shadow row
/// would carry it. The metric label is already closed to a vocabulary;
/// this bounds the two surfaces that keep the raw string. The longest
/// legitimate value, `content_filter`, is 14 bytes.
const MAX_SHADOW_FINISH_REASON_BYTES: usize = 64;

fn parse_shadow_metadata(body: &[u8]) -> (Option<u64>, Option<u64>, Option<String>) {
    let v: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (None, None, None),
    };
    let prompt = v
        .get("usage")
        .and_then(|u| u.get("prompt_tokens"))
        .and_then(|n| n.as_u64());
    let completion = v
        .get("usage")
        .and_then(|u| u.get("completion_tokens"))
        .and_then(|n| n.as_u64());
    let finish = v
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("finish_reason"))
        .and_then(|s| s.as_str())
        .map(|reason| {
            let mut end = MAX_SHADOW_FINISH_REASON_BYTES.min(reason.len());
            while end > 0 && !reason.is_char_boundary(end) {
                end -= 1;
            }
            reason[..end].to_string()
        });
    (prompt, completion, finish)
}

fn cascade_provider_is_eligible(
    provider: &ProviderConfig,
    allowed: &[String],
    blocked: &[String],
) -> bool {
    provider.enabled
        && crate::routing::provider_allowed_by_policy(provider.name.as_str(), allowed, blocked)
}

impl Default for AiClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Collect the per-provider settings the canonical OpenAI body cannot
/// carry into the translator's options struct.
///
/// One place, so a new option reaches every dial (single forward,
/// method forward, the race's pre-authorize and send legs, and the
/// shadow leg) instead of the subset a caller sweep remembered.
pub(crate) fn translate_options(provider: &ProviderConfig) -> translators::TranslateOptions<'_> {
    translators::TranslateOptions {
        bedrock_guardrail: provider.bedrock_guardrail.as_deref(),
    }
}

/// Look up a provider's wire format. Falls back to `OpenAi` (the
/// pass-through path) for unknown / custom provider names so existing
/// configurations keep working unchanged.
pub fn provider_format(provider: &ProviderConfig) -> ProviderFormat {
    let provider_key = provider
        .provider_type
        .as_deref()
        .unwrap_or(provider.name.as_str());
    get_provider_info(provider_key)
        .map(|info| info.format)
        .unwrap_or(ProviderFormat::OpenAi)
}

/// Build a full URL from base_url and path, handling version prefix overlap.
///
/// If the base_url already includes a version path (e.g. /v1) and the
/// request path starts with the same version prefix, we strip the
/// overlapping portion from the path to avoid duplication.
///
/// Examples:
/// ```text
/// base="http://host:18889/v1", path="/v1/chat/completions"
///   -> "http://host:18889/v1/chat/completions"
/// base="http://api.groq.com/openai/v1", path="/v1/chat/completions"
///   -> "http://api.groq.com/openai/v1/chat/completions"
/// ```
pub(crate) fn build_url(base_url: &str, path: &str) -> String {
    // Extract the last path segment from the base URL to check for overlap.
    // e.g. "http://host:8080/openai/v1" -> last segment is "/v1"
    if let Some(scheme_end) = base_url.find("://") {
        let after_scheme = &base_url[scheme_end + 3..];
        // Find the first slash after the host (start of path portion).
        if let Some(host_end) = after_scheme.find('/') {
            let base_path = &after_scheme[host_end..]; // e.g. "/openai/v1" or "/v1"
                                                       // Check if the request path starts with the last segment of the base path.
                                                       // e.g. base_path="/openai/v1", path="/v1/chat/completions"
                                                       // We want to find that "/v1" is at the end of base_path and start of path.
            if let Some(last_slash) = base_path.rfind('/') {
                let last_segment = &base_path[last_slash..]; // e.g. "/v1"
                if !last_segment.is_empty() && last_segment != "/" && path.starts_with(last_segment)
                {
                    // Strip the overlapping prefix from path.
                    let remainder = &path[last_segment.len()..]; // e.g. "/chat/completions"
                    return format!("{}{}", base_url, remainder);
                }
            }
        }
    }
    format!("{}{}", base_url, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    /// The composition every dial performs: read the provider entry,
    /// pick its wire format, and translate. Written against the pair
    /// rather than against `request_to_native` because the failure
    /// mode is a provider setting that parses, validates, and then
    /// never reaches the body.
    #[test]
    fn a_bedrock_entrys_guardrail_reaches_the_converse_body() {
        let provider: ProviderConfig = serde_json::from_value(serde_json::json!({
            "name": "bedrock",
            "aws_sigv4": {"region": "us-east-1"},
            "bedrock_guardrail": {"identifier": "gr-abc123", "version": "2", "trace": true},
        }))
        .expect("fixture provider parses");
        let body = serde_json::json!({
            "model": "anthropic.claude-3-5-sonnet-20240620-v1:0",
            "messages": [{"role": "user", "content": "hi"}],
        });
        let (translated, _path) = translators::translate_request(
            provider_format(&provider),
            "/v1/chat/completions",
            &body,
            translate_options(&provider),
        );
        let translated = translated.expect("Bedrock always translates");
        assert_eq!(
            translated["guardrailConfig"]["guardrailIdentifier"],
            "gr-abc123"
        );
        assert_eq!(translated["guardrailConfig"]["guardrailVersion"], "2");

        let unguarded: ProviderConfig = serde_json::from_value(serde_json::json!({
            "name": "bedrock",
            "aws_sigv4": {"region": "us-east-1"},
        }))
        .expect("fixture provider parses");
        let (translated, _path) = translators::translate_request(
            provider_format(&unguarded),
            "/v1/chat/completions",
            &body,
            translate_options(&unguarded),
        );
        assert!(
            translated
                .expect("Bedrock always translates")
                .get("guardrailConfig")
                .is_none(),
            "an entry with no guardrail must send no guardrailConfig"
        );
    }

    static SHADOW_METRIC_TEST_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

    #[derive(Default)]
    struct RecordingQuotaStore {
        reservation_ids: std::sync::Mutex<Vec<String>>,
        settled_ids: std::sync::Mutex<Vec<String>>,
        released_ids: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl crate::quota_pool::QuotaPoolStore for RecordingQuotaStore {
        async fn reserve(
            &self,
            pool: &str,
            member: &str,
            units: u64,
            reservation_id: &str,
        ) -> std::result::Result<crate::quota_pool::QuotaReservation, crate::quota_pool::PoolError>
        {
            self.reservation_ids
                .lock()
                .expect("recording quota lock")
                .push(reservation_id.to_string());
            Ok(crate::quota_pool::QuotaReservation {
                pool: pool.to_string(),
                member: member.to_string(),
                units,
                reservation_id: reservation_id.to_string(),
            })
        }

        async fn reconcile(
            &self,
            reservation: crate::quota_pool::QuotaReservation,
            _actual: crate::quota_pool::PoolUsage,
        ) -> std::result::Result<(), crate::quota_pool::PoolError> {
            self.settled_ids
                .lock()
                .expect("recording quota lock")
                .push(reservation.reservation_id);
            Ok(())
        }

        async fn release(
            &self,
            reservation: crate::quota_pool::QuotaReservation,
        ) -> std::result::Result<(), crate::quota_pool::PoolError> {
            self.released_ids
                .lock()
                .expect("recording quota lock")
                .push(reservation.reservation_id);
            Ok(())
        }
    }

    fn request_quota_config() -> crate::quota_pool::QuotaPoolConfig {
        serde_json::from_value(serde_json::json!({
            "name": "shared-upstream",
            "total_limit": 10,
            "weights": {"virtual-key-a": 1},
            "policy": "burst"
        }))
        .expect("quota fixture")
    }

    async fn wait_for_quota_release(store: &RecordingQuotaStore) {
        for _ in 0..16 {
            if !store
                .released_ids
                .lock()
                .expect("recording quota lock")
                .is_empty()
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn quota_aware_forward_releases_when_local_url_construction_fails() {
        let provider: ProviderConfig = serde_json::from_value(serde_json::json!({
            "name": "broken",
            "api_key": "test-key",
            "base_url": "not a URL"
        }))
        .expect("provider fixture");
        let store = Arc::new(RecordingQuotaStore::default());
        let quota_store: Arc<dyn crate::quota_pool::QuotaPoolStore> = store.clone();
        let admission = crate::quota_pool::QuotaPoolAdmission::new(
            Some(request_quota_config()),
            Ok(Some(quota_store)),
            Ok("virtual-key-a".to_string()),
        );
        let attempt = admission
            .reserve_attempt("request-local-url")
            .await
            .expect("quota reservation");

        AiClient::new()
            .forward_request_with_quota(
                &provider,
                "/v1/chat/completions",
                &serde_json::json!({"model": "test"}),
                attempt,
            )
            .await
            .expect_err("malformed URL must fail locally");

        wait_for_quota_release(&store).await;
        assert_eq!(
            *store.released_ids.lock().expect("recording quota lock"),
            vec!["request-local-url".to_string()]
        );
        assert!(store
            .settled_ids
            .lock()
            .expect("recording quota lock")
            .is_empty());
    }

    #[tokio::test]
    async fn quota_aware_method_releases_when_local_method_validation_fails() {
        let provider: ProviderConfig = serde_json::from_value(serde_json::json!({
            "name": "openai",
            "api_key": "test-key"
        }))
        .expect("provider fixture");
        let store = Arc::new(RecordingQuotaStore::default());
        let quota_store: Arc<dyn crate::quota_pool::QuotaPoolStore> = store.clone();
        let admission = crate::quota_pool::QuotaPoolAdmission::new(
            Some(request_quota_config()),
            Ok(Some(quota_store)),
            Ok("virtual-key-a".to_string()),
        );
        let attempt = admission
            .reserve_attempt("request-local-method")
            .await
            .expect("quota reservation");

        AiClient::new()
            .forward_with_method_and_quota(
                &provider,
                "method with spaces",
                "/v1/files",
                None,
                attempt,
            )
            .await
            .expect_err("invalid method must fail locally");

        wait_for_quota_release(&store).await;
        assert_eq!(
            *store.released_ids.lock().expect("recording quota lock"),
            vec!["request-local-method".to_string()]
        );
        assert!(store
            .settled_ids
            .lock()
            .expect("recording quota lock")
            .is_empty());
    }

    #[derive(Debug, Default)]
    struct CapturingUsageSink {
        events: std::sync::Mutex<Vec<LlmUsageEvent>>,
    }

    impl UsageSink for CapturingUsageSink {
        fn record(&self, event: &LlmUsageEvent) {
            self.events
                .lock()
                .expect("capturing usage sink lock")
                .push(event.clone());
        }

        fn name(&self) -> &str {
            "capturing"
        }
    }

    async fn serve_one_json_response(
        response_body: &'static str,
    ) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        serve_one_json_response_with_status(response_body, 200).await
    }

    async fn serve_one_json_response_with_status(
        response_body: &'static str,
        status: u16,
    ) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test provider");
        let address = listener.local_addr().expect("test provider address");
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept test request");
            let mut request = Vec::new();
            let expected_len = loop {
                let mut chunk = [0_u8; 4096];
                let read = stream.read(&mut chunk).await.expect("read test request");
                assert!(read > 0, "request ended before headers");
                request.extend_from_slice(&chunk[..read]);
                let Some(headers_end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&request[..headers_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("content length"))
                    })
                    .unwrap_or(0);
                break headers_end + 4 + content_length;
            };
            while request.len() < expected_len {
                let mut chunk = [0_u8; 4096];
                let read = stream.read(&mut chunk).await.expect("read request body");
                assert!(read > 0, "request body ended early");
                request.extend_from_slice(&chunk[..read]);
            }

            let response = format!(
                "HTTP/1.1 {status} Fixture\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write test response");
            request
        });
        (format!("http://{address}/v1"), task)
    }

    async fn serve_one_hanging_response() -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind hanging test provider");
        let address = listener.local_addr().expect("hanging provider address");
        let task = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept shadow request");
            std::future::pending::<()>().await;
        });
        (format!("http://{address}/v1"), task)
    }

    #[tokio::test]
    async fn provider_timeout_bounds_primary_requests() {
        let (base_url, server) = serve_one_hanging_response().await;
        let provider: ProviderConfig = serde_json::from_value(serde_json::json!({
            "name": "timeout-provider",
            "api_key": "test-secret",
            "base_url": base_url,
            "allow_private_base_url": true,
            "timeout_ms": 25
        }))
        .expect("provider fixture");

        let bounded = tokio::time::timeout(
            Duration::from_millis(250),
            AiClient::new().forward_get_request(&provider, "/v1/models"),
        )
        .await;
        server.abort();

        let error = bounded
            .expect("provider timeout must fire before the outer test bound")
            .expect_err("the hanging provider must time out");
        assert!(
            error
                .downcast_ref::<reqwest::Error>()
                .is_some_and(reqwest::Error::is_timeout),
            "expected a reqwest timeout, got: {error:#}"
        );
    }

    #[tokio::test]
    async fn internal_summarizer_targets_one_provider_and_mapped_model() {
        let (base_url, captured) = serve_one_json_response(
            r#"{"choices":[{"message":{"role":"assistant","content":"bounded facts"}}],"usage":{"prompt_tokens":31,"completion_tokens":4}}"#,
        )
        .await;
        let provider: ProviderConfig = serde_json::from_value(serde_json::json!({
            "name": "dedicated-summary-provider",
            "api_key": "test-secret",
            "base_url": base_url,
            "allow_private_base_url": true,
            "models": ["summary-model"],
            "model_map": {"summary-model": "upstream-summary-model"}
        }))
        .expect("provider fixture");
        let messages = vec![serde_json::json!({"role": "user", "content": "history"})];

        let output = AiClient::new()
            .summarize_internal(
                &provider,
                "summary-model",
                &messages,
                64,
                Duration::from_secs(2),
            )
            .await
            .expect("internal summary succeeds");

        assert_eq!(output.summary, "bounded facts");
        assert_eq!(output.input_tokens, 31);
        assert_eq!(output.output_tokens, 4);

        let request = captured.await.expect("test provider task");
        let request_text = String::from_utf8(request).expect("HTTP request is UTF-8");
        assert!(request_text.starts_with("POST /v1/chat/completions HTTP/1.1"));
        assert!(!request_text
            .to_ascii_lowercase()
            .contains("x-sbproxy-shadow"));
        let body = request_text.split_once("\r\n\r\n").expect("HTTP body").1;
        let body: serde_json::Value = serde_json::from_str(body).expect("JSON request body");
        assert_eq!(body["model"], "upstream-summary-model");
        assert_eq!(body["messages"], serde_json::Value::Array(messages));
        assert_eq!(body["max_tokens"], 64);
        assert_eq!(body["stream"], false);
    }

    #[test]
    fn build_url_with_v1_overlap() {
        let url = build_url("http://127.0.0.1:18889/v1", "/v1/chat/completions");
        assert_eq!(url, "http://127.0.0.1:18889/v1/chat/completions");
    }

    #[test]
    fn build_url_no_overlap() {
        let url = build_url("http://127.0.0.1:18889", "/v1/chat/completions");
        assert_eq!(url, "http://127.0.0.1:18889/v1/chat/completions");
    }

    #[test]
    fn build_url_different_path_prefix() {
        let url = build_url("http://api.example.com/openai/v1", "/v1/chat/completions");
        assert_eq!(url, "http://api.example.com/openai/v1/chat/completions");
    }

    #[test]
    fn build_url_https() {
        let url = build_url("https://api.openai.com/v1", "/v1/models");
        assert_eq!(url, "https://api.openai.com/v1/models");
    }

    #[test]
    fn build_url_no_scheme() {
        // Edge case: no scheme, just concatenate
        let url = build_url("localhost:8080", "/v1/chat/completions");
        assert_eq!(url, "localhost:8080/v1/chat/completions");
    }

    #[test]
    fn parse_http_method_accepts_canonical_verbs_case_insensitively() {
        for (input, expected) in [
            ("GET", reqwest::Method::GET),
            ("get", reqwest::Method::GET),
            ("POST", reqwest::Method::POST),
            ("put", reqwest::Method::PUT),
            ("DELETE", reqwest::Method::DELETE),
            ("PATCH", reqwest::Method::PATCH),
            ("Head", reqwest::Method::HEAD),
            ("options", reqwest::Method::OPTIONS),
        ] {
            assert_eq!(parse_http_method(input).unwrap(), expected, "input={input}");
        }
    }

    #[test]
    fn parse_http_method_falls_back_for_non_standard_verbs() {
        // RFC 7231 verbs and non-standard but valid token chars.
        let m = parse_http_method("CUSTOM").unwrap();
        assert_eq!(m.as_str(), "CUSTOM");
    }

    #[test]
    fn parse_http_method_rejects_invalid_token() {
        // Space is not a valid HTTP token character.
        assert!(parse_http_method("BAD METHOD").is_err());
    }

    #[test]
    fn provider_retry_attempts_include_initial_try() {
        let mut provider: ProviderConfig =
            serde_json::from_value(serde_json::json!({"name": "openai", "max_retries": 2}))
                .unwrap();
        assert_eq!(provider_retry_attempts(&provider), 3);
        provider.max_retries = None;
        assert_eq!(provider_retry_attempts(&provider), 1);
    }

    #[test]
    fn provider_retry_backoff_is_exponential_with_bounded_jitter() {
        let first = provider_retry_backoff_with_jitter(1, 0);
        let second = provider_retry_backoff_with_jitter(2, 0);
        let second_max = provider_retry_backoff_with_jitter(2, u64::MAX);

        assert_eq!(first, Duration::from_millis(100));
        assert_eq!(second, Duration::from_millis(200));
        assert!(
            (Duration::from_millis(200)..=Duration::from_millis(250)).contains(&second_max),
            "second retry should be 200ms plus <=25% jitter, got {second_max:?}"
        );
        assert!(provider_retry_backoff_with_jitter(99, u64::MAX) <= Duration::from_millis(2500));
    }

    #[test]
    fn cascade_provider_blocklist_overrides_allowlist() {
        let provider: ProviderConfig = serde_json::from_value(serde_json::json!({
            "name": "openai",
            "api_key": "test-key"
        }))
        .expect("provider fixture");
        let allowed = vec!["openai".to_string()];
        let blocked = vec!["openai".to_string()];

        assert!(!cascade_provider_is_eligible(&provider, &allowed, &blocked));
    }

    fn two_tier_cascade_config(first_url: &str, second_url: &str) -> AiHandlerConfig {
        AiHandlerConfig::from_config(serde_json::json!({
            "providers": [
                {
                    "name": "first",
                    "api_key": "test-key",
                    "base_url": first_url,
                    "allow_private_base_url": true
                },
                {
                    "name": "second",
                    "api_key": "test-key",
                    "base_url": second_url,
                    "allow_private_base_url": true
                }
            ],
            "routing": {
                "strategy": "cascade",
                "tiers": [
                    {
                        "provider_id": "first",
                        "model": "test-model",
                        "quality_threshold": 0.5
                    },
                    {
                        "provider_id": "second",
                        "model": "test-model",
                        "quality_threshold": 0.5
                    }
                ]
            }
        }))
        .expect("cascade fixture")
    }

    fn one_tier_anthropic_cascade_config(url: &str) -> AiHandlerConfig {
        AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{
                "name": "anthropic",
                "provider_type": "anthropic",
                "api_key": "test-key",
                "base_url": url,
                "allow_private_base_url": true
            }],
            "routing": {
                "strategy": "cascade",
                "tiers": [{
                    "provider_id": "anthropic",
                    "model": "claude-3-5-sonnet",
                    "quality_threshold": 0.5
                }]
            }
        }))
        .expect("Anthropic cascade fixture")
    }

    #[tokio::test]
    async fn cascade_preserves_final_anthropic_error_envelope() {
        let error = r#"{"type":"error","error":{"type":"overloaded_error","message":"try later"}}"#;
        let (url, request) = serve_one_json_response_with_status(error, 503).await;
        let config = one_tier_anthropic_cascade_config(&url);
        let cascade = config.router().cascade_config().cloned().expect("cascade");

        let outcome = AiClient::new()
            .forward_cascade_with_policy(
                &config,
                &cascade,
                &[],
                &[],
                "/v1/chat/completions",
                &serde_json::json!({
                    "model": "claude-3-5-sonnet",
                    "messages": [{"role": "user", "content": "ping"}]
                }),
                &crate::attribution::AttributionTags::default(),
                "messages",
            )
            .await
            .expect("final cascade error is returned");

        assert_eq!(outcome.status, 503);
        assert_eq!(outcome.body.as_ref(), error.as_bytes());
        request.await.expect("Anthropic request captured");
    }

    #[tokio::test]
    async fn cascade_consumes_one_unique_quota_reservation_per_dispatched_tier() {
        let low =
            r#"{"confidence_score":0.1,"choices":[{"message":{"content":"try another tier"}}]}"#;
        let accepted = r#"{"confidence_score":1.0,"choices":[{"message":{"content":"accepted"}}]}"#;
        let (first_url, first_request) = serve_one_json_response(low).await;
        let (second_url, second_request) = serve_one_json_response(accepted).await;
        let config = two_tier_cascade_config(&first_url, &second_url);
        let cascade = config.router().cascade_config().cloned().expect("cascade");
        let store = Arc::new(RecordingQuotaStore::default());
        let quota_store: Arc<dyn crate::quota_pool::QuotaPoolStore> = store.clone();
        let admission = crate::quota_pool::QuotaPoolAdmission::new(
            Some(request_quota_config()),
            Ok(Some(quota_store)),
            Ok("virtual-key-a".to_string()),
        );

        let outcome = AiClient::new()
            .forward_cascade_with_policy_and_quota(
                &config,
                &cascade,
                &[],
                &[],
                "/v1/chat/completions",
                &serde_json::json!({"model": "test-model"}),
                &crate::attribution::AttributionTags::default(),
                "chat_completions",
                &admission,
                "request-1:quota-pool:cascade",
            )
            .await
            .expect("second cascade tier succeeds");

        assert_eq!(outcome.provider_name, "second");
        assert_eq!(
            *store.reservation_ids.lock().expect("recording quota lock"),
            vec![
                "request-1:quota-pool:cascade:tier:0".to_string(),
                "request-1:quota-pool:cascade:tier:1".to_string(),
            ]
        );
        first_request.await.expect("first request captured");
        second_request.await.expect("second request captured");
    }

    #[tokio::test]
    async fn cascade_skips_a_resilience_ineligible_tier() {
        let accepted = r#"{"confidence_score":1.0,"choices":[{"message":{"content":"accepted"}}]}"#;
        let (first_url, first_request) = serve_one_json_response(accepted).await;
        let (second_url, second_request) = serve_one_json_response(accepted).await;
        let config = two_tier_cascade_config(&first_url, &second_url);
        config.router().set_provider_health(0, false);
        let cascade = config.router().cascade_config().cloned().expect("cascade");

        let outcome = AiClient::new()
            .forward_cascade_with_policy(
                &config,
                &cascade,
                &[],
                &[],
                "/v1/chat/completions",
                &serde_json::json!({"model": "test-model"}),
                &crate::attribution::AttributionTags::default(),
                "chat_completions",
            )
            .await
            .expect("healthy fallback tier succeeds");

        assert_eq!(outcome.provider_name, "second");
        assert_eq!(outcome.attempted_providers, vec!["second"]);
        assert!(
            !first_request.is_finished(),
            "resilience-ineligible tier must receive no upstream request"
        );
        first_request.abort();
        second_request.await.expect("healthy request captured");
    }

    // --- Cascade discarded-usage aggregation (WOR-1845) ---
    //
    // A cascade that throws a tier's body away still paid for it. The
    // gateway settles a governed-key reservation from what the outcome
    // reports, so usage the outcome does not carry is usage nobody is
    // charged for, and a caller who can force a cascade can walk past a
    // strict allowance. These pin the two halves of the contract:
    // discarded attempts are summed, and the body the caller is about
    // to read is never summed twice.

    fn priced_two_tier_cascade_config(first_url: &str, second_url: &str) -> AiHandlerConfig {
        AiHandlerConfig::from_config(serde_json::json!({
            "providers": [
                {
                    "name": "first",
                    "api_key": "test-key",
                    "base_url": first_url,
                    "allow_private_base_url": true
                },
                {
                    "name": "second",
                    "api_key": "test-key",
                    "base_url": second_url,
                    "allow_private_base_url": true
                }
            ],
            "routing": {
                "strategy": "cascade",
                "tiers": [
                    {
                        "provider_id": "first",
                        "model": "gpt-4o-mini",
                        "quality_threshold": 0.5
                    },
                    {
                        "provider_id": "second",
                        "model": "gpt-4o-mini",
                        "quality_threshold": 0.5
                    }
                ]
            }
        }))
        .expect("priced cascade fixture")
    }

    const CASCADE_LOSER_BODY: &str = r#"{"confidence_score":0.1,"choices":[{"message":{"content":"try another tier"}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#;
    const CASCADE_WINNER_BODY: &str = r#"{"confidence_score":1.0,"choices":[{"message":{"content":"accepted"}}],"usage":{"prompt_tokens":20,"completion_tokens":7,"total_tokens":27}}"#;

    #[tokio::test]
    async fn cascade_aggregates_discarded_attempt_usage_and_excludes_the_served_body() {
        let (first_url, first_request) = serve_one_json_response(CASCADE_LOSER_BODY).await;
        let (second_url, second_request) = serve_one_json_response(CASCADE_WINNER_BODY).await;
        let config = priced_two_tier_cascade_config(&first_url, &second_url);
        let cascade = config.router().cascade_config().cloned().expect("cascade");

        let outcome = AiClient::new()
            .forward_cascade_with_policy(
                &config,
                &cascade,
                &[],
                &[],
                "/v1/chat/completions",
                &serde_json::json!({"model": "gpt-4o-mini"}),
                &crate::attribution::AttributionTags::default(),
                "chat_completions",
            )
            .await
            .expect("second cascade tier is accepted");

        assert!(outcome.accepted);
        assert_eq!(outcome.provider_name, "second");
        assert_eq!(
            outcome.discarded_tokens, 15,
            "the discarded first tier's 10 prompt + 5 completion tokens must be reported"
        );
        assert_eq!(
            outcome.discarded_cost_usd,
            crate::budget::estimate_cost("gpt-4o-mini", 10, 5),
            "discarded spend is priced against the attempt's own model"
        );
        assert!(
            outcome.discarded_cost_usd > 0.0,
            "a priced model must produce a non-zero discarded cost, or this test proves nothing"
        );
        // The served body still reports its own usage, so the caller's
        // `discarded + body` sum is the whole cascade exactly once.
        assert_eq!(extract_usage_tokens(outcome.body.as_ref()), (20, 7));

        first_request.await.expect("first request captured");
        second_request.await.expect("second request captured");
    }

    #[tokio::test]
    async fn an_exhausted_cascade_does_not_count_the_returned_losers_own_usage() {
        // Both tiers score low, so the cascade runs out of tiers and
        // hands back the last loser as the response. That body is the
        // one the caller reconciles from, so counting it in
        // `discarded_tokens` too would charge it twice.
        let (first_url, first_request) = serve_one_json_response(CASCADE_LOSER_BODY).await;
        let (second_url, second_request) = serve_one_json_response(CASCADE_WINNER_BODY).await;
        let config = priced_two_tier_cascade_config(&first_url, &second_url);
        // Raise both thresholds above the winner body's 1.0 score so
        // neither tier can be accepted.
        let mut cascade = config.router().cascade_config().cloned().expect("cascade");
        for tier in &mut cascade.tiers {
            tier.quality_threshold = 2.0;
        }

        let outcome = AiClient::new()
            .forward_cascade_with_policy(
                &config,
                &cascade,
                &[],
                &[],
                "/v1/chat/completions",
                &serde_json::json!({"model": "gpt-4o-mini"}),
                &crate::attribution::AttributionTags::default(),
                "chat_completions",
            )
            .await
            .expect("an exhausted cascade returns its last attempt");

        assert!(!outcome.accepted);
        assert_eq!(outcome.provider_name, "second");
        assert_eq!(extract_usage_tokens(outcome.body.as_ref()), (20, 7));
        assert_eq!(
            outcome.discarded_tokens, 15,
            "only the earlier discarded tier counts; the returned body is the caller's to add"
        );

        first_request.await.expect("first request captured");
        second_request.await.expect("second request captured");
    }

    // --- Shadow supervisor tests ---
    //
    // These exercise the bounded-supervisor wrapper around
    // `run_shadow_request`. Each test drives a stand-in shadow future
    // through `tokio::time::timeout` plus the `ShadowSupervisor`
    // semaphore so the production cancellation + bookkeeping paths
    // are covered without needing a live HTTP server.

    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    fn shadow_handler_config(sample_rate: f32) -> AiHandlerConfig {
        AiHandlerConfig::from_config(serde_json::json!({
            "providers": [
                {
                    "name": "primary",
                    "api_key": "primary-test-key",
                    "base_url": "http://127.0.0.1:9/v1",
                    "allow_private_base_url": true
                },
                {
                    "name": "shadow",
                    "api_key": "shadow-test-key",
                    "base_url": "http://127.0.0.1:9/v1",
                    "allow_private_base_url": true
                }
            ],
            "shadow": {
                "provider": "shadow",
                "model": "shadow-model",
                "sample_rate": sample_rate,
                "timeout_ms": 50,
                "task_timeout_ms": 50
            }
        }))
        .expect("valid shadow handler fixture")
    }

    #[tokio::test]
    async fn quota_aware_shadow_does_not_charge_a_sampled_out_copy() {
        let store = Arc::new(RecordingQuotaStore::default());
        let quota_store: Arc<dyn crate::quota_pool::QuotaPoolStore> = store.clone();
        let admission = crate::quota_pool::QuotaPoolAdmission::new(
            Some(request_quota_config()),
            Ok(Some(quota_store)),
            Ok("virtual-key-a".to_string()),
        );

        let outcome = AiClient::new()
            .try_spawn_shadow_with_quota(
                &shadow_handler_config(0.0),
                "/v1/chat/completions",
                &serde_json::json!({"model": "primary-model"}),
                false,
                &[],
                &[],
                false,
                None,
                &admission,
                "request-1:quota-pool",
            )
            .await
            .expect("sampling out is not a quota failure");

        assert_eq!(outcome, vec![ShadowDispatchOutcome::SampledOut]);
        assert!(
            store
                .reservation_ids
                .lock()
                .expect("recording quota lock")
                .is_empty(),
            "a shadow suppressed before dispatch must not consume quota"
        );
    }

    #[tokio::test]
    async fn quota_aware_shadow_charges_immediately_before_spawn() {
        let (base_url, captured) =
            serve_one_json_response(r#"{"choices":[{"message":{"content":"ok"}}]}"#).await;
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [
                {"name": "primary", "api_key": "primary-test-key"},
                {
                    "name": "shadow",
                    "api_key": "shadow-test-key",
                    "base_url": base_url,
                    "allow_private_base_url": true
                }
            ],
            "shadow": {
                "provider": "shadow",
                "sample_rate": 1.0,
                "timeout_ms": 500,
                "task_timeout_ms": 500
            }
        }))
        .expect("valid shadow fixture");
        let store = Arc::new(RecordingQuotaStore::default());
        let quota_store: Arc<dyn crate::quota_pool::QuotaPoolStore> = store.clone();
        let admission = crate::quota_pool::QuotaPoolAdmission::new(
            Some(request_quota_config()),
            Ok(Some(quota_store)),
            Ok("virtual-key-a".to_string()),
        );

        let outcome = AiClient::new()
            .try_spawn_shadow_with_quota(
                &config,
                "/v1/chat/completions",
                &serde_json::json!({"model": "primary-model"}),
                false,
                &[],
                &[],
                false,
                None,
                &admission,
                "request-1:quota-pool",
            )
            .await
            .expect("quota admits shadow");

        assert_eq!(outcome, vec![ShadowDispatchOutcome::Spawned]);
        captured.await.expect("shadow request reached provider");
        // The trailing index is the target's position in
        // `shadow.targets`. The pool dedups by reservation id, so one
        // shared `:shadow` id across N targets would reserve a single
        // unit for N billable calls.
        assert_eq!(
            *store.reservation_ids.lock().expect("recording quota lock"),
            vec!["request-1:quota-pool:shadow:0".to_string()]
        );
        assert_eq!(
            *store.settled_ids.lock().expect("recording quota lock"),
            vec!["request-1:quota-pool:shadow:0".to_string()]
        );
    }

    #[tokio::test]
    async fn quota_aware_shadow_releases_when_local_header_construction_fails() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [
                {"name": "primary", "api_key": "primary-test-key"},
                {
                    "name": "shadow",
                    "api_key": "invalid\nheader",
                    "base_url": "http://127.0.0.1:9/v1",
                    "allow_private_base_url": true
                }
            ],
            "shadow": {
                "provider": "shadow",
                "sample_rate": 1.0,
                "timeout_ms": 500,
                "task_timeout_ms": 500
            }
        }))
        .expect("valid shadow fixture");
        let store = Arc::new(RecordingQuotaStore::default());
        let quota_store: Arc<dyn crate::quota_pool::QuotaPoolStore> = store.clone();
        let admission = crate::quota_pool::QuotaPoolAdmission::new(
            Some(request_quota_config()),
            Ok(Some(quota_store)),
            Ok("virtual-key-a".to_string()),
        );

        let outcome = AiClient::new()
            .try_spawn_shadow_with_quota(
                &config,
                "/v1/chat/completions",
                &serde_json::json!({"model": "primary-model"}),
                false,
                &[],
                &[],
                false,
                None,
                &admission,
                "request-local-shadow",
            )
            .await
            .expect("reservation succeeds before local shadow construction");

        assert_eq!(outcome, vec![ShadowDispatchOutcome::Spawned]);
        wait_for_quota_release(&store).await;
        assert_eq!(
            *store.released_ids.lock().expect("recording quota lock"),
            vec!["request-local-shadow:shadow:0".to_string()]
        );
        assert!(store
            .settled_ids
            .lock()
            .expect("recording quota lock")
            .is_empty());
    }

    fn shadow_usage_event(request_id: &str) -> LlmUsageEvent {
        LlmUsageEvent {
            provider: "primary".to_string(),
            model: "primary-model".to_string(),
            prompt_tokens: 1,
            completion_tokens: 1,
            total_tokens: 2,
            cost_usd: 1.0,
            latency_ms: 1,
            status: 200,
            key_id: None,
            tenant_id: None,
            project: None,
            user: None,
            team: None,
            tags: Vec::new(),
            metadata: std::collections::BTreeMap::new(),
            request_id: Some(request_id.to_string()),
            session_id: None,
            tag: None,
            priority: None,
            engine_version: None,
            agent_id: None,
            a2a_context_id: None,
            a2a_identity_verified: None,
            workflow_id: None,
            logical_model: None,
            served_model: None,
            finish_reason: None,
            shadow_of: None,
        }
    }

    fn shadow_result(status: u16, finish_reason: Option<&str>) -> ShadowCallResult {
        ShadowCallResult {
            status,
            latency_ms: 12,
            prompt_tokens: 3,
            completion_tokens: 4,
            finish_reason: finish_reason.map(str::to_string),
        }
    }

    /// Emit `count` rows from one `ShadowUsageRecord`, the way a
    /// multi-target request does: build once, clone per target.
    fn recorded_shadow_rows(count: usize) -> Vec<LlmUsageEvent> {
        let sink = Arc::new(CapturingUsageSink::default());
        let record = ShadowUsageRecord::new(
            shadow_usage_event("caller-id"),
            vec![sink.clone() as Arc<dyn UsageSink>],
        );
        for index in 0..count {
            record.clone().record(
                format!("target-{index}"),
                "m".to_string(),
                shadow_result(200, Some("stop")),
            );
        }
        let events = sink.events.lock().expect("capturing usage sink lock");
        events.clone()
    }

    #[test]
    fn shadow_usage_id_is_server_generated_and_cannot_collide_with_primary_id() {
        let rows = recorded_shadow_rows(1);
        let request_id = rows[0].request_id.clone().expect("shadow request id");

        assert_ne!(request_id, "caller-id:shadow");
        assert!(request_id.ends_with(":shadow"));
        assert_eq!(request_id.len(), 39);
        assert!(request_id[..32]
            .chars()
            .all(|character| character.is_ascii_hexdigit()));
    }

    #[test]
    fn each_shadow_target_row_gets_its_own_ledger_id() {
        // `ShadowUsageRecord` is built once per request and cloned per
        // target. Minting the id in `new` gave every clone the same
        // one, and that id is the verifiable ledger's dedup key: three
        // targets would collapse to one row on replay, silently, with
        // no test failing.
        let rows = recorded_shadow_rows(3);
        assert_eq!(rows.len(), 3);
        let ids: std::collections::BTreeSet<_> = rows
            .iter()
            .map(|row| row.request_id.clone().expect("shadow request id"))
            .collect();
        assert_eq!(ids.len(), 3, "each target row needs its own dedup key");
    }

    #[test]
    fn shadow_row_carries_shadow_of_but_never_derives_its_id_from_it() {
        let rows = recorded_shadow_rows(2);
        for row in &rows {
            assert_eq!(
                row.shadow_of.as_deref(),
                Some("caller-id"),
                "shadow_of is the join key back to the primary row"
            );
            let request_id = row.request_id.as_deref().expect("shadow request id");
            assert!(
                !request_id.contains("caller-id"),
                "the correlation-id feature lets a caller pick the primary's \
                 request id, so a derived shadow id would let one caller \
                 suppress another's rows on ledger replay: {request_id}"
            );
        }
    }

    #[test]
    fn a_targets_finish_reason_is_bounded_before_it_reaches_a_row() {
        // The string is copied out of the target's response body and
        // now lands on a durable ledger row, so a target that answers
        // with a very long finish reason must not be able to size that
        // row. Multi-byte on purpose: truncating mid-character would
        // panic on the slice.
        let long = "\u{00e9}".repeat(4096);
        let body = serde_json::json!({
            "choices": [{"finish_reason": long}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        })
        .to_string();
        let (_, _, finish) = parse_shadow_metadata(body.as_bytes());
        let finish = finish.expect("a finish reason was present");
        assert!(
            finish.len() <= MAX_SHADOW_FINISH_REASON_BYTES,
            "finish reason kept {} bytes",
            finish.len()
        );
        assert!(finish.chars().all(|c| c == '\u{00e9}'));

        let (_, _, finish) = parse_shadow_metadata(
            serde_json::json!({"choices": [{"finish_reason": "content_filter"}]})
                .to_string()
                .as_bytes(),
        );
        assert_eq!(
            finish.as_deref(),
            Some("content_filter"),
            "the longest legitimate value must survive intact"
        );
    }

    #[test]
    fn shadow_finish_reason_reaches_the_usage_row() {
        // Parsed by `parse_shadow_metadata` since the feature shipped
        // and then dropped on the floor. A target that stopped on
        // `length` where the primary stopped on `stop` truncated, and
        // no cost or latency comparison says so.
        let sink = Arc::new(CapturingUsageSink::default());
        let record = ShadowUsageRecord::new(
            shadow_usage_event("caller-id"),
            vec![sink.clone() as Arc<dyn UsageSink>],
        );
        record.record(
            "anthropic".to_string(),
            "claude".to_string(),
            shadow_result(200, Some("length")),
        );
        let events = sink.events.lock().expect("capturing usage sink lock");
        assert_eq!(events[0].finish_reason.as_deref(), Some("length"));
        assert_eq!(events[0].tag.as_deref(), Some("shadow"));
    }

    #[test]
    fn shadow_usage_carries_neither_serving_lane() {
        // WOR-2223: the shadow copy inherits the primary's context. Left
        // alone, a shadow of a locally served request would land in the
        // value report as a second local completion, and a shadow of a
        // spilled one as a second cloud spill.
        let mut primary = shadow_usage_event("caller-id");
        primary.logical_model = Some("qwen3-14b".to_string());
        primary.served_model = Some("qwen3-14b".to_string());

        let usage = ShadowUsageRecord::new(primary, Vec::new());

        assert_eq!(usage.event.logical_model, None);
        assert_eq!(usage.event.served_model, None);
    }

    #[test]
    fn shadow_response_metadata_buffer_is_bounded() {
        let mut buffer = vec![b'a'; MAX_SHADOW_RESPONSE_METADATA_BYTES - 2];

        let truncated = append_shadow_response_metadata(&mut buffer, b"bcdef");

        assert!(truncated);
        assert_eq!(buffer.len(), MAX_SHADOW_RESPONSE_METADATA_BYTES);
        assert!(buffer.ends_with(b"bc"));
    }

    #[tokio::test]
    async fn shadow_dispatch_applies_the_shadow_providers_model_map() {
        let (base_url, captured) =
            serve_one_json_response(r#"{"usage":{"prompt_tokens":1,"completion_tokens":1}}"#).await;
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [
                {
                    "name": "primary",
                    "api_key": "primary-test-key"
                },
                {
                    "name": "shadow",
                    "api_key": "shadow-test-key",
                    "base_url": base_url,
                    "allow_private_base_url": true,
                    "model_map": {"shadow-model": "upstream-shadow-model"}
                }
            ],
            "shadow": {
                "provider": "shadow",
                "model": "shadow-model",
                "sample_rate": 1.0,
                "timeout_ms": 500,
                "task_timeout_ms": 500
            }
        }))
        .expect("valid mapped shadow fixture");
        let client = AiClient::with_shadow_supervisor(Arc::new(ShadowSupervisor::new(1)));

        let outcome = client.try_spawn_shadow(
            &config,
            "/v1/chat/completions",
            &serde_json::json!({"model": "primary-model"}),
            false,
            &[],
            &[],
            false,
            None,
        );

        assert_eq!(outcome, vec![ShadowDispatchOutcome::Spawned]);
        let request = captured.await.expect("test provider task");
        let request_text = String::from_utf8(request).expect("HTTP request is UTF-8");
        let body = request_text.split_once("\r\n\r\n").expect("HTTP body").1;
        let body: serde_json::Value = serde_json::from_str(body).expect("JSON request body");
        assert_eq!(body["model"], "upstream-shadow-model");
    }

    #[test]
    fn shadow_preserves_pre_compression_code_bypass() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [
                {"name": "primary", "api_key": "primary-test-key"},
                {
                    "name": "shadow",
                    "provider_type": "openai",
                    "api_key": "shadow-test-key",
                    "base_url": "http://127.0.0.1:9/v1",
                    "allow_private_base_url": true
                }
            ],
            "reasoning": "concise",
            "shadow": {
                "provider": "shadow",
                "model": "gpt-5-mini",
                "sample_rate": 1.0,
                "timeout_ms": 50,
                "task_timeout_ms": 50
            }
        }))
        .expect("valid reasoning shadow fixture");
        let original = serde_json::json!({
            "model": "gpt-5-mini",
            "messages": [{
                "role": "user",
                "content": "Implement fn parse(input: &str) -> Result<Value, Error>."
            }]
        });
        let eligibility = crate::reasoning::reasoning_eligibility(&original);
        let compressed = serde_json::json!({
            "model": "gpt-5-mini",
            "messages": [{"role": "user", "content": "Implement the parser."}]
        });
        let client = AiClient::with_shadow_supervisor(Arc::new(ShadowSupervisor::new(1)));

        let prepared = client
            .prepare_shadows(
                &config,
                "/v1/chat/completions",
                &compressed,
                false,
                &[],
                &[],
                false,
                None,
                Some(eligibility),
            )
            .expect("the request-level gates admit this request")
            .pop()
            .expect("one configured target")
            .expect("shadow is admitted");

        assert_eq!(prepared.reasoning_outcome, "code_bypass");
        assert!(prepared.body.get("reasoning_effort").is_none());
        assert_eq!(prepared.body["messages"], compressed["messages"]);
    }

    fn multi_target_handler_config(targets: serde_json::Value) -> AiHandlerConfig {
        AiHandlerConfig::from_config(serde_json::json!({
            "providers": [
                {
                    "name": "primary",
                    "api_key": "primary-test-key",
                    "base_url": "http://127.0.0.1:9/v1",
                    "allow_private_base_url": true
                },
                {
                    "name": "shadow-a",
                    "api_key": "a-test-key",
                    "base_url": "http://127.0.0.1:9/v1",
                    "allow_private_base_url": true
                },
                {
                    "name": "shadow-b",
                    "api_key": "b-test-key",
                    "base_url": "http://127.0.0.1:9/v1",
                    "allow_private_base_url": true
                },
                {
                    "name": "shadow-c",
                    "api_key": "c-test-key",
                    "base_url": "http://127.0.0.1:9/v1",
                    "allow_private_base_url": true
                }
            ],
            "shadow": {"targets": targets}
        }))
        .expect("valid multi-target shadow fixture")
    }

    #[tokio::test]
    async fn two_shadow_targets_share_one_admission_ceiling() {
        // The supervisor's task and memory ceilings are process-wide
        // bounds on how much optional work a gateway will carry. If
        // admission ran once per request rather than once per target,
        // an operator could multiply that bound by editing a config
        // list, which is exactly the thing the supervisor exists to
        // stop. With three targets and two slots, the third is dropped
        // as saturated.
        let _metric_guard = SHADOW_METRIC_TEST_LOCK.lock().await;
        let client = AiClient::with_shadow_supervisor(Arc::new(ShadowSupervisor::new(2)));
        let config = multi_target_handler_config(serde_json::json!([
            {"provider": "shadow-a", "timeout_ms": 50, "task_timeout_ms": 50},
            {"provider": "shadow-b", "timeout_ms": 50, "task_timeout_ms": 50},
            {"provider": "shadow-c", "timeout_ms": 50, "task_timeout_ms": 50},
        ]));
        let before = ai_metrics::shadow_dropped_value(ai_metrics::ShadowDropReason::Saturated);

        let outcomes = client.try_spawn_shadow(
            &config,
            "/v1/chat/completions",
            &serde_json::json!({"model": "primary-model"}),
            false,
            &[],
            &[],
            false,
            None,
        );

        assert_eq!(
            outcomes,
            vec![
                ShadowDispatchOutcome::Spawned,
                ShadowDispatchOutcome::Spawned,
                ShadowDispatchOutcome::Saturated,
            ]
        );
        assert_eq!(
            ai_metrics::shadow_dropped_value(ai_metrics::ShadowDropReason::Saturated) - before,
            1.0,
            "exactly one target is dropped, not the whole request"
        );
    }

    #[tokio::test]
    async fn one_sampling_draw_nests_target_populations() {
        // Independent per-target draws would give disjoint populations,
        // and two targets measured on different requests are not
        // comparable, which is the only reason to run two. One draw per
        // request, compared against each rate, makes the 0.1 target's
        // population a strict subset of the 0.5 target's, so the two
        // are comparable on the smaller one's whole population.
        // Capacity zero, so a target that clears sampling is refused at
        // the next gate and never spawns a task. Sampling is the only
        // thing under test here, and 500 spawned background calls would
        // otherwise exhaust any finite supervisor partway through the
        // loop and turn a later `Spawned` into a `Saturated` that reads
        // exactly like "this target did not fire".
        //
        // The metric lock is held even though this test asserts on no
        // metric: capacity zero means every sampled target is refused
        // as `saturated`, so the loop bumps
        // `sbproxy_ai_shadow_dropped_total{reason="saturated"}` a few
        // hundred times, and two sibling tests assert an exact delta of
        // one on that process-global series.
        let _metric_guard = SHADOW_METRIC_TEST_LOCK.lock().await;
        let client = AiClient::with_shadow_supervisor(Arc::new(ShadowSupervisor::new(0)));
        let config = multi_target_handler_config(serde_json::json!([
            {"provider": "shadow-a", "sample_rate": 0.1, "timeout_ms": 50, "task_timeout_ms": 50},
            {"provider": "shadow-b", "sample_rate": 0.5, "timeout_ms": 50, "task_timeout_ms": 50},
        ]));

        let mut narrow_fired = 0_u32;
        let mut wide_fired = 0_u32;
        for _ in 0..500 {
            let outcomes = client.try_spawn_shadow(
                &config,
                "/v1/chat/completions",
                &serde_json::json!({"model": "primary-model"}),
                false,
                &[],
                &[],
                false,
                None,
            );
            assert_eq!(outcomes.len(), 2);
            let narrow = outcomes[0] != ShadowDispatchOutcome::SampledOut;
            let wide = outcomes[1] != ShadowDispatchOutcome::SampledOut;
            assert!(
                !narrow || wide,
                "the 0.1 target fired on a request the 0.5 target skipped; \
                 the populations are disjoint, not nested"
            );
            narrow_fired += u32::from(narrow);
            wide_fired += u32::from(wide);
        }
        // Loose bounds, because this is a real RNG. The nesting
        // assertion above is the exact one; these only catch a rate
        // that stopped being honored at all.
        assert!(narrow_fired > 0, "the 0.1 target never fired in 500 draws");
        assert!(
            wide_fired > narrow_fired,
            "a 0.5 rate must fire more often than a 0.1 rate: \
             {wide_fired} vs {narrow_fired}"
        );
        assert!(
            wide_fired < 500,
            "a 0.5 rate must not fire on every request: {wide_fired}"
        );
    }

    #[tokio::test]
    async fn every_shadow_target_records_its_own_call_metric() {
        let _metric_guard = SHADOW_METRIC_TEST_LOCK.lock().await;
        let (url_a, _a) = serve_one_json_response(
            r#"{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"a"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
        )
        .await;
        let (url_b, _b) = serve_one_json_response(
            r#"{"choices":[{"finish_reason":"length","message":{"role":"assistant","content":"b"}}],"usage":{"prompt_tokens":1,"completion_tokens":9,"total_tokens":10}}"#,
        )
        .await;
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [
                {"name": "primary", "api_key": "k", "base_url": "http://127.0.0.1:9/v1", "allow_private_base_url": true},
                {"name": "shadow-a", "api_key": "k", "base_url": url_a, "allow_private_base_url": true},
                {"name": "shadow-b", "api_key": "k", "base_url": url_b, "allow_private_base_url": true},
            ],
            "shadow": {"targets": [
                {"provider": "shadow-a", "timeout_ms": 2000, "task_timeout_ms": 2000},
                {"provider": "shadow-b", "timeout_ms": 2000, "task_timeout_ms": 2000},
            ]}
        }))
        .expect("valid two-target shadow fixture");
        let before_a = ai_metrics::shadow_calls_value("shadow-a", "2xx", "stop");
        let before_b = ai_metrics::shadow_calls_value("shadow-b", "2xx", "length");

        let client = AiClient::with_shadow_supervisor(Arc::new(ShadowSupervisor::new(4)));
        let outcomes = client.try_spawn_shadow(
            &config,
            "/v1/chat/completions",
            &serde_json::json!({"model": "primary-model"}),
            false,
            &[],
            &[],
            false,
            None,
        );
        assert_eq!(
            outcomes,
            vec![
                ShadowDispatchOutcome::Spawned,
                ShadowDispatchOutcome::Spawned
            ]
        );

        // The tasks are detached; poll the counters rather than sleep a
        // fixed amount, so a slow machine does not make this flaky.
        for _ in 0..200 {
            if ai_metrics::shadow_calls_value("shadow-a", "2xx", "stop") - before_a >= 1.0
                && ai_metrics::shadow_calls_value("shadow-b", "2xx", "length") - before_b >= 1.0
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!(
            "both targets must record their own call: a={} b={}",
            ai_metrics::shadow_calls_value("shadow-a", "2xx", "stop") - before_a,
            ai_metrics::shadow_calls_value("shadow-b", "2xx", "length") - before_b,
        );
    }

    #[tokio::test]
    async fn shadow_dispatch_boundary_rejects_non_chat_paths() {
        let client = AiClient::with_shadow_supervisor(Arc::new(ShadowSupervisor::new(1)));

        let outcome = client.try_spawn_shadow(
            &shadow_handler_config(1.0),
            "/v1/assistants",
            &serde_json::json!({"model": "primary-model"}),
            false,
            &[],
            &[],
            false,
            None,
        );

        assert_eq!(outcome, vec![ShadowDispatchOutcome::UnsupportedSurface]);
        assert_eq!(client.shadow_supervisor().available(), 1);
    }

    #[tokio::test]
    async fn shadow_dispatch_skips_streaming_without_admission() {
        let _metric_guard = SHADOW_METRIC_TEST_LOCK.lock().await;
        let client = AiClient::with_shadow_supervisor(Arc::new(ShadowSupervisor::new(1)));
        let outcome = client.try_spawn_shadow(
            &shadow_handler_config(1.0),
            "/v1/chat/completions",
            &serde_json::json!({"model": "primary-model", "stream": true}),
            true,
            &[],
            &[],
            false,
            None,
        );

        assert_eq!(outcome, vec![ShadowDispatchOutcome::StreamingSkipped]);
        assert_eq!(client.shadow_supervisor().available(), 1);
    }

    #[tokio::test]
    async fn shadow_dispatch_sampling_out_is_not_a_failed_admission() {
        let _metric_guard = SHADOW_METRIC_TEST_LOCK.lock().await;
        let client = AiClient::with_shadow_supervisor(Arc::new(ShadowSupervisor::new(1)));
        let outcome = client.try_spawn_shadow(
            &shadow_handler_config(0.0),
            "/v1/chat/completions",
            &serde_json::json!({"model": "primary-model"}),
            false,
            &[],
            &[],
            false,
            None,
        );

        assert_eq!(outcome, vec![ShadowDispatchOutcome::SampledOut]);
        assert_eq!(client.shadow_supervisor().available(), 1);
    }

    #[tokio::test]
    async fn shadow_dispatch_honors_credential_provider_policy() {
        let _metric_guard = SHADOW_METRIC_TEST_LOCK.lock().await;
        let client = AiClient::with_shadow_supervisor(Arc::new(ShadowSupervisor::new(1)));
        let outcome = client.try_spawn_shadow(
            &shadow_handler_config(1.0),
            "/v1/chat/completions",
            &serde_json::json!({"model": "primary-model"}),
            false,
            &["primary".to_string()],
            &[],
            false,
            None,
        );

        assert_eq!(outcome, vec![ShadowDispatchOutcome::ProviderNotAllowed]);
        assert_eq!(client.shadow_supervisor().available(), 1);
    }

    #[tokio::test]
    async fn shadow_dispatch_honors_prompt_training_opt_out() {
        let _metric_guard = SHADOW_METRIC_TEST_LOCK.lock().await;
        let client = AiClient::with_shadow_supervisor(Arc::new(ShadowSupervisor::new(1)));
        let dropped_before = ai_metrics::shadow_dropped_value(
            ai_metrics::ShadowDropReason::PromptTrainingDisallowed,
        );
        let outcome = client.try_spawn_shadow(
            &shadow_handler_config(1.0),
            "/v1/chat/completions",
            &serde_json::json!({"model": "primary-model"}),
            false,
            &[],
            &[],
            true,
            None,
        );

        assert_eq!(
            outcome,
            vec![ShadowDispatchOutcome::PromptTrainingDisallowed]
        );
        assert!(
            ai_metrics::shadow_dropped_value(
                ai_metrics::ShadowDropReason::PromptTrainingDisallowed
            ) - dropped_before
                >= 1.0
        );
        assert_eq!(client.shadow_supervisor().available(), 1);
    }

    #[tokio::test]
    async fn prompt_training_opt_out_allows_a_compliant_shadow_provider() {
        let mut config = shadow_handler_config(1.0);
        config
            .providers
            .iter_mut()
            .find(|provider| provider.name == "shadow")
            .expect("shadow provider")
            .no_prompt_training = true;
        let client = AiClient::with_shadow_supervisor(Arc::new(ShadowSupervisor::new(1)));

        let outcome = client.try_spawn_shadow(
            &config,
            "/v1/chat/completions",
            &serde_json::json!({"model": "primary-model"}),
            false,
            &[],
            &[],
            true,
            None,
        );

        assert_eq!(outcome, vec![ShadowDispatchOutcome::Spawned]);
    }

    #[tokio::test]
    async fn shadow_dispatch_records_each_closed_drop_reason_exactly_once() {
        let _metric_guard = SHADOW_METRIC_TEST_LOCK.lock().await;
        // The canonical list, not a copy of it: a hand-written array
        // here compiled fine when a variant was added and quietly
        // stopped covering it.
        let reasons = ai_metrics::ALL_SHADOW_DROP_REASONS;
        let snapshot = || reasons.map(ai_metrics::shadow_dropped_value);

        let before_sampling = snapshot();
        assert_eq!(
            AiClient::new().try_spawn_shadow(
                &shadow_handler_config(0.0),
                "/v1/chat/completions",
                &serde_json::json!({"model": "primary-model"}),
                false,
                &[],
                &[],
                false,
                None,
            ),
            vec![ShadowDispatchOutcome::SampledOut]
        );
        assert_eq!(snapshot(), before_sampling, "sampling is not a drop");

        let assert_one_increment = |before: [f64; 6], reason: ai_metrics::ShadowDropReason| {
            let after = snapshot();
            for (index, candidate) in reasons.iter().enumerate() {
                let expected = if *candidate == reason { 1.0 } else { 0.0 };
                assert_eq!(
                    after[index] - before[index],
                    expected,
                    "unexpected increment for {} while exercising {}",
                    candidate.as_str(),
                    reason.as_str()
                );
            }
        };

        let client = AiClient::new();
        let before = snapshot();
        assert_eq!(
            client.try_spawn_shadow(
                &shadow_handler_config(1.0),
                "/v1/chat/completions",
                &serde_json::json!({"model": "primary-model", "stream": true}),
                true,
                &[],
                &[],
                false,
                None,
            ),
            vec![ShadowDispatchOutcome::StreamingSkipped]
        );
        assert_one_increment(before, ai_metrics::ShadowDropReason::Streaming);

        let mut missing = shadow_handler_config(1.0);
        missing.shadow.as_mut().expect("shadow config").targets[0].provider = "missing".to_string();
        let before = snapshot();
        assert_eq!(
            client.try_spawn_shadow(
                &missing,
                "/v1/chat/completions",
                &serde_json::json!({"model": "primary-model"}),
                false,
                &[],
                &[],
                false,
                None,
            ),
            vec![ShadowDispatchOutcome::ProviderNotFound]
        );
        assert_one_increment(before, ai_metrics::ShadowDropReason::ProviderNotFound);

        let before = snapshot();
        assert_eq!(
            client.try_spawn_shadow(
                &shadow_handler_config(1.0),
                "/v1/chat/completions",
                &serde_json::json!({"model": "primary-model"}),
                false,
                &["primary".to_string()],
                &[],
                false,
                None,
            ),
            vec![ShadowDispatchOutcome::ProviderNotAllowed]
        );
        assert_one_increment(before, ai_metrics::ShadowDropReason::ProviderNotAllowed);

        let before = snapshot();
        assert_eq!(
            client.try_spawn_shadow(
                &shadow_handler_config(1.0),
                "/v1/chat/completions",
                &serde_json::json!({"model": "primary-model"}),
                false,
                &[],
                &[],
                true,
                None,
            ),
            vec![ShadowDispatchOutcome::PromptTrainingDisallowed]
        );
        assert_one_increment(
            before,
            ai_metrics::ShadowDropReason::PromptTrainingDisallowed,
        );

        let egress_client = AiClient::new().with_egress(enforce_ai_provider(&["api.openai.com"]));
        let before = snapshot();
        assert_eq!(
            egress_client.try_spawn_shadow(
                &shadow_handler_config(1.0),
                "/v1/chat/completions",
                &serde_json::json!({"model": "primary-model"}),
                false,
                &[],
                &[],
                false,
                None,
            ),
            vec![ShadowDispatchOutcome::EgressDenied]
        );
        assert_one_increment(before, ai_metrics::ShadowDropReason::EgressDenied);

        let supervisor = Arc::new(ShadowSupervisor::new(1));
        let saturated_client = AiClient::with_shadow_supervisor(supervisor.clone());
        let held = supervisor.try_admit().expect("reserve the only slot");
        let before = snapshot();
        assert_eq!(
            saturated_client.try_spawn_shadow(
                &shadow_handler_config(1.0),
                "/v1/chat/completions",
                &serde_json::json!({"model": "primary-model"}),
                false,
                &[],
                &[],
                false,
                None,
            ),
            vec![ShadowDispatchOutcome::Saturated]
        );
        assert_one_increment(before, ai_metrics::ShadowDropReason::Saturated);
        drop(held);
    }

    #[tokio::test]
    async fn shadow_dispatch_drops_when_bounded_admission_is_saturated() {
        let _metric_guard = SHADOW_METRIC_TEST_LOCK.lock().await;
        let supervisor = Arc::new(ShadowSupervisor::new(1));
        let client = AiClient::with_shadow_supervisor(supervisor.clone());
        let held = supervisor.try_admit().expect("reserve the only slot");
        let dropped_before =
            ai_metrics::shadow_dropped_value(ai_metrics::ShadowDropReason::Saturated);

        let outcome = client.try_spawn_shadow(
            &shadow_handler_config(1.0),
            "/v1/chat/completions",
            &serde_json::json!({"model": "primary-model"}),
            false,
            &[],
            &[],
            false,
            None,
        );

        assert_eq!(outcome, vec![ShadowDispatchOutcome::Saturated]);
        assert!(
            ai_metrics::shadow_dropped_value(ai_metrics::ShadowDropReason::Saturated)
                - dropped_before
                >= 1.0
        );
        drop(held);
    }

    #[tokio::test]
    async fn shadow_admission_reserves_a_process_wide_memory_budget() {
        let _metric_guard = SHADOW_METRIC_TEST_LOCK.lock().await;
        let one_task_bytes = MAX_SHADOW_RESPONSE_METADATA_BYTES * 2 + 16;
        let supervisor = ShadowSupervisor::with_memory_budget(8, one_task_bytes);
        let first = supervisor
            .try_admit_request(8)
            .expect("first request fits the byte budget");
        assert_eq!(supervisor.available_memory_bytes(), 0);
        let dropped_before =
            ai_metrics::shadow_dropped_value(ai_metrics::ShadowDropReason::Saturated);

        assert!(
            supervisor.try_admit_request(8).is_none(),
            "a free task slot must not bypass the byte budget"
        );
        assert_eq!(
            ai_metrics::shadow_dropped_value(ai_metrics::ShadowDropReason::Saturated)
                - dropped_before,
            1.0
        );

        drop(first);
        assert_eq!(supervisor.available_memory_bytes(), one_task_bytes);
        assert!(
            supervisor.try_admit_request(8).is_some(),
            "dropping the task must return both admission resources"
        );
    }

    #[tokio::test]
    async fn shadow_supervisor_succeeds_within_timeout() {
        // Note: the shadow_dropped_total and shadow_timeout_total
        // counters are process-wide LazyLock prometheus statics, so
        // concurrent tests in this module will tick them too. We only
        // assert this test's local supervisor + inflight permit
        // bookkeeping, not the global counter values.
        let supervisor = ShadowSupervisor::new(8);
        let counter = Arc::new(AtomicU64::new(0));

        let permit = supervisor.try_admit().expect("queue has room");
        let counter_in = counter.clone();
        let task = tokio::spawn(async move {
            let _permit = permit;
            let _gauge = ShadowInflightGuard::enter();
            let res = tokio::time::timeout(Duration::from_millis(500), async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                counter_in.fetch_add(1, AtomicOrdering::SeqCst);
            })
            .await;
            assert!(res.is_ok(), "fast shadow future should not time out");
        });
        task.await.unwrap();

        assert_eq!(counter.load(AtomicOrdering::SeqCst), 1);
        // Permit dropped: full queue width restored.
        assert_eq!(supervisor.available(), 8);
    }

    #[tokio::test]
    async fn shadow_supervisor_records_timeout_when_future_hangs() {
        let _metric_guard = SHADOW_METRIC_TEST_LOCK.lock().await;
        let supervisor = ShadowSupervisor::new(4);
        let timeout_before = ai_metrics::shadow_timeout_value();

        let permit = supervisor.try_admit().expect("queue has room");
        let task = tokio::spawn(async move {
            let _permit = permit;
            let _gauge = ShadowInflightGuard::enter();
            // The supervisor timeout is 50ms; the inner future sleeps
            // for 5s. tokio::time::timeout must drop the inner future
            // and the supervisor must tick the timeout counter.
            let res = tokio::time::timeout(Duration::from_millis(50), async {
                tokio::time::sleep(Duration::from_secs(5)).await;
            })
            .await;
            if res.is_err() {
                ai_metrics::record_shadow_timeout();
            }
            assert!(res.is_err(), "slow future should time out");
        });
        task.await.unwrap();

        assert_eq!(supervisor.available(), 4);
        assert!(
            ai_metrics::shadow_timeout_value() - timeout_before >= 1.0,
            "shadow_timeout_total should have ticked"
        );
    }

    #[tokio::test]
    async fn shadow_supervisor_drops_request_when_queue_full() {
        let _metric_guard = SHADOW_METRIC_TEST_LOCK.lock().await;
        let supervisor = ShadowSupervisor::new(2);
        let dropped_before =
            ai_metrics::shadow_dropped_value(ai_metrics::ShadowDropReason::Saturated);

        // Fill every slot. Hold the permits across the test so the
        // semaphore stays at zero.
        let p1 = supervisor.try_admit().expect("first admit ok");
        let p2 = supervisor.try_admit().expect("second admit ok");
        assert_eq!(supervisor.available(), 0);

        // Third try must return None and tick the dropped counter.
        let denied = supervisor.try_admit();
        assert!(denied.is_none(), "queue must reject when full");
        assert!(
            ai_metrics::shadow_dropped_value(ai_metrics::ShadowDropReason::Saturated)
                - dropped_before
                >= 1.0,
            "shadow_dropped_total should have ticked"
        );

        // Releasing one slot lets a new request in again.
        drop(p1);
        let p3 = supervisor.try_admit().expect("admit after release");
        drop(p2);
        drop(p3);
        assert_eq!(supervisor.available(), 2);
    }

    #[tokio::test]
    async fn production_shadow_timeout_emits_a_failed_usage_event() {
        let _metric_guard = SHADOW_METRIC_TEST_LOCK.lock().await;
        let (base_url, hanging_provider) = serve_one_hanging_response().await;
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [
                {"name": "primary", "api_key": "primary-test-key"},
                {
                    "name": "shadow",
                    "api_key": "shadow-test-key",
                    "base_url": base_url,
                    "allow_private_base_url": true
                }
            ],
            "shadow": {
                "provider": "shadow",
                "model": "gpt-4o",
                "sample_rate": 1.0,
                "timeout_ms": 5000,
                "task_timeout_ms": 25
            }
        }))
        .expect("valid timeout fixture");
        let sink = Arc::new(CapturingUsageSink::default());
        let usage = ShadowUsageRecord::new(
            shadow_usage_event("caller-controlled"),
            vec![sink.clone() as Arc<dyn UsageSink>],
        );
        let timeout_before = ai_metrics::shadow_timeout_value();

        assert_eq!(
            AiClient::new().try_spawn_shadow(
                &config,
                "/v1/chat/completions",
                &serde_json::json!({"model": "gpt-4o"}),
                false,
                &[],
                &[],
                false,
                Some(usage),
            ),
            vec![ShadowDispatchOutcome::Spawned]
        );

        let event = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(event) = sink
                    .events
                    .lock()
                    .expect("capturing usage sink lock")
                    .first()
                    .cloned()
                {
                    break event;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("shadow timeout usage event");
        hanging_provider.abort();

        assert_eq!(ai_metrics::shadow_timeout_value() - timeout_before, 1.0);
        assert_eq!(event.provider, "shadow");
        assert_eq!(event.model, "gpt-4o");
        assert_eq!(event.status, 504);
        assert_eq!(event.total_tokens, 0);
        assert_eq!(event.tag.as_deref(), Some("shadow"));
        assert_ne!(
            event.request_id.as_deref(),
            Some("caller-controlled:shadow")
        );
    }

    /// Test resolver mapping a host to fixed addresses. Production
    /// paths pass `CachedSystemResolver`; a fixture resolver belongs
    /// only here, where the fixture is the thing under test.
    struct MapResolver {
        map: std::collections::HashMap<String, Vec<std::net::SocketAddr>>,
    }

    impl MapResolver {
        fn new(entries: Vec<(&str, Vec<std::net::SocketAddr>)>) -> Self {
            Self {
                map: entries
                    .into_iter()
                    .map(|(h, a)| (h.to_string(), a))
                    .collect(),
            }
        }
    }

    impl HostResolver for MapResolver {
        fn resolve(&self, host: &str, _port: u16) -> Result<Vec<std::net::SocketAddr>, ()> {
            self.map.get(host).cloned().ok_or(())
        }
    }

    fn public_addr(port: u16) -> std::net::SocketAddr {
        std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34)),
            port,
        )
    }

    fn enforce_ai_provider(hosts: &[&str]) -> EgressAuthorizer {
        use sbproxy_security::egress::{EgressConfig, PurposeAllowlist};
        use std::collections::HashMap;
        let mut allow = PurposeAllowlist::default();
        for h in hosts {
            allow.hosts.insert((*h).to_string());
        }
        allow.schemes.insert("https".to_string());
        allow.schemes.insert("http".to_string());
        allow.ports.insert(443);
        allow.ports.insert(80);
        let mut purposes = HashMap::new();
        purposes.insert(EgressPurpose::AiProvider, allow);
        EgressAuthorizer::new(EgressConfig { purposes })
    }

    #[test]
    fn provider_egress_denies_unlisted_host_with_closed_vocabulary() {
        let client = AiClient::new().with_egress(enforce_ai_provider(&["api.openai.com"]));
        let resolver = MapResolver::new(vec![("evil.example", vec![public_addr(443)])]);
        let err = client
            .authorize_provider_url("https://evil.example/v1/chat", &resolver)
            .expect_err("unlisted host must be denied");
        assert_eq!(err, EgressDenied::UnlistedHost);
        assert!(!format!("{err:?}").contains("evil.example"));
    }

    #[test]
    fn provider_egress_denies_an_allowlisted_host_that_resolves_internal() {
        // The old fixed synthetic resolver returned a public address for
        // every host, so `allow_private` could not fire and this whole
        // class of denial was unreachable. With a live answer it is the
        // first thing the gate catches.
        let client = AiClient::new().with_egress(enforce_ai_provider(&["api.internal.test"]));
        let resolver = MapResolver::new(vec![(
            "api.internal.test",
            vec![std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(169, 254, 169, 254)),
                443,
            )],
        )]);
        assert_eq!(
            client
                .authorize_provider_url("https://api.internal.test/v1", &resolver)
                .unwrap_err(),
            EgressDenied::PrivateAddress
        );
    }

    #[test]
    fn omitted_egress_preserves_legacy_provider_compatibility() {
        let client = AiClient::new();
        let resolver = MapResolver::new(vec![]);
        client
            .authorize_provider_url("https://evil.example/v1/chat", &resolver)
            .expect("omitted egress must not deny, and must not even resolve");
    }

    #[test]
    fn enforce_egress_fails_closed_for_unlisted_purpose_host() {
        let client = AiClient::new().with_egress(enforce_ai_provider(&["api.openai.com"]));
        let resolver = MapResolver::new(vec![("api.anthropic.com", vec![public_addr(443)])]);
        assert_eq!(
            client
                .authorize_provider_url("https://api.anthropic.com/v1", &resolver)
                .unwrap_err(),
            EgressDenied::UnlistedHost
        );
    }

    #[test]
    fn ungated_provider_url_is_recorded_in_the_egress_inventory() {
        // WOR-2476: a client with no authorizer attached must still stamp
        // the destination into the egress inventory, with an honest
        // "ungated" status rather than silently skipping the record.
        use sbproxy_security::egress::egress_inventory_snapshot;
        let client = AiClient::new();
        client
            .gate_provider_url(
                "http://ungated-sighting-test.invalid:9099/v1",
                "test-provider",
            )
            .expect("no authorizer attached; gate must not deny");
        let snapshot = egress_inventory_snapshot();
        let sighting = snapshot
            .iter()
            .find(|s| s.host == "ungated-sighting-test.invalid")
            .expect("ungated sighting must be present in the inventory");
        assert_eq!(sighting.status, "ungated");
    }

    #[test]
    fn configured_gate_registry_arms_the_client_and_the_dispatch_is_stamped_denied() {
        // WOR-2476: proves the seam `sbproxy_core::server::reload_ai_client`
        // uses to arm the client from a compiled `egress.ai_providers:
        // { mode: deny_by_default }` block (empty `hosts:`, exactly the
        // brief's acceptance shape). `sbproxy-ai` cannot depend on
        // `sbproxy-core` to call `reload_ai_client` itself, so this
        // reproduces its one-line composition: read the process-wide
        // `EgressPurpose::AiProvider` gate, attach it via `with_egress`
        // when present. A real provider dispatch through the resulting
        // client must be refused, before any I/O, and the refusal must
        // land in the (cross-crate, publicly readable) egress inventory
        // as `denied`, not silently dropped.
        use sbproxy_security::egress::{
            configured_gate, egress_inventory_snapshot, install_configured_gate, EgressConfig,
            PurposeAllowlist,
        };
        use std::collections::{HashMap, HashSet};

        // Mirrors exactly what `compile_egress_gates` builds for
        // `egress.ai_providers: { mode: deny_by_default }` with no
        // `hosts:` (WOR-2476): schemes/ports open, hosts empty, so
        // every destination is denied on the empty host allowlist
        // specifically, not on scheme or port.
        let empty_hosts = PurposeAllowlist {
            schemes: HashSet::from(["https".to_string(), "http".to_string()]),
            ports: HashSet::from([443, 80]),
            ..Default::default()
        };
        let deny_all = EgressAuthorizer::new(EgressConfig {
            purposes: HashMap::from([(EgressPurpose::AiProvider, empty_hosts)]),
        });
        install_configured_gate(EgressPurpose::AiProvider, Some(deny_all));

        let mut client = AiClient::new();
        if let Some(authorizer) = configured_gate(EgressPurpose::AiProvider) {
            client = client.with_egress(authorizer);
        }

        let err = client
            .gate_provider_url(
                "https://armed-dispatch-test.invalid/v1/chat",
                "test-provider",
            )
            .expect_err("deny_by_default with empty hosts must refuse the dispatch");
        assert!(err.to_string().contains("UnlistedHost"));

        let snapshot = egress_inventory_snapshot();
        let sighting = snapshot
            .iter()
            .find(|s| s.host == "armed-dispatch-test.invalid")
            .expect("the denied dispatch must be stamped in the inventory");
        assert_eq!(sighting.status, "denied");
        assert_eq!(sighting.last_reason, Some("unlisted_host"));

        install_configured_gate(EgressPurpose::AiProvider, None);
    }

    /// One-shot loopback fixture that serves `response` verbatim to the
    /// first connection and reports whether it was contacted. Mirrors
    /// the `dial_fixture` shape the OpenAPI redirect test uses.
    fn dial_fixture(response: String) -> Option<(std::net::SocketAddr, Arc<AtomicBool>)> {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
        let addr = listener.local_addr().ok()?;
        let hit = Arc::new(AtomicBool::new(false));
        let hit_writer = Arc::clone(&hit);
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                hit_writer.store(true, Ordering::SeqCst);
                let mut scratch = [0u8; 2048];
                let _ = stream.read(&mut scratch);
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        Some((addr, hit))
    }

    fn ok_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    /// Serve a sequence of responses on one listener, one connection
    /// each, and hand back the raw text of every request received.
    ///
    /// `dial_fixture` accepts a single connection, which is enough for
    /// a refused hop but not for a redirect that is actually followed.
    /// `build` receives the bound address so a response can name the
    /// listener's own port, which a plain `Vec<String>` cannot do.
    fn dial_sequence(
        build: impl FnOnce(std::net::SocketAddr) -> Vec<String>,
    ) -> Option<(std::net::SocketAddr, Arc<parking_lot::Mutex<Vec<String>>>)> {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
        let addr = listener.local_addr().ok()?;
        let responses = build(addr);
        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let writer = Arc::clone(&seen);
        std::thread::spawn(move || {
            for response in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut scratch = [0u8; 4096];
                let read = stream.read(&mut scratch).unwrap_or(0);
                let text = String::from_utf8_lossy(&scratch[..read]).to_string();
                writer.lock().push(text);
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        Some((addr, seen))
    }

    /// A signer that records the URL it was handed and stamps a marker
    /// header, so a test can see exactly when and against what the
    /// signing boundary fired.
    #[derive(Debug)]
    struct RecordingSigner {
        seen: parking_lot::Mutex<Vec<String>>,
        fail: bool,
    }

    impl RecordingSigner {
        fn new(fail: bool) -> Self {
            Self {
                seen: parking_lot::Mutex::new(Vec::new()),
                fail,
            }
        }

        fn urls(&self) -> Vec<String> {
            self.seen.lock().clone()
        }
    }

    #[async_trait::async_trait]
    impl OutboundSigner for RecordingSigner {
        fn scheme(&self) -> &'static str {
            "recording"
        }

        async fn sign(&self, request: &mut reqwest::Request) -> Result<()> {
            self.seen.lock().push(request.url().to_string());
            if self.fail {
                return Err(anyhow::anyhow!("signing refused"));
            }
            let index = self.seen.lock().len();
            let mut value = reqwest::header::HeaderValue::from_str(&format!("signed-{index}"))?;
            value.set_sensitive(true);
            request
                .headers_mut()
                .insert(reqwest::header::AUTHORIZATION, value);
            Ok(())
        }
    }

    fn sigv4_provider_json(name: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "provider_type": "bedrock",
            "aws_sigv4": {"region": "us-east-1"},
        })
    }

    #[test]
    fn a_signed_provider_emits_no_verbatim_credential_header() {
        // The bearer mode and the signing mode have to be exclusive at
        // the point the header is built, not merely refused at config
        // load, because the signer overwrites `Authorization` and a
        // static credential riding along would be invisible.
        let signed: ProviderConfig =
            serde_json::from_value(sigv4_provider_json("bedrock")).expect("config parses");
        assert!(
            provider_auth_header(&signed)
                .expect("header resolution succeeds")
                .is_none(),
            "a SigV4 provider must contribute no static credential header"
        );

        let bearer: ProviderConfig = serde_json::from_value(serde_json::json!({
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test",
        }))
        .expect("config parses");
        let (name, value) = provider_auth_header(&bearer)
            .expect("header resolution succeeds")
            .expect("a bearer provider still sends its credential");
        assert_eq!(name.as_str(), "authorization");
        assert!(value.is_sensitive());
    }

    #[tokio::test]
    async fn the_signer_runs_again_on_every_hop_against_the_rewritten_url() {
        // A signature is bound to the host and path it covers, so
        // replaying hop one's signature onto hop two is an
        // authentication failure that looks like a network problem.
        // `send_governed` must therefore sign after the URL rewrite,
        // once per hop.
        let Some((addr, seen)) = dial_sequence(|addr| {
            vec![
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/v1/moved\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    addr.port()
                ),
                ok_response("{}"),
            ]
        }) else {
            return;
        };

        let client = AiClient::new();
        let request = client
            .http
            .post(format!("http://{addr}/v1/chat/completions"))
            .json(&serde_json::json!({"model": "m"}))
            .build()
            .expect("test request builds");
        let signer = RecordingSigner::new(false);
        let resp = send_governed(&client.http, None, "test-provider", Some(&signer), request)
            .await
            .expect("a same-origin hop is followed");
        assert_eq!(resp.status().as_u16(), 200);

        let urls = signer.urls();
        assert_eq!(urls.len(), 2, "one signature per hop, got {urls:?}");
        assert!(urls[0].ends_with("/v1/chat/completions"));
        assert!(
            urls[1].ends_with("/v1/moved"),
            "the second signature must cover the redirect target, got {}",
            urls[1]
        );

        let requests = seen.lock().clone();
        assert_eq!(requests.len(), 2);
        assert!(
            requests[0].contains("signed-1"),
            "hop one carries the first signature"
        );
        assert!(
            requests[1].contains("signed-2") && !requests[1].contains("signed-1"),
            "hop two carries the second signature and not the first: {}",
            requests[1]
        );
    }

    #[tokio::test]
    async fn a_signer_failure_fails_the_attempt_without_dialing() {
        // Fail closed. An unsigned request to a SigV4 endpoint is a 403
        // and a wasted round trip; worse, a scheme that silently fell
        // through would send the credential-free request as if it were
        // fine.
        let Some((addr, hit)) = dial_fixture(ok_response("{}")) else {
            return;
        };
        let client = AiClient::new();
        let request = client
            .http
            .post(format!("http://{addr}/v1/chat/completions"))
            .build()
            .expect("test request builds");
        let signer = RecordingSigner::new(true);
        let error = send_governed(&client.http, None, "test-provider", Some(&signer), request)
            .await
            .expect_err("a signing failure fails the attempt");
        assert!(format!("{error:#}").contains("signing refused"));
        assert!(
            !hit.load(Ordering::SeqCst),
            "nothing may be dialed once signing has failed"
        );
    }

    #[tokio::test]
    async fn provider_dial_refuses_a_cross_origin_redirect_hop() {
        // Hop one is the host the operator configured and serves a 302
        // to a different host. The credential must not follow: the
        // second listener must never be contacted.
        let Some((sink_addr, sink_hit)) = dial_fixture(ok_response("{}")) else {
            return;
        };
        let redirect = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            sink_addr.port()
        );
        let Some((first_addr, first_hit)) = dial_fixture(redirect) else {
            return;
        };

        let client = AiClient::new();
        let request = client
            .http
            .post(format!("http://{first_addr}/v1/chat/completions"))
            .header("x-api-key", {
                let mut v = reqwest::header::HeaderValue::from_static("sk-secret");
                v.set_sensitive(true);
                v
            })
            .json(&serde_json::json!({"model": "gpt-4o"}))
            .build()
            .expect("test request builds");

        let err = send_governed(&client.http, None, "test-provider", None, request)
            .await
            .expect_err("a cross-origin hop must be refused, not followed");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("RedirectToUnlistedHost"),
            "expected RedirectToUnlistedHost, got: {rendered}"
        );
        assert!(
            first_hit.load(Ordering::SeqCst),
            "hop one must have served the redirect"
        );
        assert!(
            !sink_hit.load(Ordering::SeqCst),
            "the redirect target must never be contacted"
        );
    }

    #[tokio::test]
    async fn provider_dial_returns_a_non_redirect_response_unchanged() {
        // The governed loop must not perturb the ordinary path: a 200
        // comes back on the first pass with one dial and no hop
        // evaluation at all.
        let body = r#"{"ok":true}"#;
        let Some((addr, hit)) = dial_fixture(ok_response(body)) else {
            return;
        };
        let client = AiClient::new();
        let request = client
            .http
            .get(format!("http://{addr}/v1/models"))
            .build()
            .expect("test request builds");
        let resp = send_governed(&client.http, None, "test-provider", None, request)
            .await
            .expect("a non-redirect response returns unchanged");
        assert_eq!(resp.status().as_u16(), 200);
        assert!(hit.load(Ordering::SeqCst));
    }
}
