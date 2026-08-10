// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! `agent_budget` semantic rate-limit primitive.
//!
//! Standard per-IP / per-user / per-key limits assume humans pause
//! between requests. Agents driven by an LLM loop fire at network
//! speed and trip those buckets immediately. Datadog reports roughly a
//! third of LLM-span errors in production are rate-limit denials for
//! that reason.
//!
//! This policy is keyed on the resolver-produced `agent_id` (from
//! `sbproxy-agent-detect` / `sbproxy-classifiers`). One bucket per
//! named agent collapses "every request from the Cursor instance" into
//! a single budget, which is what operators actually want to size.
//!
//! ## Knobs
//!
//! * `requests_per_minute`: token bucket refill rate, per `agent_id`.
//!   Shared across replicas when an L2 store is attached; see
//!   "Cluster-shared enforcement" below.
//! * `tokens_per_hour`: rolling hourly LLM-token budget per
//!   `agent_id`. Enforcement is two-phase because a response's token
//!   count is only known after the response completes: admission
//!   checks the accumulated counter before dispatch, and the gateway
//!   charges the measured usage via
//!   [`AgentBudgetPolicy::consume_tokens`] once the provider reports
//!   it (buffered responses at usage extraction, streamed responses
//!   when the end-of-stream usage frame aggregates). A request over
//!   the cap is refused at admission with the same verdict mapping
//!   as `requests_per_minute`.
//! * `burst`: max simultaneous in-flight requests per `agent_id`. The
//!   acquired permit is returned as an RAII guard so the slot
//!   releases when the request completes.
//! * `on_exceed`: `deny` (default), `log`, or `downgrade`. The policy
//!   reports the chosen verdict; the dispatcher maps that verdict to
//!   an HTTP response or a downgraded action.
//! * `on_anonymous`: how to handle requests where `agent_id` is `None`.
//!   Defaults to `skip` (no enforcement); operators that explicitly
//!   want shared-bucket fallback set `shared`.
//!
//! ## Cluster-shared enforcement
//!
//! Ten replicas holding ten local buckets enforce every configured cap
//! ten times over, so `requests_per_minute` has the same L2 tier
//! [`super::rate_limit::RateLimitPolicy`] already carries. Attach a
//! shared store with [`AgentBudgetPolicy::with_store`] or
//! [`AgentBudgetPolicy::with_async_store`] and the per-minute cap is
//! decided by a fixed-window counter every replica increments, so the
//! fleet enforces the operator's number once. Attach nothing and the
//! policy keeps its purely local view, which is the right answer for a
//! single node and is what every deployment gets until an operator
//! configures the store.
//!
//! ## Out of scope
//!
//! * Cluster-shared `tokens_per_hour`. An hourly fixed window bucketed
//!   on the wall clock resets on the same boundary for every replica,
//!   so a fleet can spend close to twice the cap across that boundary.
//!   That is tolerable for a 60 second window and not for an hourly
//!   spend budget, so the hourly tier waits on a design that does not
//!   reset in lock-step.
//! * Cluster-shared `burst`. In-flight permits are per-process by
//!   construction: the permit releases when a request on this node
//!   completes, which no other node can observe.
//! * Token estimates for responses that never report usage. A
//!   response with no parseable `usage` block, and any surface that
//!   cannot report one, consumes zero rather than an invented count.

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;
use sbproxy_platform::storage::{incr_with_ttl_async, AsyncKVStore, KVStore};
use serde::Deserialize;

/// What to do when an `agent_id` blows past its budget.
///
/// The policy module surfaces the verdict; the dispatcher translates
/// it to an HTTP response (deny) or a downgraded action (downgrade).
/// `Log` admits the request and records the overage on the metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AgentBudgetOnExceed {
    /// Reject the request with `429 Too Many Requests`. Default.
    #[default]
    Deny,
    /// Admit the request but record the overage on the metric. The
    /// dispatcher does not stamp any header in this mode; operators
    /// use the metric to size a future deny rollout.
    Log,
    /// Admit the request and signal that downstream should pick a
    /// cheaper model. The dispatcher is responsible for honouring
    /// the signal; the policy just emits the verdict.
    Downgrade,
}

impl AgentBudgetOnExceed {
    /// Stable string used for metric labels and structured logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Log => "log",
            Self::Downgrade => "downgrade",
        }
    }
}

/// What to do when `agent_id` is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AgentBudgetOnAnonymous {
    /// Bypass the policy. The bucket is not consumed and the verdict
    /// is always [`AgentBudgetDecision::SkippedAnonymous`]. Default.
    #[default]
    Skip,
    /// Funnel every anonymous request through a single shared bucket
    /// keyed by the sentinel string `"__anonymous__"`. Operators who
    /// want a coarse fallback select this; otherwise prefer `skip`
    /// and stack `rate_limit` for IP-keyed enforcement.
    Shared,
}

impl AgentBudgetOnAnonymous {
    /// Stable string used for diagnostic logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Skip => "skip",
            Self::Shared => "shared",
        }
    }
}

/// Verdict the policy returns to the caller.
///
/// `Allow` is the happy path; `AllowDowngrade` and `AllowLogged` both
/// admit the request but signal a budget breach with the configured
/// `on_exceed` behaviour. `Deny` is the hard reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentBudgetDecision {
    /// Within budget. Permit was acquired when `burst` is configured.
    Allow,
    /// `agent_id` was `None` and `on_anonymous` is `skip`. No bucket
    /// was consumed and no permit was issued.
    SkippedAnonymous,
    /// Budget exceeded; admitted because `on_exceed: log`. The
    /// dispatcher should record the overage but admit the request.
    AllowLogged {
        /// Why the budget was exceeded.
        reason: AgentBudgetExceedReason,
    },
    /// Budget exceeded; admitted because `on_exceed: downgrade`. The
    /// dispatcher should select a cheaper upstream / model.
    AllowDowngrade {
        /// Why the budget was exceeded.
        reason: AgentBudgetExceedReason,
    },
    /// Budget exceeded; rejected because `on_exceed: deny`. The
    /// dispatcher returns `429 Too Many Requests`.
    Deny {
        /// Why the budget was exceeded.
        reason: AgentBudgetExceedReason,
    },
}

impl AgentBudgetDecision {
    /// Stable outcome label for metrics: `allow`, `deny`, `log`,
    /// `downgrade`. The `allow` label covers both the in-budget happy
    /// path and the anonymous skip case; `log` / `downgrade` /
    /// `deny` correspond one-to-one with the `on_exceed` modes.
    pub fn outcome_label(&self) -> &'static str {
        match self {
            Self::Allow | Self::SkippedAnonymous => "allow",
            Self::AllowLogged { .. } => "log",
            Self::AllowDowngrade { .. } => "downgrade",
            Self::Deny { .. } => "deny",
        }
    }

    /// True for any verdict that admits the request. The dispatcher
    /// short-circuits to a 429 only when this is false.
    pub fn admits(&self) -> bool {
        !matches!(self, Self::Deny { .. })
    }
}

/// Closed enum describing which sub-budget tripped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentBudgetExceedReason {
    /// `requests_per_minute` exhausted: token bucket empty.
    RequestsPerMinute,
    /// `tokens_per_hour` exhausted. Reported when a caller asks the
    /// policy whether the agent still has token headroom before
    /// dispatching to the upstream model.
    TokensPerHour,
    /// `burst` exceeded: no free in-flight slot.
    Burst,
}

impl AgentBudgetExceedReason {
    /// Stable string for diagnostic logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RequestsPerMinute => "requests_per_minute",
            Self::TokensPerHour => "tokens_per_hour",
            Self::Burst => "burst",
        }
    }
}

/// Per-`agent_id` token bucket for the `requests_per_minute` knob.
///
/// Mirrors the math used by [`super::rate_limit::RateLimitPolicy`] so
/// the two policies have the same admission semantics modulo the
/// keying strategy.
#[derive(Debug, Clone)]
struct RequestBucket {
    tokens: f64,
    capacity: f64,
    refill_per_second: f64,
    last_refill: Instant,
}

impl RequestBucket {
    fn new(capacity: f64, refill_per_second: f64, now: Instant) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_per_second,
            last_refill: now,
        }
    }

    fn try_acquire(&mut self, now: Instant) -> bool {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_second).min(self.capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Per-`agent_id` rolling token-usage counter for `tokens_per_hour`.
///
/// Uses a fixed-window counter (one wall-clock hour) rather than a
/// smooth bucket. LLM token accounting is bursty and operators
/// reason about hourly caps. The window resets on first observation
/// inside a new hour.
#[derive(Debug, Clone)]
struct TokenBucket {
    consumed: u64,
    limit: u64,
    window_start: Instant,
    window: Duration,
}

impl TokenBucket {
    fn new(limit: u64, now: Instant) -> Self {
        Self {
            consumed: 0,
            limit,
            window_start: now,
            window: Duration::from_secs(3600),
        }
    }

    /// Returns `true` while the agent is within budget for this hour.
    fn within_budget(&mut self, now: Instant) -> bool {
        self.maybe_roll(now);
        self.consumed < self.limit
    }

    /// Add `n` tokens to the rolling count, rolling the window first
    /// if it has expired.
    fn add(&mut self, n: u64, now: Instant) {
        self.maybe_roll(now);
        self.consumed = self.consumed.saturating_add(n);
    }

    fn maybe_roll(&mut self, now: Instant) {
        if now.duration_since(self.window_start) >= self.window {
            self.window_start = now;
            self.consumed = 0;
        }
    }
}

/// RAII guard returned by [`AgentBudgetPolicy::try_admit`] that releases
/// the in-flight slot for the keyed agent when dropped.
///
/// Holding the guard is what keeps the `burst` count accurate: every
/// admitted request retains its guard until it finishes, and the
/// dispatcher drops the guard on the response phase. The guard is
/// always returned, even when `burst` is unconfigured, so callers do
/// not have to special-case the absence.
pub struct AgentBudgetGuard {
    counters: Option<Arc<DashMap<String, AtomicU32>>>,
    key: String,
}

impl Drop for AgentBudgetGuard {
    fn drop(&mut self) {
        if let Some(counters) = self.counters.as_ref() {
            if let Some(entry) = counters.get(&self.key) {
                // Best-effort release. The increment is paired with
                // this decrement; if the entry has already been
                // evicted we drop the count silently.
                entry.value().fetch_sub(1, Ordering::AcqRel);
            }
        }
    }
}

/// Post-response half of the token budget: the policy handle plus the
/// agent key admission resolved, stashed on the request context by the
/// dispatcher's enforcer and drained exactly once when the response's
/// measured token usage is known.
///
/// Capturing the key at admission time keeps consumption keyed exactly
/// the way the pre-flight check was keyed, even if the context's agent
/// resolution were to change between the two phases.
pub struct AgentBudgetTokenSink {
    policy: Arc<AgentBudgetPolicy>,
    agent_id: Option<String>,
}

impl AgentBudgetTokenSink {
    /// Bind a sink to `policy`, keyed by the `agent_id` the admission
    /// check ran under.
    pub fn new(policy: Arc<AgentBudgetPolicy>, agent_id: Option<String>) -> Self {
        Self { policy, agent_id }
    }

    /// Charge `n` upstream tokens against the hourly budget under the
    /// captured agent key. Zero is a no-op, so a response that
    /// reported no usage consumes nothing.
    pub fn consume(&self, n: u64) {
        self.policy.consume_tokens(self.agent_id.as_deref(), n);
    }
}

/// `agent_budget` policy: per-`agent_id` semantic rate limiter.
pub struct AgentBudgetPolicy {
    /// Token-bucket refill rate in requests per minute, per agent.
    /// `None` disables the request-rate sub-budget entirely.
    pub requests_per_minute: Option<f64>,
    /// Rolling hourly LLM-token cap per agent. `None` disables.
    pub tokens_per_hour: Option<u64>,
    /// Maximum simultaneous in-flight requests per agent. `None`
    /// disables the burst sub-budget.
    pub burst: Option<u32>,
    /// What to do when a sub-budget trips.
    pub on_exceed: AgentBudgetOnExceed,
    /// What to do when `agent_id` is `None`.
    pub on_anonymous: AgentBudgetOnAnonymous,
    /// Maximum number of distinct agent keys held in the LRU caches.
    pub max_agents: usize,

    request_buckets: Mutex<lru::LruCache<String, RequestBucket>>,
    token_buckets: Mutex<lru::LruCache<String, TokenBucket>>,
    in_flight: Arc<DashMap<String, AtomicU32>>,

    // --- Optional L2 (cluster-shared) state ---
    //
    // These are not part of `RawConfig` and so cannot be named in a
    // config block, which is the same effect `#[serde(skip)]` has on
    // `RateLimitPolicy`'s equivalents. This struct deserializes through
    // `RawConfig` rather than deriving `Deserialize` itself, so the
    // attribute has nowhere to sit here.
    /// Shared counter backend (sync). Kept for callers that have not yet
    /// migrated to `async_store`; reached through `spawn_blocking`
    /// because the sync backends block on network I/O.
    store: Option<Arc<dyn KVStore>>,
    /// Shared counter backend (async-native). Preferred over `store` on
    /// the request-hot path: no `spawn_blocking` tax per request.
    async_store: Option<Arc<dyn AsyncKVStore>>,
    /// Pre-computed counter-key prefix, so the hot path allocates no
    /// more than it must. Format: `"sbproxy:ab:<origin-id>:"`.
    key_prefix: String,
}

const SHARED_ANONYMOUS_KEY: &str = "__anonymous__";
const DEFAULT_MAX_AGENTS: usize = 10_000;

/// Fixed-window length, in seconds, for the shared `requests_per_minute`
/// counter.
///
/// `RateLimitPolicy` derives this from its rate unit because it has two
/// of them (1 s for `requests_per_second`, 60 s for
/// `requests_per_minute`). This policy has one, so the window is the
/// constant 60 that policy's `requests_per_minute` arm resolves to.
const REQUEST_WINDOW_SECS: u64 = 60;

#[derive(Deserialize)]
struct RawConfig {
    #[serde(default)]
    requests_per_minute: Option<f64>,
    #[serde(default)]
    tokens_per_hour: Option<u64>,
    #[serde(default)]
    burst: Option<u32>,
    #[serde(default)]
    on_exceed: AgentBudgetOnExceed,
    #[serde(default)]
    on_anonymous: AgentBudgetOnAnonymous,
    #[serde(default)]
    max_agents: Option<usize>,
}

impl AgentBudgetPolicy {
    /// Build the policy from its JSON config block. Caps `max_agents`
    /// at a non-zero value so the LRU constructors do not panic on
    /// `max_agents: 0`.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let raw: RawConfig = serde_json::from_value(value)?;
        if let Some(rpm) = raw.requests_per_minute {
            anyhow::ensure!(
                rpm >= 0.0 && rpm.is_finite(),
                "agent_budget.requests_per_minute must be non-negative and finite"
            );
        }
        if let Some(burst) = raw.burst {
            anyhow::ensure!(burst > 0, "agent_budget.burst must be > 0 when set");
        }
        let max_agents = raw.max_agents.unwrap_or(DEFAULT_MAX_AGENTS).max(1);
        let cap = NonZeroUsize::new(max_agents).expect("max_agents capped at 1");
        Ok(Self {
            requests_per_minute: raw.requests_per_minute,
            tokens_per_hour: raw.tokens_per_hour,
            burst: raw.burst,
            on_exceed: raw.on_exceed,
            on_anonymous: raw.on_anonymous,
            max_agents,
            request_buckets: Mutex::new(lru::LruCache::new(cap)),
            token_buckets: Mutex::new(lru::LruCache::new(cap)),
            in_flight: Arc::new(DashMap::new()),
            store: None,
            async_store: None,
            key_prefix: String::new(),
        })
    }

    /// Attach a shared L2 store so this policy enforces its
    /// `requests_per_minute` cap once across the fleet instead of once
    /// per replica. The `origin_id` is baked into every counter key so
    /// two origins never share an agent's budget.
    ///
    /// When `store` is `None` the policy keeps its in-process bucket.
    pub fn with_store(mut self, store: Option<Arc<dyn KVStore>>, origin_id: &str) -> Self {
        self.store = store;
        self.key_prefix = counter_key_prefix(origin_id);
        self
    }

    /// Attach an **async** shared L2 store. Takes precedence over the
    /// sync `store` on the request-hot path: [`Self::try_admit_async`]
    /// awaits the async backend directly instead of bridging through
    /// `spawn_blocking`.
    ///
    /// `origin_id` is baked into the counter-key prefix the same way
    /// [`Self::with_store`] does it. This setter fills the prefix only
    /// when `with_store` has not already set it, so the two chain in
    /// either order and an upgrade that adds the async handle cannot
    /// move live counters into a fresh keyspace.
    pub fn with_async_store(
        mut self,
        store: Option<Arc<dyn AsyncKVStore>>,
        origin_id: &str,
    ) -> Self {
        self.async_store = store;
        if self.key_prefix.is_empty() {
            self.key_prefix = counter_key_prefix(origin_id);
        }
        self
    }

    /// Resolve the bucket key from a caller-supplied `agent_id`.
    ///
    /// Returns `None` when there is no `agent_id` and the policy is
    /// configured to skip anonymous traffic, in which case the
    /// caller should treat the request as bypass.
    fn resolve_key(&self, agent_id: Option<&str>) -> Option<String> {
        match (agent_id, self.on_anonymous) {
            (Some(id), _) if !id.is_empty() => Some(id.to_string()),
            (_, AgentBudgetOnAnonymous::Shared) => Some(SHARED_ANONYMOUS_KEY.to_string()),
            _ => None,
        }
    }

    /// Try to admit a request keyed on `agent_id`.
    ///
    /// Acquires a permit on the in-flight counter when `burst` is set
    /// and consumes one token from the per-minute bucket when
    /// `requests_per_minute` is set. Returns a verdict plus an RAII
    /// guard; the guard releases the permit on drop.
    ///
    /// Permits and tokens are reserved in lock-step: if the
    /// per-minute bucket is empty the in-flight counter is not
    /// incremented, and vice-versa, so a denied request never wedges
    /// the burst budget.
    pub fn try_admit(&self, agent_id: Option<&str>) -> (AgentBudgetDecision, AgentBudgetGuard) {
        self.try_admit_at(agent_id, Instant::now())
    }

    /// `try_admit` with an injected `now`. Exposed for tests that need
    /// to drive time deterministically without sleeping.
    pub fn try_admit_at(
        &self,
        agent_id: Option<&str>,
        now: Instant,
    ) -> (AgentBudgetDecision, AgentBudgetGuard) {
        let Some(key) = self.resolve_key(agent_id) else {
            return (AgentBudgetDecision::SkippedAnonymous, self.empty_guard());
        };

        if let Some(reason) = self.check_token_headroom(&key, now) {
            return self.apply_on_exceed(reason, &key, false);
        }

        let mut admitted_request = true;
        if self.requests_per_minute.is_some() {
            admitted_request = self.consume_request_token(&key, now);
        }
        if !admitted_request {
            return self.apply_on_exceed(AgentBudgetExceedReason::RequestsPerMinute, &key, false);
        }

        if let Some(max) = self.burst {
            match self.acquire_in_flight(&key, max) {
                Some(guard) => (AgentBudgetDecision::Allow, guard),
                None => {
                    // Burst is full. Refund the request token we just
                    // consumed so a denied request does not also drain
                    // the per-minute budget.
                    self.refund_request_token(&key, now);
                    self.apply_on_exceed(AgentBudgetExceedReason::Burst, &key, true)
                }
            }
        } else {
            (AgentBudgetDecision::Allow, self.empty_guard())
        }
    }

    /// Async variant of [`AgentBudgetPolicy::try_admit`], and the entry
    /// point a clustered deployment has to call.
    ///
    /// With a shared L2 store attached, the `requests_per_minute`
    /// sub-budget is decided by a fixed-window counter in the store
    /// (atomic INCR plus expiry) rather than by this node's token
    /// bucket, so every replica spends from one allowance. This is a
    /// different algorithm from the local bucket: it does not refill
    /// smoothly, it steps at the window boundary, which is the same
    /// trade [`super::rate_limit::RateLimitPolicy`] makes on its own L2
    /// path.
    ///
    /// With nothing attached, or with no `requests_per_minute` to
    /// share, this is exactly [`AgentBudgetPolicy::try_admit`]. A
    /// single-node deployment therefore behaves as it always has.
    ///
    /// `tokens_per_hour` and `burst` stay local in both cases; see the
    /// module's "Out of scope" notes for why.
    pub async fn try_admit_async(
        &self,
        agent_id: Option<&str>,
    ) -> (AgentBudgetDecision, AgentBudgetGuard) {
        // Nothing shared to consult: no store, or no request-rate
        // sub-budget for the shared tier to cover. Both cases are the
        // local path verbatim rather than a re-implementation of it, so
        // they cannot drift.
        if self.requests_per_minute.is_none()
            || (self.async_store.is_none() && self.store.is_none())
        {
            return self.try_admit(agent_id);
        }

        let now = Instant::now();
        let Some(key) = self.resolve_key(agent_id) else {
            return (AgentBudgetDecision::SkippedAnonymous, self.empty_guard());
        };

        if let Some(reason) = self.check_token_headroom(&key, now) {
            return self.apply_on_exceed(reason, &key, false);
        }

        // Burst is taken before the shared counter, the reverse of the
        // local path's order. The local path consumes a request token
        // first and refunds it when burst denies, so a request that
        // never reached an upstream does not drain the request budget;
        // a fixed-window INCR has no compensating decrement, so the only
        // way to hold that same invariant here is to learn about burst
        // contention before spending a window slot. What differs is
        // which reason a request that trips both sub-budgets reports,
        // not whether it is admitted.
        let guard = if let Some(max) = self.burst {
            match self.acquire_in_flight(&key, max) {
                Some(guard) => guard,
                None => return self.apply_on_exceed(AgentBudgetExceedReason::Burst, &key, true),
            }
        } else {
            self.empty_guard()
        };

        if let Some(rpm) = self.requests_per_minute {
            if !self.shared_window_admits(&key, rpm).await {
                // Returning here drops `guard`, which releases the
                // in-flight permit taken above: a request the shared
                // counter refuses must not go on holding a burst slot.
                return self.apply_on_exceed(
                    AgentBudgetExceedReason::RequestsPerMinute,
                    &key,
                    true,
                );
            }
        }

        (AgentBudgetDecision::Allow, guard)
    }

    /// Increment this agent's shared fixed-window counter and report
    /// whether the post-increment count is still inside the cap.
    ///
    /// **Failure posture: fail open.** A store that errors, or a
    /// blocking bridge that fails to join, admits the request.
    /// `RateLimitPolicy::allow_with_info_async` makes the same call for
    /// the same reason, that a Redis hiccup must not become a
    /// cluster-wide outage, and matching it is the point: a budget that
    /// failed closed on the same blip a rate limiter next to it failed
    /// open on would be behavior no operator could predict. There is no
    /// fallback to the local bucket either, again matching that policy;
    /// a store outage suspends the request-rate budget rather than
    /// quietly swapping in a differently sized one.
    async fn shared_window_admits(&self, key: &str, rpm: f64) -> bool {
        let limit = window_limit(rpm);
        // Bucket on the wall clock rather than on a process-local
        // `Instant` so every replica derives the same window without
        // coordinating, and so a replica that started ten minutes later
        // does not carry its own boundary.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let counter_key = self.window_key(key, now_secs).into_bytes();
        // One second of slack so the key outlives the window it counts
        // even when the increment lands on that window's last moment.
        let ttl = REQUEST_WINDOW_SECS + 1;

        let incr_result: anyhow::Result<i64> = if let Some(async_store) = self.async_store.as_ref()
        {
            // Async path: native await, no spawn_blocking tax.
            async_store.incr_with_ttl(&counter_key, ttl).await
        } else if let Some(store) = self.store.as_ref() {
            // Sync fallback for a deployment that has not migrated to
            // the async handle. The blocking backends issue network I/O,
            // so the platform helper hands the call to a blocking
            // thread; a join failure arrives here as an `Err` and takes
            // the same fail-open branch as any other store failure.
            incr_with_ttl_async(Arc::clone(store), counter_key, ttl).await
        } else {
            // Unreachable: `try_admit_async` returns before calling this
            // when neither handle is attached. Admitting keeps the dead
            // arm on the same side as a store error rather than
            // inventing a denial nobody configured.
            return true;
        };

        match incr_result {
            Ok(count) => (count as u64) <= limit,
            Err(e) => {
                tracing::warn!(error = %e, "agent_budget l2 INCR failed, failing open");
                true
            }
        }
    }

    /// Build the shared request-counter key for `key` at wall-clock
    /// second `now_secs`.
    ///
    /// Format: `sbproxy:ab:<origin-id>:rpm:<agent-key>:<window-start>`,
    /// where the window start is the epoch second floored to
    /// [`REQUEST_WINDOW_SECS`]. Flooring is what makes the tier work
    /// without coordination: two replicas handling requests in the same
    /// minute derive the same string, and the counter for a closed
    /// window is simply abandoned to its expiry rather than reset by
    /// anyone.
    ///
    /// The `rpm` segment names which sub-budget the counter belongs to.
    /// Nothing reads it today, and it is here so that a later
    /// cluster-shared `tokens_per_hour` can take a segment of its own
    /// rather than force live per-minute counters into a fresh
    /// keyspace to make room.
    fn window_key(&self, key: &str, now_secs: u64) -> String {
        let window_start = now_secs - (now_secs % REQUEST_WINDOW_SECS);
        format!("{}rpm:{}:{}", self.key_prefix, key, window_start)
    }

    /// Record that `n` upstream tokens were consumed by `agent_id`.
    ///
    /// Called from the gateway's response-completion paths (via
    /// [`AgentBudgetTokenSink`]) once the provider reports actual
    /// usage, so the hourly budget the next admission checks reflects
    /// real model spend. `None` agent ids are ignored under
    /// `on_anonymous: skip`; under `shared` they charge the shared
    /// bucket.
    pub fn consume_tokens(&self, agent_id: Option<&str>, n: u64) {
        if n == 0 || self.tokens_per_hour.is_none() {
            return;
        }
        let Some(key) = self.resolve_key(agent_id) else {
            return;
        };
        let limit = self.tokens_per_hour.expect("checked above");
        let now = Instant::now();
        let mut buckets = self.token_buckets.lock();
        if let Some(b) = buckets.get_mut(&key) {
            b.add(n, now);
        } else {
            let mut b = TokenBucket::new(limit, now);
            b.add(n, now);
            buckets.put(key, b);
        }
    }

    /// Snapshot of how many slots are currently held for `agent_id`.
    /// Used by tests; not part of any wire surface.
    pub fn in_flight_count(&self, agent_id: &str) -> u32 {
        self.in_flight
            .get(agent_id)
            .map(|e| e.value().load(Ordering::Acquire))
            .unwrap_or(0)
    }

    fn check_token_headroom(&self, key: &str, now: Instant) -> Option<AgentBudgetExceedReason> {
        let limit = self.tokens_per_hour?;
        let mut buckets = self.token_buckets.lock();
        let bucket = if let Some(b) = buckets.get_mut(key) {
            b
        } else {
            buckets.put(key.to_string(), TokenBucket::new(limit, now));
            buckets
                .get_mut(key)
                .expect("just inserted; pop is impossible here")
        };
        if bucket.within_budget(now) {
            None
        } else {
            Some(AgentBudgetExceedReason::TokensPerHour)
        }
    }

    fn consume_request_token(&self, key: &str, now: Instant) -> bool {
        let rpm = match self.requests_per_minute {
            Some(rpm) => rpm,
            None => return true,
        };
        let capacity = rpm.max(1.0);
        let refill = rpm / 60.0;
        let mut buckets = self.request_buckets.lock();
        if let Some(b) = buckets.get_mut(key) {
            b.try_acquire(now)
        } else {
            let mut b = RequestBucket::new(capacity, refill, now);
            let ok = b.try_acquire(now);
            buckets.put(key.to_string(), b);
            ok
        }
    }

    fn refund_request_token(&self, key: &str, now: Instant) {
        let mut buckets = self.request_buckets.lock();
        if let Some(b) = buckets.get_mut(key) {
            // Refund stays clamped at capacity so the bucket cannot
            // overflow if a parallel refill already topped it up.
            b.tokens = (b.tokens + 1.0).min(b.capacity);
            b.last_refill = now;
        }
    }

    fn acquire_in_flight(&self, key: &str, max: u32) -> Option<AgentBudgetGuard> {
        let entry = self
            .in_flight
            .entry(key.to_string())
            .or_insert_with(|| AtomicU32::new(0));
        let prev = entry.value().fetch_add(1, Ordering::AcqRel);
        if prev >= max {
            entry.value().fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(AgentBudgetGuard {
            counters: Some(Arc::clone(&self.in_flight)),
            key: key.to_string(),
        })
    }

    fn empty_guard(&self) -> AgentBudgetGuard {
        AgentBudgetGuard {
            counters: None,
            key: String::new(),
        }
    }

    fn apply_on_exceed(
        &self,
        reason: AgentBudgetExceedReason,
        key: &str,
        _already_refunded: bool,
    ) -> (AgentBudgetDecision, AgentBudgetGuard) {
        // For `log` and `downgrade` we admit the request without
        // taking a burst slot. The point of those modes is to let the
        // request through despite the breach; queuing on the burst
        // counter would defeat that. The guard is still returned so
        // the dispatcher's drop pattern stays uniform; it just does
        // not back any counter.
        match self.on_exceed {
            AgentBudgetOnExceed::Deny => {
                record_decision(key, "deny");
                (AgentBudgetDecision::Deny { reason }, self.empty_guard())
            }
            AgentBudgetOnExceed::Log => {
                record_decision(key, "log");
                (
                    AgentBudgetDecision::AllowLogged { reason },
                    self.empty_guard(),
                )
            }
            AgentBudgetOnExceed::Downgrade => {
                record_decision(key, "downgrade");
                (
                    AgentBudgetDecision::AllowDowngrade { reason },
                    self.empty_guard(),
                )
            }
        }
    }
}

impl std::fmt::Debug for AgentBudgetPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentBudgetPolicy")
            .field("requests_per_minute", &self.requests_per_minute)
            .field("tokens_per_hour", &self.tokens_per_hour)
            .field("burst", &self.burst)
            .field("on_exceed", &self.on_exceed)
            .field("on_anonymous", &self.on_anonymous)
            .field("max_agents", &self.max_agents)
            .field("tracked_agents", &self.in_flight.len())
            .field("store_attached", &self.store.is_some())
            .field("async_store_attached", &self.async_store.is_some())
            .field("key_prefix", &self.key_prefix)
            .finish()
    }
}

/// Counter-key prefix for one origin's shared budgets.
///
/// `ab` rather than `rl`: `rate_limit` owns the `sbproxy:rl:` keyspace,
/// and an origin that runs both policies against one Redis must not
/// have them counting into each other's keys.
fn counter_key_prefix(origin_id: &str) -> String {
    format!("sbproxy:ab:{origin_id}:")
}

/// Per-window request cap for the shared fixed-window path.
///
/// Deliberately the count the local bucket admits from full rather than
/// a rounded-up reading of the rate: tokens start at `rpm.max(1.0)` and
/// every admission needs a whole one, so a fractional rate admits its
/// floor and a rate of zero still admits one. Attaching a store has to
/// move where the cap is counted, not what the cap is.
fn window_limit(rpm: f64) -> u64 {
    rpm.max(1.0).floor() as u64
}

fn record_decision(agent_id: &str, outcome: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_agent_budget_decisions_total",
            "agent_budget policy verdicts, labelled by agent and outcome",
            &["agent_id", "outcome"],
        )
        .expect("agent_budget decisions counter registers")
    });
    // Cap the agent_id label length so a malicious or buggy upstream
    // cannot blow up Prometheus cardinality. 64 chars is well past the
    // longest legitimate catalog id today.
    let agent_label = if agent_id.len() > 64 {
        &agent_id[..64]
    } else {
        agent_id
    };
    counter.with_label_values(&[agent_label, outcome]).inc();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn policy(value: serde_json::Value) -> AgentBudgetPolicy {
        AgentBudgetPolicy::from_config(value).expect("config compiles")
    }

    #[test]
    fn rejects_61st_request_within_a_minute() {
        let p = policy(serde_json::json!({
            "requests_per_minute": 60,
            "on_exceed": "deny"
        }));
        let start = Instant::now();
        // The bucket starts full at capacity == 60 tokens; the 61st
        // call within the same instant must trip the budget.
        for i in 0..60 {
            let (decision, _g) = p.try_admit_at(Some("claude-code-cli"), start);
            assert_eq!(
                decision,
                AgentBudgetDecision::Allow,
                "request {i} should be admitted"
            );
        }
        let (decision, _g) = p.try_admit_at(Some("claude-code-cli"), start);
        assert!(matches!(
            decision,
            AgentBudgetDecision::Deny {
                reason: AgentBudgetExceedReason::RequestsPerMinute
            }
        ));
    }

    #[test]
    fn anonymous_requests_skip_the_bucket_by_default() {
        let p = policy(serde_json::json!({
            "requests_per_minute": 1,
            "on_exceed": "deny"
        }));
        let start = Instant::now();
        // Spray 100 anonymous requests; none of them should drain the
        // bucket since the default `on_anonymous: skip` bypasses
        // entirely.
        for _ in 0..100 {
            let (decision, _g) = p.try_admit_at(None, start);
            assert_eq!(decision, AgentBudgetDecision::SkippedAnonymous);
        }
        // A named agent still gets its full budget afterwards.
        let (decision, _g) = p.try_admit_at(Some("cursor"), start);
        assert_eq!(decision, AgentBudgetDecision::Allow);
    }

    #[test]
    fn anonymous_shared_bucket_consumes_per_request() {
        let p = policy(serde_json::json!({
            "requests_per_minute": 2,
            "on_exceed": "deny",
            "on_anonymous": "shared"
        }));
        let start = Instant::now();
        let (d1, _g1) = p.try_admit_at(None, start);
        let (d2, _g2) = p.try_admit_at(None, start);
        let (d3, _g3) = p.try_admit_at(None, start);
        assert_eq!(d1, AgentBudgetDecision::Allow);
        assert_eq!(d2, AgentBudgetDecision::Allow);
        assert!(matches!(d3, AgentBudgetDecision::Deny { .. }));
    }

    #[test]
    fn burst_caps_simultaneous_in_flight_count() {
        let p = policy(serde_json::json!({
            "requests_per_minute": 1000,
            "burst": 2,
            "on_exceed": "deny"
        }));
        let start = Instant::now();
        let (d1, g1) = p.try_admit_at(Some("agent"), start);
        let (d2, g2) = p.try_admit_at(Some("agent"), start);
        let (d3, _g3) = p.try_admit_at(Some("agent"), start);
        assert_eq!(d1, AgentBudgetDecision::Allow);
        assert_eq!(d2, AgentBudgetDecision::Allow);
        assert!(matches!(
            d3,
            AgentBudgetDecision::Deny {
                reason: AgentBudgetExceedReason::Burst
            }
        ));
        assert_eq!(p.in_flight_count("agent"), 2);

        // Releasing one guard frees a slot.
        drop(g1);
        assert_eq!(p.in_flight_count("agent"), 1);
        let (d4, _g4) = p.try_admit_at(Some("agent"), start);
        assert_eq!(d4, AgentBudgetDecision::Allow);

        drop(g2);
    }

    #[test]
    fn on_exceed_log_admits_with_logged_verdict() {
        let p = policy(serde_json::json!({
            "requests_per_minute": 1,
            "on_exceed": "log"
        }));
        let start = Instant::now();
        let (d1, _g1) = p.try_admit_at(Some("agent"), start);
        let (d2, _g2) = p.try_admit_at(Some("agent"), start);
        assert_eq!(d1, AgentBudgetDecision::Allow);
        assert!(matches!(d2, AgentBudgetDecision::AllowLogged { .. }));
        assert!(d2.admits());
        assert_eq!(d2.outcome_label(), "log");
    }

    #[test]
    fn on_exceed_downgrade_admits_with_downgrade_verdict() {
        let p = policy(serde_json::json!({
            "requests_per_minute": 1,
            "on_exceed": "downgrade"
        }));
        let start = Instant::now();
        let (d1, _g1) = p.try_admit_at(Some("agent"), start);
        let (d2, _g2) = p.try_admit_at(Some("agent"), start);
        assert_eq!(d1, AgentBudgetDecision::Allow);
        assert!(matches!(d2, AgentBudgetDecision::AllowDowngrade { .. }));
        assert!(d2.admits());
        assert_eq!(d2.outcome_label(), "downgrade");
    }

    #[test]
    fn on_exceed_deny_returns_429_intent() {
        let p = policy(serde_json::json!({
            "requests_per_minute": 1,
            "on_exceed": "deny"
        }));
        let start = Instant::now();
        let (d1, _g1) = p.try_admit_at(Some("agent"), start);
        let (d2, _g2) = p.try_admit_at(Some("agent"), start);
        assert_eq!(d1, AgentBudgetDecision::Allow);
        assert!(!d2.admits());
        assert_eq!(d2.outcome_label(), "deny");
    }

    #[test]
    fn denied_burst_does_not_drain_request_budget() {
        // With requests_per_minute=2 and burst=1, the second request
        // is denied on burst contention; the request-budget token it
        // would have consumed must be refunded so a follow-up call
        // after the first guard drops can still get through.
        let p = policy(serde_json::json!({
            "requests_per_minute": 2,
            "burst": 1,
            "on_exceed": "deny"
        }));
        let start = Instant::now();
        let (d1, g1) = p.try_admit_at(Some("agent"), start);
        let (d2, _g2) = p.try_admit_at(Some("agent"), start);
        assert_eq!(d1, AgentBudgetDecision::Allow);
        assert!(matches!(
            d2,
            AgentBudgetDecision::Deny {
                reason: AgentBudgetExceedReason::Burst
            }
        ));
        drop(g1);
        // Two more requests should still be admittable: refund means
        // the budget reads (2 - 1 admitted - 0 burst-denied) = 1 left.
        let (d3, g3) = p.try_admit_at(Some("agent"), start);
        assert_eq!(d3, AgentBudgetDecision::Allow);
        drop(g3);
    }

    #[test]
    fn tokens_per_hour_blocks_once_consumed() {
        let p = policy(serde_json::json!({
            "requests_per_minute": 10,
            "tokens_per_hour": 100,
            "on_exceed": "deny"
        }));
        let start = Instant::now();
        // Drain the hourly budget.
        p.consume_tokens(Some("agent"), 100);
        let (d, _g) = p.try_admit_at(Some("agent"), start);
        assert!(matches!(
            d,
            AgentBudgetDecision::Deny {
                reason: AgentBudgetExceedReason::TokensPerHour
            }
        ));
    }

    #[test]
    fn tokens_per_hour_is_noop_without_consumption() {
        // Admission must not depend on the limit until somebody
        // charges the bucket: a deployment whose responses never
        // report usage (or that serves no AI traffic at all) keeps
        // admitting under any cap.
        let p = policy(serde_json::json!({
            "requests_per_minute": 100,
            "tokens_per_hour": 1,
            "on_exceed": "deny"
        }));
        let start = Instant::now();
        for _ in 0..50 {
            let (d, _g) = p.try_admit_at(Some("agent"), start);
            assert_eq!(d, AgentBudgetDecision::Allow);
        }
    }

    #[test]
    fn token_consumption_accumulates_until_the_cap_crosses() {
        let p = policy(serde_json::json!({
            "tokens_per_hour": 100,
            "on_exceed": "deny"
        }));
        let start = Instant::now();
        // Two responses inside one window add up; the check refuses
        // only once the running total reaches the cap.
        p.consume_tokens(Some("agent"), 60);
        let (d, _g) = p.try_admit_at(Some("agent"), start);
        assert_eq!(d, AgentBudgetDecision::Allow, "60 of 100 still admits");
        p.consume_tokens(Some("agent"), 40);
        let (d, _g) = p.try_admit_at(Some("agent"), start);
        assert!(matches!(
            d,
            AgentBudgetDecision::Deny {
                reason: AgentBudgetExceedReason::TokensPerHour
            }
        ));
    }

    #[test]
    fn token_window_rolls_over_after_an_hour() {
        let p = policy(serde_json::json!({
            "tokens_per_hour": 100,
            "on_exceed": "deny"
        }));
        let start = Instant::now();
        p.consume_tokens(Some("agent"), 100);
        let (d, _g) = p.try_admit_at(Some("agent"), start);
        assert!(matches!(
            d,
            AgentBudgetDecision::Deny {
                reason: AgentBudgetExceedReason::TokensPerHour
            }
        ));
        // One hour later the fixed window resets and the agent gets a
        // fresh budget.
        let later = start + Duration::from_secs(3601);
        let (d, _g) = p.try_admit_at(Some("agent"), later);
        assert_eq!(d, AgentBudgetDecision::Allow);
    }

    #[test]
    fn zero_token_responses_consume_nothing() {
        let p = policy(serde_json::json!({
            "tokens_per_hour": 1,
            "on_exceed": "deny"
        }));
        // A surface that cannot report usage charges zero; even under
        // a one-token cap the agent stays admitted.
        for _ in 0..50 {
            p.consume_tokens(Some("agent"), 0);
        }
        let (d, _g) = p.try_admit_at(Some("agent"), Instant::now());
        assert_eq!(d, AgentBudgetDecision::Allow);
    }

    #[test]
    fn requests_per_minute_is_unchanged_by_token_consumption() {
        let p = policy(serde_json::json!({
            "requests_per_minute": 2,
            "tokens_per_hour": 1000,
            "on_exceed": "deny"
        }));
        let start = Instant::now();
        // Charging the hourly budget must not drain the per-minute
        // bucket: the two sub-budgets stay independent.
        p.consume_tokens(Some("agent"), 500);
        let (d1, _g1) = p.try_admit_at(Some("agent"), start);
        let (d2, _g2) = p.try_admit_at(Some("agent"), start);
        let (d3, _g3) = p.try_admit_at(Some("agent"), start);
        assert_eq!(d1, AgentBudgetDecision::Allow);
        assert_eq!(d2, AgentBudgetDecision::Allow);
        assert!(matches!(
            d3,
            AgentBudgetDecision::Deny {
                reason: AgentBudgetExceedReason::RequestsPerMinute
            }
        ));
    }

    #[test]
    fn token_sink_charges_the_key_it_was_built_with() {
        let p = Arc::new(policy(serde_json::json!({
            "tokens_per_hour": 100,
            "on_exceed": "deny"
        })));
        let sink = AgentBudgetTokenSink::new(Arc::clone(&p), Some("agent".to_string()));
        sink.consume(100);
        let (d, _g) = p.try_admit_at(Some("agent"), Instant::now());
        assert!(matches!(
            d,
            AgentBudgetDecision::Deny {
                reason: AgentBudgetExceedReason::TokensPerHour
            }
        ));
        // A different agent's budget is untouched by the charge.
        let (d, _g) = p.try_admit_at(Some("other"), Instant::now());
        assert_eq!(d, AgentBudgetDecision::Allow);
    }

    #[test]
    fn empty_string_agent_id_is_treated_as_anonymous() {
        let p = policy(serde_json::json!({
            "requests_per_minute": 60,
            "on_exceed": "deny"
        }));
        let start = Instant::now();
        let (d, _g) = p.try_admit_at(Some(""), start);
        assert_eq!(d, AgentBudgetDecision::SkippedAnonymous);
    }

    #[test]
    fn requests_per_minute_unset_admits_freely() {
        let p = policy(serde_json::json!({
            "burst": 4,
            "on_exceed": "deny"
        }));
        let start = Instant::now();
        // 100 sequential calls with guards dropped immediately stay
        // under the burst cap of 4 and incur no request-budget check.
        for _ in 0..100 {
            let (d, _g) = p.try_admit_at(Some("agent"), start);
            assert_eq!(d, AgentBudgetDecision::Allow);
        }
    }

    #[test]
    fn refills_after_a_minute_resets_budget() {
        let p = policy(serde_json::json!({
            "requests_per_minute": 60,
            "on_exceed": "deny"
        }));
        let start = Instant::now();
        for _ in 0..60 {
            let _ = p.try_admit_at(Some("a"), start);
        }
        // 60 seconds later the bucket has fully refilled.
        let later = start + Duration::from_secs(61);
        let (d, _g) = p.try_admit_at(Some("a"), later);
        assert_eq!(d, AgentBudgetDecision::Allow);
    }

    #[test]
    fn debug_impl_renders() {
        let p = policy(serde_json::json!({"requests_per_minute": 60, "burst": 4}));
        let s = format!("{p:?}");
        assert!(s.contains("AgentBudgetPolicy"));
        assert!(s.contains("requests_per_minute"));
    }

    #[test]
    fn rejects_invalid_config() {
        assert!(AgentBudgetPolicy::from_config(serde_json::json!({"burst": 0})).is_err());
        assert!(
            AgentBudgetPolicy::from_config(serde_json::json!({"requests_per_minute": -1.0}))
                .is_err()
        );
    }

    // --- WOR-2315: cluster-shared requests_per_minute ---

    /// Store double that counts per key the way Redis `INCR` does, over
    /// both the sync and the async trait, so one fake covers every
    /// attach shape the policy supports.
    ///
    /// Counting per key rather than globally is what gives the
    /// two-replica test its teeth: instances that derived different keys
    /// would each get a full budget and the test would fail, which is
    /// precisely the defect being fixed. `fail` turns every increment
    /// into an error, which is what a Redis blip looks like from here.
    struct CountingStore {
        counts: Mutex<HashMap<String, i64>>,
        calls: AtomicU32,
        fail: bool,
    }

    impl CountingStore {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                counts: Mutex::new(HashMap::new()),
                calls: AtomicU32::new(0),
                fail: false,
            })
        }

        fn failing() -> Arc<Self> {
            Arc::new(Self {
                counts: Mutex::new(HashMap::new()),
                calls: AtomicU32::new(0),
                fail: true,
            })
        }

        /// Every distinct counter key the store has seen, sorted.
        fn keys(&self) -> Vec<String> {
            let mut keys: Vec<String> = self.counts.lock().keys().cloned().collect();
            keys.sort();
            keys
        }

        /// How many increments reached the store, error or not.
        fn calls(&self) -> u32 {
            self.calls.load(Ordering::Acquire)
        }

        fn bump(&self, key: &[u8]) -> anyhow::Result<i64> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            if self.fail {
                anyhow::bail!("store unreachable");
            }
            let mut counts = self.counts.lock();
            let entry = counts
                .entry(String::from_utf8_lossy(key).into_owned())
                .or_insert(0);
            *entry += 1;
            Ok(*entry)
        }
    }

    impl KVStore for CountingStore {
        fn get(&self, _key: &[u8]) -> anyhow::Result<Option<bytes::Bytes>> {
            Ok(None)
        }
        fn put(&self, _key: &[u8], _value: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
        fn delete(&self, _key: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
        fn scan_prefix(&self, _prefix: &[u8]) -> anyhow::Result<Vec<(bytes::Bytes, bytes::Bytes)>> {
            Ok(Vec::new())
        }
        fn incr_with_ttl(&self, key: &[u8], _ttl_secs: u64) -> anyhow::Result<i64> {
            self.bump(key)
        }
    }

    #[async_trait::async_trait]
    impl AsyncKVStore for CountingStore {
        async fn get(&self, _key: &[u8]) -> anyhow::Result<Option<bytes::Bytes>> {
            Ok(None)
        }
        async fn put(&self, _key: &[u8], _value: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
        async fn put_with_ttl(
            &self,
            _key: &[u8],
            _value: &[u8],
            _ttl_secs: u64,
        ) -> anyhow::Result<()> {
            Ok(())
        }
        async fn incr_with_ttl(&self, key: &[u8], _ttl_secs: u64) -> anyhow::Result<i64> {
            self.bump(key)
        }
        async fn delete(&self, _key: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn without_a_store_the_async_path_is_the_local_path() {
        // The single-node deployment, which must not notice this change
        // at all: same cap, same reason, same anonymous handling the
        // sync entry point has always had.
        let p = policy(serde_json::json!({
            "requests_per_minute": 2,
            "on_exceed": "deny"
        }));
        let (d1, _g1) = p.try_admit_async(Some("cursor")).await;
        let (d2, _g2) = p.try_admit_async(Some("cursor")).await;
        let (d3, _g3) = p.try_admit_async(Some("cursor")).await;
        assert_eq!(d1, AgentBudgetDecision::Allow);
        assert_eq!(d2, AgentBudgetDecision::Allow);
        assert!(matches!(
            d3,
            AgentBudgetDecision::Deny {
                reason: AgentBudgetExceedReason::RequestsPerMinute
            }
        ));
        let (anon, _g4) = p.try_admit_async(None).await;
        assert_eq!(anon, AgentBudgetDecision::SkippedAnonymous);
    }

    #[tokio::test]
    async fn two_replicas_sharing_a_store_enforce_one_combined_cap() {
        // The defect this change fixes. Before it, each instance held
        // its own bucket of 2, so the pair admitted 4 against a
        // configured cap of 2, and a ten-pod deployment multiplied every
        // operator's number by ten.
        let store = CountingStore::new();
        let attach = |p: AgentBudgetPolicy| {
            p.with_async_store(
                Some(Arc::clone(&store) as Arc<dyn AsyncKVStore>),
                "origin-a",
            )
        };
        let replica_a = attach(policy(serde_json::json!({
            "requests_per_minute": 2,
            "on_exceed": "deny"
        })));
        let replica_b = attach(policy(serde_json::json!({
            "requests_per_minute": 2,
            "on_exceed": "deny"
        })));

        let (d1, _g1) = replica_a.try_admit_async(Some("claude-code-cli")).await;
        let (d2, _g2) = replica_b.try_admit_async(Some("claude-code-cli")).await;
        let (d3, _g3) = replica_a.try_admit_async(Some("claude-code-cli")).await;
        let (d4, _g4) = replica_b.try_admit_async(Some("claude-code-cli")).await;
        assert_eq!(d1, AgentBudgetDecision::Allow);
        assert_eq!(d2, AgentBudgetDecision::Allow);
        assert!(
            matches!(
                d3,
                AgentBudgetDecision::Deny {
                    reason: AgentBudgetExceedReason::RequestsPerMinute
                }
            ),
            "the third request in the window must be refused whichever replica takes it"
        );
        assert!(matches!(d4, AgentBudgetDecision::Deny { .. }));

        // One key, not one per replica. The fake counts per key, so a
        // pair that derived different keys would each have had a full
        // budget and the assertions above could not have held.
        assert_eq!(
            store.keys().len(),
            1,
            "replicas must share one counter, saw {:?}",
            store.keys()
        );

        // A different agent still has a budget of its own.
        let (other, _g5) = replica_a.try_admit_async(Some("cursor")).await;
        assert_eq!(other, AgentBudgetDecision::Allow);
    }

    #[test]
    fn the_window_key_rolls_over_on_the_epoch_boundary() {
        // A `None` handle still names the origin, which is all the key
        // derivation needs.
        let p = policy(serde_json::json!({ "requests_per_minute": 60 }))
            .with_async_store(None, "origin-a");
        // 1_700_000_040 is a minute boundary and 1_700_000_099 is the
        // last second before the next one.
        let first = p.window_key("claude-code-cli", 1_700_000_040);
        let last = p.window_key("claude-code-cli", 1_700_000_099);
        let rolled = p.window_key("claude-code-cli", 1_700_000_100);
        assert_eq!(first, "sbproxy:ab:origin-a:rpm:claude-code-cli:1700000040");
        assert_eq!(
            last, first,
            "every second inside one minute counts into one key"
        );
        assert_eq!(rolled, "sbproxy:ab:origin-a:rpm:claude-code-cli:1700000100");
    }

    #[tokio::test]
    async fn a_store_error_admits_the_request_the_way_rate_limit_does() {
        // Fail open, the posture `RateLimitPolicy::allow_with_info_async`
        // takes on the same failure. A budget that failed closed while
        // the rate limiter beside it failed open would be behavior an
        // operator cannot predict, and it would turn a Redis blip into a
        // cluster-wide outage rather than a degraded budget.
        let store = CountingStore::failing();
        let p = policy(serde_json::json!({
            "requests_per_minute": 1,
            "on_exceed": "deny"
        }))
        .with_async_store(
            Some(Arc::clone(&store) as Arc<dyn AsyncKVStore>),
            "origin-a",
        );

        for i in 0..5 {
            let (d, _g) = p.try_admit_async(Some("agent")).await;
            assert_eq!(
                d,
                AgentBudgetDecision::Allow,
                "request {i} must be admitted while the store is down"
            );
        }
        // Every one of them reached the store, so admission is not
        // quietly falling back to the local bucket, which under this cap
        // of 1 would have refused the second request.
        assert_eq!(store.calls(), 5);
    }

    #[tokio::test]
    async fn the_sync_store_enforces_the_same_shared_window() {
        // `with_store` is the pre-async handle the pipeline attaches
        // alongside the async one. It reaches the same keyspace through
        // `spawn_blocking`, so a deployment carrying only the sync
        // handle is clustered too.
        let store = CountingStore::new();
        let p = policy(serde_json::json!({
            "requests_per_minute": 1,
            "on_exceed": "deny"
        }))
        .with_store(Some(Arc::clone(&store) as Arc<dyn KVStore>), "origin-a");

        let (d1, _g1) = p.try_admit_async(Some("agent")).await;
        let (d2, _g2) = p.try_admit_async(Some("agent")).await;
        assert_eq!(d1, AgentBudgetDecision::Allow);
        assert!(matches!(
            d2,
            AgentBudgetDecision::Deny {
                reason: AgentBudgetExceedReason::RequestsPerMinute
            }
        ));

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        assert_eq!(store.keys(), vec![p.window_key("agent", now_secs)]);
    }

    #[tokio::test]
    async fn a_burst_denial_does_not_spend_a_shared_window_slot() {
        // The clustered mirror of
        // `denied_burst_does_not_drain_request_budget`. The local path
        // consumes a request token and refunds it when burst denies; a
        // fixed-window increment cannot be refunded, so the shared path
        // consults burst first and spends a window slot only for a
        // request that got past it.
        let store = CountingStore::new();
        let p = policy(serde_json::json!({
            "requests_per_minute": 10,
            "burst": 1,
            "on_exceed": "deny"
        }))
        .with_async_store(
            Some(Arc::clone(&store) as Arc<dyn AsyncKVStore>),
            "origin-a",
        );

        let (d1, g1) = p.try_admit_async(Some("agent")).await;
        let (d2, _g2) = p.try_admit_async(Some("agent")).await;
        assert_eq!(d1, AgentBudgetDecision::Allow);
        assert!(matches!(
            d2,
            AgentBudgetDecision::Deny {
                reason: AgentBudgetExceedReason::Burst
            }
        ));
        assert_eq!(
            store.calls(),
            1,
            "the burst-denied request must not have touched the shared counter"
        );

        // The admitted request's permit still releases on drop.
        drop(g1);
        assert_eq!(p.in_flight_count("agent"), 0);
    }
}
