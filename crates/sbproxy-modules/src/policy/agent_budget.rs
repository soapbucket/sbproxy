// SPDX-License-Identifier: BUSL-1.1
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
//! * `tokens_per_hour`: rolling LLM-token budget per `agent_id`. The
//!   policy exposes the bookkeeping surface; upstream token accounting
//!   is wired in via [`AgentBudgetPolicy::consume_tokens`] once the
//!   AI-usage tracker reports actual usage. Configuring the field
//!   without that wiring is a no-op for slice 1.
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
//! ## Out of scope for slice 1
//!
//! * Cluster-shared budgets. Each proxy enforces its own local view.
//! * Upstream token accounting. The token bucket exists in the API
//!   but is only consumed when the AI gateway calls
//!   [`AgentBudgetPolicy::consume_tokens`]. A follow-up wires that
//!   call into `sbproxy-ai`'s usage tracker.

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;
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
}

const SHARED_ANONYMOUS_KEY: &str = "__anonymous__";
const DEFAULT_MAX_AGENTS: usize = 10_000;

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
        })
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

    /// Record that `n` upstream tokens were consumed by `agent_id`.
    ///
    /// Wired into the AI gateway's usage tracker so the hourly token
    /// budget reflects actual model usage. `None` agent ids are
    /// ignored under `on_anonymous: skip`; under `shared` they
    /// charge the shared bucket.
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
            .finish()
    }
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
        // Slice 1 contract: configuring tokens_per_hour without
        // wiring `consume_tokens` is a no-op. Admission must not
        // depend on the limit until somebody charges the bucket.
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
}
