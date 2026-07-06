//! WOR-1130: workspace rate-limit budget with a soft / throttle /
//! auto-suspend escalation state machine (the R2.3 / A2.5 contract).
//!
//! This is the workspace-wide ceiling that sits ahead of the per-origin
//! `rate_limiting` policy. A process-wide
//! [`RateLimitBudgetRegistry`](crate::rate_limit_budget::RateLimitBudgetRegistry) is
//! installed at startup from the top-level `rate_limits:` config and is
//! reached by:
//!   - the `rate_limit_budget` policy enforcer (per request), and
//!   - the admin endpoints (`/api/rate_limits/effective`,
//!     `/api/rate_limits/clock/advance`, `/api/audit/recent`).
//!
//! Tiers (per A2.5):
//!   - `Normal`  - traffic under the soft threshold.
//!   - `Soft`    - above the soft threshold but under the sustained
//!     ceiling; emits `sbproxy_rate_limit_total{result="soft"}` but does
//!     NOT 429 the client.
//!   - `Throttle` - the burst ceiling was hit; the request is 429'd with
//!     the full RFC 9239 header set.
//!   - `AutoSuspend` - sustained throttling crossed the abuse threshold;
//!     the workspace ceiling drops to 1 rps for the cool-down window and
//!     an audit row + `sbproxy_rate_limit_suspend_total` are emitted.
//!     After the cool-down the workspace returns to `Throttle`.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use sbproxy_config::types::{RateLimitClockMode, RateLimitsConfig};

/// Max audit rows retained by the in-memory sink.
const AUDIT_RING_CAP: usize = 256;

/// Process-wide budget registry. Installed once at startup; `None` when
/// no top-level `rate_limits:` block is configured.
static REGISTRY: OnceLock<Arc<RateLimitBudgetRegistry>> = OnceLock::new();

/// Install the registry from the parsed config. Idempotent: a second
/// install (e.g. a reload) is ignored, matching the other startup
/// singletons; the running budget keeps its accumulated state.
pub fn install_registry(cfg: &RateLimitsConfig) {
    let _ = REGISTRY.set(Arc::new(RateLimitBudgetRegistry::new(cfg)));
}

/// Borrow the installed registry, when one exists.
pub fn registry() -> Option<Arc<RateLimitBudgetRegistry>> {
    REGISTRY.get().cloned()
}

/// A monotonic clock that the test harness can advance deterministically.
#[derive(Debug)]
enum Clock {
    System { base: Instant },
    Manual { offset: Mutex<Duration> },
}

impl Clock {
    fn new(mode: RateLimitClockMode) -> Self {
        match mode {
            RateLimitClockMode::System => Clock::System {
                base: Instant::now(),
            },
            RateLimitClockMode::Manual => Clock::Manual {
                offset: Mutex::new(Duration::ZERO),
            },
        }
    }

    /// "Now" as a monotonic `Duration` since the registry was built.
    fn now(&self) -> Duration {
        match self {
            Clock::System { base } => base.elapsed(),
            Clock::Manual { offset } => *offset.lock().unwrap(),
        }
    }

    /// Advance a manual clock. No-op (returns false) for the system
    /// clock so the admin endpoint can report "not a manual clock".
    fn advance(&self, by: Duration) -> bool {
        match self {
            Clock::System { .. } => false,
            Clock::Manual { offset } => {
                *offset.lock().unwrap() += by;
                true
            }
        }
    }
}

/// Escalation tier exposed to the admin endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Traffic under the soft threshold; no metric, no throttle.
    Normal,
    /// Above the soft threshold but still admitted; emits the soft metric.
    Soft,
    /// Burst ceiling hit; the request is 429'd with the RFC 9239 headers.
    Throttle,
    /// Sustained throttling crossed the abuse threshold; ceiling drops to 1 rps.
    AutoSuspend,
}

impl Tier {
    /// The tier name as surfaced by the admin endpoint and metric labels.
    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::Normal => "Normal",
            Tier::Soft => "Soft",
            Tier::Throttle => "Throttle",
            Tier::AutoSuspend => "AutoSuspend",
        }
    }
}

/// A token bucket evaluated against the injectable clock.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    /// Refill rate in tokens per second.
    rate: f64,
    last: Duration,
}

impl TokenBucket {
    fn new(capacity: u32, rate: u32, now: Duration) -> Self {
        Self {
            tokens: capacity as f64,
            capacity: capacity as f64,
            rate: rate as f64,
            last: now,
        }
    }

    fn refill(&mut self, now: Duration) {
        if now > self.last {
            let elapsed = (now - self.last).as_secs_f64();
            self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
            self.last = now;
        }
    }

    /// Try to consume one token. Returns `true` when admitted.
    fn try_take(&mut self, now: Duration) -> bool {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Seconds until one token is available (ceil, min 1) for the
    /// `Retry-After` / `RateLimit-Reset` headers.
    fn reset_secs(&self) -> u64 {
        if self.tokens >= 1.0 || self.rate <= 0.0 {
            0
        } else {
            ((1.0 - self.tokens) / self.rate).ceil().max(1.0) as u64
        }
    }
}

/// Per-workspace runtime state.
#[derive(Debug)]
struct WorkspaceState {
    bucket: TokenBucket,
    tier: Tier,
    consecutive_throttles: u32,
    /// Clock time the auto-suspend cool-down ends.
    suspend_until: Option<Duration>,
    /// 1-second window for soft-tier rate observation.
    window_sec: u64,
    window_count: u32,
}

/// One admin-action audit row (the in-memory sink).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditRow {
    /// RFC 3339 timestamp of the admin action.
    pub timestamp: String,
    /// The action taken, e.g. `rate_limit_suspend`.
    pub action: String,
    /// The kind of entity the action targeted, e.g. `workspace`.
    pub target_kind: String,
    /// The identifier of the targeted entity, e.g. the workspace name.
    pub target_id: String,
    /// Human-readable explanation of why the action fired.
    pub reason: String,
}

/// A per-workspace budget snapshot for the admin API (WOR-1764).
#[derive(Debug, Clone, serde::Serialize)]
pub struct WorkspaceStatus {
    /// The workspace identifier.
    pub workspace: String,
    /// Current escalation tier (`normal`, `soft`, `throttle`, `auto_suspend`).
    pub tier: String,
    /// True while the workspace is auto-suspended (ceiling dropped to 1 rps).
    pub suspended: bool,
    /// Seconds left on the suspend cool-down, when one is active.
    pub cooldown_secs: Option<u64>,
}

/// The per-request decision returned to the policy enforcer.
#[derive(Debug, Clone)]
pub struct BudgetDecision {
    /// `false` -> respond 429 with the headers below.
    pub allowed: bool,
    /// The escalation tier the workspace is in after this check.
    pub tier: Tier,
    /// The sustained ceiling that backs `RateLimit-Limit` / `-Policy`.
    pub limit: u64,
    /// Tokens left in the bucket, the `RateLimit-Remaining` value.
    pub remaining: u64,
    /// Seconds until the next token, the `RateLimit-Reset` / `Retry-After` value.
    pub reset_secs: u64,
    /// Window seconds for the `RateLimit-Policy` `;w=` parameter.
    pub window_secs: u64,
}

/// The process-wide workspace budget: the token buckets, escalation
/// state, and in-memory audit ring shared by the enforcer and the admin
/// endpoints.
pub struct RateLimitBudgetRegistry {
    sustained: u32,
    burst: u32,
    soft_threshold: Option<u32>,
    abuse_threshold: u32,
    cooldown: Duration,
    clock: Clock,
    workspaces: Mutex<HashMap<String, WorkspaceState>>,
    audit: Mutex<VecDeque<AuditRow>>,
}

impl RateLimitBudgetRegistry {
    fn new(cfg: &RateLimitsConfig) -> Self {
        Self {
            sustained: cfg.workspace_default.http_rps_sustained.max(1),
            burst: cfg.workspace_default.http_rps_burst.max(1),
            soft_threshold: cfg.workspace_default.soft_threshold_rps,
            abuse_threshold: cfg.escalation.abuse_threshold_throttle_to_suspend.max(1),
            cooldown: Duration::from_secs(cfg.escalation.auto_suspend_cooldown_secs as u64),
            clock: Clock::new(cfg.clock),
            workspaces: Mutex::new(HashMap::new()),
            audit: Mutex::new(VecDeque::with_capacity(AUDIT_RING_CAP)),
        }
    }

    fn new_state(&self, now: Duration) -> WorkspaceState {
        WorkspaceState {
            bucket: TokenBucket::new(self.burst, self.sustained, now),
            tier: Tier::Normal,
            consecutive_throttles: 0,
            suspend_until: None,
            window_sec: now.as_secs(),
            window_count: 0,
        }
    }

    /// Resolve any pending cool-down expiry for `st` at `now`. Returns
    /// the workspace to `Throttle` (per A2.5, one step down, not Soft).
    fn settle_cooldown(st: &mut WorkspaceState, now: Duration, sustained: u32, burst: u32) {
        if st.tier == Tier::AutoSuspend {
            if let Some(until) = st.suspend_until {
                if now >= until {
                    st.tier = Tier::Throttle;
                    st.suspend_until = None;
                    st.consecutive_throttles = 0;
                    // Restore the full-rate bucket.
                    st.bucket = TokenBucket::new(burst, sustained, now);
                }
            }
        }
    }

    /// Per-request budget check for `workspace`. Emits soft / suspend
    /// metrics + the suspend audit row as side effects.
    pub fn check(&self, workspace: &str) -> BudgetDecision {
        let now = self.clock.now();
        let mut map = self.workspaces.lock().unwrap();
        let st = map
            .entry(workspace.to_string())
            .or_insert_with(|| self.new_state(now));

        Self::settle_cooldown(st, now, self.sustained, self.burst);

        // Effective ceiling: 1 rps while suspended, else the sustained
        // budget. The bucket already reflects the effective rate
        // (rebuilt on the suspend transition + the cool-down settle).
        let suspended = st.tier == Tier::AutoSuspend;
        let effective_limit = if suspended { 1 } else { self.sustained as u64 };

        // 1-second window bookkeeping for the soft-tier observation.
        if now.as_secs() != st.window_sec {
            st.window_sec = now.as_secs();
            st.window_count = 0;
        }
        st.window_count += 1;

        let admitted = st.bucket.try_take(now);
        let reset_secs = st.bucket.reset_secs();
        let remaining = st.bucket.tokens.floor().max(0.0) as u64;

        if admitted {
            st.consecutive_throttles = 0;
            // Soft tier: rate has reached the soft threshold (in rps,
            // counted over the 1-second window) but is still admitted.
            // `>=` so the warning fires on the request that reaches the
            // configured rps, not one past it.
            let soft = self
                .soft_threshold
                .map(|t| st.window_count >= t && !suspended)
                .unwrap_or(false);
            if soft {
                st.tier = Tier::Soft;
                record_rate_limit(workspace, "soft");
            } else if !suspended {
                st.tier = Tier::Normal;
            }
            BudgetDecision {
                allowed: true,
                tier: st.tier,
                limit: effective_limit,
                remaining,
                reset_secs,
                window_secs: 1,
            }
        } else {
            // Throttled.
            record_rate_limit(workspace, "throttle");
            st.consecutive_throttles = st.consecutive_throttles.saturating_add(1);
            if !suspended {
                st.tier = Tier::Throttle;
            }
            // Escalate to auto-suspend once sustained throttling crosses
            // the abuse threshold.
            if !suspended && st.consecutive_throttles >= self.abuse_threshold {
                st.tier = Tier::AutoSuspend;
                st.suspend_until = Some(now + self.cooldown);
                // Drop the effective ceiling to 1 rps.
                st.bucket = TokenBucket::new(1, 1, now);
                self.emit_suspend(workspace);
            }
            BudgetDecision {
                allowed: false,
                tier: st.tier,
                limit: if st.tier == Tier::AutoSuspend {
                    1
                } else {
                    effective_limit
                },
                remaining: 0,
                reset_secs: reset_secs.max(1),
                window_secs: 1,
            }
        }
    }

    fn emit_suspend(&self, workspace: &str) {
        record_suspend(workspace);
        let row = AuditRow {
            timestamp: chrono::Utc::now().to_rfc3339(),
            action: "rate_limit_suspend".to_string(),
            target_kind: "workspace".to_string(),
            target_id: workspace.to_string(),
            reason: format!(
                "auto_suspend_threshold_exceeded: {} consecutive throttles >= {}",
                self.abuse_threshold, self.abuse_threshold
            ),
        };
        // Mirror to the structured security_audit target for external
        // sinks, then retain in the in-memory ring for /api/audit/recent.
        tracing::warn!(
            target: "security_audit",
            action = %row.action,
            target_kind = %row.target_kind,
            target_id = %row.target_id,
            reason = %row.reason,
            "rate-limit auto-suspend"
        );
        let mut ring = self.audit.lock().unwrap();
        if ring.len() == AUDIT_RING_CAP {
            ring.pop_front();
        }
        ring.push_back(row);
    }

    /// Effective ceiling + tier for the admin endpoint. Settles any
    /// pending cool-down so a query after a manual-clock advance sees
    /// the post-cool-down tier.
    pub fn effective(&self, workspace: &str) -> (u64, Tier) {
        let now = self.clock.now();
        let mut map = self.workspaces.lock().unwrap();
        let st = map
            .entry(workspace.to_string())
            .or_insert_with(|| self.new_state(now));
        Self::settle_cooldown(st, now, self.sustained, self.burst);
        let rps = if st.tier == Tier::AutoSuspend {
            1
        } else {
            self.sustained as u64
        };
        (rps, st.tier)
    }

    /// Advance the manual clock. Returns `false` for a system clock.
    pub fn advance_clock(&self, by: Duration) -> bool {
        self.clock.advance(by)
    }

    /// The most recent audit rows, newest first, capped at `limit`.
    pub fn recent_audit(&self, limit: usize) -> Vec<AuditRow> {
        let ring = self.audit.lock().unwrap();
        ring.iter().rev().take(limit).cloned().collect()
    }

    /// Snapshot every tracked workspace's budget state for the admin API
    /// (WOR-1764). Settles any pending cool-down first so the reported
    /// tier is current. Sorted by workspace id.
    pub fn snapshot(&self) -> Vec<WorkspaceStatus> {
        let now = self.clock.now();
        let mut map = self.workspaces.lock().unwrap();
        let mut out: Vec<WorkspaceStatus> = map
            .iter_mut()
            .map(|(name, st)| {
                Self::settle_cooldown(st, now, self.sustained, self.burst);
                let suspended = st.tier == Tier::AutoSuspend;
                let cooldown_secs = st
                    .suspend_until
                    .and_then(|until| until.checked_sub(now))
                    .map(|d| d.as_secs());
                WorkspaceStatus {
                    workspace: name.clone(),
                    tier: st.tier.as_str().to_string(),
                    suspended,
                    cooldown_secs,
                }
            })
            .collect();
        out.sort_by(|a, b| a.workspace.cmp(&b.workspace));
        out
    }

    /// Manually clear a workspace's escalation, returning it to `Normal`
    /// and cancelling any auto-suspend cool-down (WOR-1764). Records an
    /// audit row. Returns `false` if the workspace is not tracked.
    pub fn resume(&self, workspace: &str) -> bool {
        let existed = {
            let mut map = self.workspaces.lock().unwrap();
            match map.get_mut(workspace) {
                Some(st) => {
                    st.tier = Tier::Normal;
                    st.suspend_until = None;
                    st.consecutive_throttles = 0;
                    true
                }
                None => false,
            }
        };
        if existed {
            let row = AuditRow {
                timestamp: chrono::Utc::now().to_rfc3339(),
                action: "rate_limit_resume".to_string(),
                target_kind: "workspace".to_string(),
                target_id: workspace.to_string(),
                reason: "manual resume via admin".to_string(),
            };
            tracing::info!(
                target: "security_audit",
                action = %row.action,
                target_kind = %row.target_kind,
                target_id = %row.target_id,
                reason = %row.reason,
                "rate-limit manual resume"
            );
            let mut ring = self.audit.lock().unwrap();
            if ring.len() == AUDIT_RING_CAP {
                ring.pop_front();
            }
            ring.push_back(row);
        }
        existed
    }
}

// Metrics live in sbproxy-observe (the only crate with prometheus as a
// normal dependency); these are thin aliases for readability.
use sbproxy_observe::metrics::{record_rate_limit, record_rate_limit_suspend as record_suspend};
