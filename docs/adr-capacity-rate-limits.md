# ADR: Capacity model and rate-limit budget

*Last modified: 2026-05-03*

## Status

Accepted. Builds on `adr-metric-cardinality.md` (hot-key protection at the metric layer), `adr-slo-alert-taxonomy.md` (per-pillar SLOs and alert tiers), and `adr-admin-action-audit.md` (audit envelope for escalation events). Implementation lands in rate-limit middleware and the operator runbook (RB-RATE-LIMIT-ESCALATION).

## Context

The proxy has to defend three new request budgets:

1. **HTTP request budget.** Inbound traffic per-route, plus wallet endpoints, DCR registration endpoints, and audit-log export endpoints expose attack surfaces that need explicit ceilings.
2. **Wallet-debit budget.** Wallet debits are state-mutating, billable, and serialised in the wallet adapter. Without a per-tenant ceiling, a single misbehaving agent can saturate the wallet write path and starve every other workspace.
3. **DCR registration budget.** Dynamic Client Registration (RFC 7591) lets agents register without operator intervention. This is a registration-storm vector; we need a budget here before the feature ships.

Beyond the budgets themselves, three operational concerns also need a written policy:

- **Coordinated headers.** Customers integrating sbproxy build automation against rate-limit responses. Without RFC 9239 / IETF rate-limit headers, every customer rolls their own back-off.
- **Abuse escalation path.** Telemetry alone is not enough; sustained abuse needs an automatic suspend mechanism with manual review.
- **Hot-key protection.** Metric cardinality protection prevents Prometheus label blow-ups. Capacity budgets prevent request-budget blow-ups. The two policies must share the same `workspace_id` semantics so the dashboards line up.

## Decision

### Per-tenant ceilings

All ceilings are per `workspace_id` unless noted. Defaults are tuned for the standard tier; higher tiers override via the workspace plan record.

| Budget | Sustained | Burst | Hard ceiling | Inner per-(workspace, route) cap |
|---|---|---|---|---|
| Inbound HTTP requests | 1000 rps | 2000 rps | 10000 rps (higher tier) | 100 rps default per route |
| Wallet debits | 100 ops/sec | 200 ops/sec | 500 ops/sec (higher tier) | n/a (single inner namespace) |
| DCR registrations | 10/hour | 20/hour | 100/hour (higher tier) | n/a |
| Audit log writes (emitter side) | 1000 events/sec | 2000 events/sec | 5000 events/sec | n/a |
| Audit log read/export | 10 rps | 20 rps | 50 rps | n/a |

The "inner cap" column is the hot-key protection: each `(workspace_id, route)` pair has its own bucket inside the workspace bucket. A burst of 1000 rps on a single route is throttled to the inner 100 rps even though the workspace bucket has headroom. This stops a misbehaving client from monopolising one expensive route at the expense of the rest of the workspace's traffic.

The hard ceilings are the absolute upper limit per workspace; passing the hard ceiling requires a contract amendment, not a config change. The portal surfaces the customer's current plan ceiling and current consumption.

**Audit log emitter backpressure.** When the audit emitter exceeds 1000 events/sec sustained for 30 seconds, events drop into an in-memory deadletter queue (bounded at 10k events per workspace, matching the messenger bound). The deadletter drain pages via `SLO-AUDIT-WRITE`; sustained overflow indicates a misbehaving caller and triggers the abuse escalation path below.

**Wallet debit serialisation.** Wallet debits are serialised per-`wallet_id` inside the adapter; the 100/sec budget is per-workspace, not per-wallet. A workspace with N wallets sees aggregate 100/sec across all of them. This matches the wallet adapter's single-writer model and avoids cross-wallet contention surprises.

### Coordinated rate-limit headers (RFC 9239 + draft-ietf-httpapi-ratelimit-headers)

Every rate-limited response, **including 402 Payment Required responses** for paid agents, carries the full set:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 12
RateLimit-Limit: 1000
RateLimit-Remaining: 0
RateLimit-Reset: 12
RateLimit-Policy: 1000;w=60
```

- `Retry-After`: integer seconds. Always present on 429 / 402 / 503 responses where retry is allowed.
- `RateLimit-Limit`: requests permitted in the active window.
- `RateLimit-Remaining`: requests remaining in the current window. Zero on the response that triggered the limit.
- `RateLimit-Reset`: seconds until the bucket refills enough for one more request. Coordinates with `Retry-After`.
- `RateLimit-Policy`: human-parseable policy descriptor (`<limit>;w=<window-seconds>`).

402 responses for paid agents (the ledger path) carry the same headers when the budget shape is rate-related ("you are over your debit-rate ceiling"), distinct from the price-required path ("you owe a redeem"). An automated client sees the budget shape from the headers and can back off without parsing the response body.

The headers are emitted by a single `RateLimitHeaders` helper in `crates/sbproxy-modules/src/middleware/rate_limit_headers.rs`; every limit-aware module composes through it so we don't drift across implementations.

### Abuse escalation (typed enum, monotonic)

Escalation is monotonic: you can only ratchet up, never down, until either the manual-review queue resets you or the cooldown expires.

```rust
pub enum AbuseTier {
    /// Telemetry only. Counts in `sbproxy_rate_limit_soft_total{tenant,route}`.
    /// No customer-visible response change. Used to tune ceilings before
    /// they bite. Lasts indefinitely while consumption stays under hard
    /// ceiling but over soft threshold.
    Soft,

    /// Rate-limit response with full RateLimit headers. Counts in
    /// `sbproxy_rate_limit_throttle_total{tenant,route}`. Audit row
    /// emitted (action: Other("rate_limit_throttle"), target: Tenant).
    Throttle,

    /// Workspace dropped to 1 rps for 60 minutes after 1000 consecutive
    /// throttle events within a 5-minute window. Audit row emitted with
    /// reason="auto_suspend_threshold_exceeded". Customer notification
    /// webhook fires.
    AutoSuspend { until: Instant, reason: String },

    /// Workspace placed in the manual-review queue. Portal surfaces the
    /// pending entry to the operator. Restoration requires explicit
    /// operator action, which is itself audited
    /// (action: Approve, target: Tenant).
    ManualReview { queued_at: Instant, reason: String },
}
```

Transition rules:

- `Soft` to `Throttle`: when consumption crosses the sustained ceiling on any of the four budgets above.
- `Throttle` to `AutoSuspend`: 1000 consecutive throttle events in any 5-minute window. The workspace's effective ceiling drops to 1 rps; webhook fires; audit row records the trigger.
- `AutoSuspend` cooldown: 60 minutes. After cooldown, the workspace returns to `Throttle` (not `Soft`); a second auto-suspend within 24 hours promotes to `ManualReview`.
- `ManualReview` exit: only via a portal admin action with a non-empty `reason`. The action is audited; the workspace returns to `Soft` after a 24-hour observation window.

The escalation tier is stored in workspace metadata so it survives a process restart. The audit envelope records every transition.

### Hot-key complement to metric cardinality

Metric cardinality protection (`adr-metric-cardinality.md`) protects label cardinality. This ADR protects HTTP request budgets. The two share the `workspace_id` label semantics so dashboards line up:

- The `sbproxy_rate_limit_throttle_total{tenant,route}` counter uses the same `tenant` (= `workspace_id`) label as the per-tenant counts.
- The `sbproxy_label_demotion_total{metric,label}` counter and the `sbproxy_rate_limit_throttle_total` counter both alert into the same workspace abuse dashboard.
- A workspace that hits both `__other__` label demotion AND `Throttle` tier within the same 5-minute window is a strong signal that something has gone wrong; the joint condition feeds a higher-priority alert (`SLO-ABUSE-COMPOSITE`).

Hot-key protection inside the request budget itself uses the same token-bucket pattern as the metric protection: a per-(workspace, route) inner bucket sits inside the workspace bucket, and the inner bucket is what catches a single hot route from monopolising the workspace ceiling.

### Plan tier overrides

Workspace plan records carry per-budget overrides:

```rust
pub struct WorkspacePlan {
    pub tier: PlanTier,
    pub http_rps_sustained: u32,
    pub http_rps_burst: u32,
    pub wallet_ops_sustained: u32,
    pub dcr_per_hour: u32,
    pub audit_writes_sustained: u32,
    pub abuse_threshold_throttle_to_suspend: u32,  // default 1000
    pub auto_suspend_cooldown_secs: u32,           // default 3600
}
```

Plan changes are audited (`AuditAction::Update`, `AuditTarget::Tenant`). The compiled handler chain reloads the plan at config-reload time; in-flight requests see the old plan.

### Metrics and alerts

All new metrics carry the `workspace_id` label per the cardinality budget (capped at 2000):

- `sbproxy_rate_limit_soft_total{tenant,route}`: count of soft-tier observations.
- `sbproxy_rate_limit_throttle_total{tenant,route}`: count of throttled responses.
- `sbproxy_rate_limit_suspend_total{tenant}`: count of auto-suspend triggers.
- `sbproxy_wallet_debit_throttle_total{tenant}`: count of debit-rate throttles.
- `sbproxy_dcr_throttle_total{tenant}`: count of DCR registration throttles.
- `sbproxy_audit_writes_dropped_total{tenant,reason}`: count of audit-log writes that overflowed the deadletter queue.

Alert thresholds (per `adr-slo-alert-taxonomy.md` tier conventions):

- `RATE-SUSPEND` (page): any auto-suspend for a paying-tier workspace. Operator-on-call investigates; this is rare and load-bearing.
- `RATE-DEADLETTER-DRAIN` (page): audit deadletter drain backed up >5 minutes. Coordinates with `SLO-AUDIT-WRITE`.
- `RATE-MANUAL-REVIEW-PENDING` (ticket): manual-review queue depth >0 for 24h.
- `RATE-COMPOSITE` (page): joint metric demotion + capacity throttle for the same workspace inside 5 min.

### What this ADR does NOT decide

- The exact token-bucket implementation (leaky-bucket vs. GCRA vs. sliding-window). This ADR pins the budget numbers and the header contract.
- Per-region ceiling reconciliation for multi-region deployments; the per-workspace ceilings are local-region.
- Customer-facing rate-limit dashboards (portal). The metric names are pinned so the dashboard has stable inputs.
- Plan-tier billing model. Out of scope.

## Consequences

- One header contract across every limit-aware response. Customers write one back-off helper, not five.
- The auto-suspend tier is a real production knob: a misbehaving agent in a paying customer's workspace will trigger it, and the customer receives a webhook. The 60-minute cooldown is short enough that legitimate customers recover without operator intervention; the manual-review escalation catches repeat offenders.
- The 5 budgets above (HTTP, wallet, DCR, audit-write, audit-read) are independently configurable, which means the workspace plan record grows. Acceptable; better than a single conflated cap.
- Hot-key protection at the request layer means a misbehaving client cannot starve other routes inside the same workspace. The workspace ceiling and the inner per-route ceiling are a two-level structure, but customers only see one ceiling in the portal (the workspace one); the inner ceiling is operational, not customer-facing.
- The composite alert (label-cardinality demotion plus capacity throttle joint condition) is a load-bearing signal for "something is genuinely off in this workspace" and reduces alert fatigue compared to two independent alerts.
- The audit log itself is rate-limited (1000 events/sec emitter side) which sounds counterintuitive, but the deadletter queue + page on overflow is the right answer. We never silently drop audit; we either persist or page.

## Alternatives considered

**Single global rate-limit configuration; no per-budget separation.** Rejected. HTTP requests, wallet debits, and DCR registrations have wildly different cost profiles. A single ceiling either over-budgets cheap routes or under-budgets expensive ones. Per-budget separation is operational complexity now in exchange for predictable performance later.

**Drop the manual-review tier; auto-suspend only.** Rejected. Repeat-offender customers need a human eyeball; auto-suspend cooldown is a temporary measure, not a permanent one. The portal manual-review queue is where ops triage real abuse.

**Use Cloudflare-style adaptive rate-limiting (model-based per-tenant predictions).** Considered. Rejected; the operational complexity of an ML-driven limit is too high for a substrate ADR. Static ceilings + plan overrides cover the current need.

**Skip the inner per-(workspace, route) cap.** Rejected. Without it, a single hot route monopolises the workspace's request ceiling and quiet routes starve. The two-level structure is the minimum needed to keep the workspace experience predictable.

**Headers only on 429, not on 402.** Rejected. 402 for paid agents has the same back-off shape as 429 for rate-limited ones; emitting the headers on both gives automated clients a uniform retry contract.

## References

- Companion ADRs: `adr-metric-cardinality.md`, `adr-slo-alert-taxonomy.md`, `adr-admin-action-audit.md`, `adr-disaster-recovery-retention.md`, `adr-db-migration-policy.md`.
- IETF rate-limit headers draft: <https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/>.
- RFC 9239 (token-bucket guidance, the rate-limit-policy header structure): <https://datatracker.ietf.org/doc/html/rfc9239>.
- Google SRE Workbook chapter on adaptive throttling: <https://sre.google/workbook/managing-load/>.
