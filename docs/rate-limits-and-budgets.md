# Rate limits and budgets
*Last modified: 2026-05-03*

SBproxy defends five request budgets at every workspace boundary: inbound HTTP, wallet debits, DCR registrations, audit-log writes, and audit-log read/export. Each carries a sustained ceiling, a burst ceiling, a hard ceiling that requires a contract change to lift, and (for HTTP) an inner per-route bucket that protects quiet routes from a single hot route monopolising the workspace ceiling. RFC 9239-aligned headers tell automated clients exactly how to back off. A monotonic abuse-tier escalation handles the tail of misbehaving callers without operator intervention.

This guide is the operator companion to ADR `docs/adr-capacity-rate-limits.md`. It complements the metric-cardinality protection in `docs/adr-metric-cardinality.md`; the two share `workspace_id` semantics so the dashboards line up.

## Budgets at a glance

All ceilings are per `workspace_id` unless noted. Defaults are tuned for the SaaS plan tier; the enterprise plan tier and any operator-supplied plan record can override.

| Budget | Sustained | Burst | Hard ceiling | Inner per-(workspace, route) cap |
|---|---|---|---|---|
| Inbound HTTP requests | 1 000 rps | 2 000 rps | 10 000 rps (enterprise) | 100 rps default per route |
| Wallet debits | 100 ops/sec | 200 ops/sec | 500 ops/sec (enterprise) | n/a (single inner namespace) |
| DCR registrations | 10 per hour | 20 per hour | 100 per hour (enterprise) | n/a |
| Audit log writes (emitter side) | 1 000 events/sec | 2 000 events/sec | 5 000 events/sec | n/a |
| Audit log read / export | 10 rps | 20 rps | 50 rps | n/a |

Three notes on the table:

- **Inner cap is hot-key protection.** A burst of 1 000 rps on a single route is throttled to the inner 100 rps even when the workspace bucket has headroom. This stops a misbehaving client from monopolising one expensive route at the expense of the rest of the workspace's traffic.
- **Hard ceiling is a contract knob.** Passing the hard ceiling requires a contract amendment, not a config change. The portal surfaces the workspace's current plan ceiling and current consumption.
- **Wallet debits serialise per `wallet_id` inside the adapter.** The 100/sec budget is per-workspace, not per-wallet. A workspace with N wallets sees aggregate 100/sec across all of them. This matches the wallet adapter's single-writer model and avoids cross-wallet contention surprises.

## RFC 9239 headers

Every rate-limited response carries the full set, including 402 Payment Required for paid agents:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 12
RateLimit-Limit: 1000
RateLimit-Remaining: 0
RateLimit-Reset: 12
RateLimit-Policy: 1000;w=60
```

| Header | Meaning |
|---|---|
| `Retry-After` | Integer seconds. Always present on 429, 402, and 503 responses where retry is allowed. |
| `RateLimit-Limit` | Requests permitted in the active window. |
| `RateLimit-Remaining` | Requests remaining in the current window. Zero on the response that triggered the limit. |
| `RateLimit-Reset` | Seconds until the bucket refills enough for one more request. Coordinates with `Retry-After`. |
| `RateLimit-Policy` | Human-parseable policy descriptor, format `<limit>;w=<window-seconds>`. |

402 responses for paid agents carry the same headers when the budget shape is rate-related ("you are over your debit-rate ceiling"), distinct from the price-required path ("you owe a redeem"). An automated client sees the budget shape from the headers and can back off without parsing the response body.

The headers are emitted by a single `RateLimitHeaders` helper in `crates/sbproxy-modules/src/middleware/rate_limit_headers.rs`. Every limit-aware module composes through it so the implementation does not drift across surfaces.

## Abuse escalation: monotonic four-tier ladder

Escalation is monotonic. A workspace can only ratchet up, never down, until either the manual-review queue resets it or the cooldown expires.

```
Soft  ----[crosses sustained ceiling]---->  Throttle
Throttle ---[1000 throttle events / 5 min]--> AutoSuspend
AutoSuspend ---[60 min cooldown]----------> Throttle
Throttle ---[2nd auto-suspend within 24h]-> ManualReview
ManualReview ---[admin restore + 24h obs]-> Soft
```

```rust
pub enum AbuseTier {
    Soft,
    Throttle,
    AutoSuspend { until: Instant, reason: String },
    ManualReview { queued_at: Instant, reason: String },
}
```

### Soft

Telemetry only. Counts in `sbproxy_rate_limit_soft_total{tenant, route}`. No customer-visible response change. Used to tune ceilings before they bite. Lasts indefinitely while consumption stays under the hard ceiling but over the soft threshold.

### Throttle

Rate-limit response with the full RFC 9239 header set. Counts in `sbproxy_rate_limit_throttle_total{tenant, route}`. Audit row emitted with `action: AuditAction::Other("rate_limit_throttle")`, `target: AuditTarget::Tenant`.

### AutoSuspend

Workspace dropped to 1 rps for 60 minutes after 1 000 consecutive throttle events within a 5-minute window. Audit row emitted with `reason="auto_suspend_threshold_exceeded"`. The customer notification webhook fires through the outbound framework. After cooldown the workspace returns to `Throttle`, not `Soft`. A second auto-suspend within 24 hours promotes to `ManualReview`.

### ManualReview

Workspace placed in the manual-review queue. The portal surfaces the pending entry to the operator. Restoration requires explicit operator action with a non-empty `reason`. The action is itself audited (`action: Approve, target: Tenant`). The workspace returns to `Soft` after a 24-hour observation window.

### Persistence

The escalation tier is stored in workspace metadata so it survives a process restart. The audit envelope records every transition.

## Plan tier overrides

Workspace plan records carry per-budget overrides:

```rust
pub struct WorkspacePlan {
    pub tier: PlanTier,                              // Free, SaaS, Enterprise
    pub http_rps_sustained: u32,
    pub http_rps_burst: u32,
    pub wallet_ops_sustained: u32,
    pub dcr_per_hour: u32,
    pub audit_writes_sustained: u32,
    pub abuse_threshold_throttle_to_suspend: u32,    // default 1000
    pub auto_suspend_cooldown_secs: u32,             // default 3600
}
```

Plan changes are audited (`AuditAction::Update`, `AuditTarget::Tenant`). The compiled handler chain reloads the plan at config-reload time; in-flight requests see the old plan.

Storage location: a `workspace_plans` Postgres table next to `wallets`. The runbook covers the upgrade path for older deployments that did not have plan rows.

## Hot-key complement to cardinality protection

Two policies share `workspace_id` semantics so dashboards line up:

- The metric-cardinality budget protects metric-label cardinality. The cap per metric prevents `__other__` blowups.
- The capacity rate-limit budget protects HTTP request budgets. The token bucket per workspace prevents DoS.

The `sbproxy_rate_limit_throttle_total{tenant, route}` counter uses the same `tenant` (= `workspace_id`) label as the per-tenant counters in the cardinality budget. The two metrics feed the same workspace abuse dashboard. A workspace that hits both `__other__` demotion AND a `Throttle` tier inside the same 5-minute window is a strong signal that something is genuinely wrong; the joint condition feeds a higher-priority alert (`SLO-ABUSE-COMPOSITE`).

Hot-key protection inside the request budget itself uses the same token-bucket pattern: a per-(workspace, route) inner bucket sits inside the workspace bucket. The inner bucket catches a single hot route from monopolising the workspace ceiling.

## Audit-write backpressure

When the audit emitter exceeds 1 000 events/sec sustained for 30 seconds, events drop into an in-memory dead-letter queue (bounded at 10 000 events per workspace, matching the messenger bound). The dead-letter drain pages via `SLO-AUDIT-WRITE`. Sustained overflow indicates a misbehaving caller and triggers the abuse escalation path above.

The audit-log emitter being itself rate-limited sounds counterintuitive. The dead-letter queue plus page-on-overflow is the right answer: SBproxy never silently drops audit events. Either it persists, or the operator hears about it.

## Metrics

All carry the `workspace_id` label per the cardinality budget (capped at 2 000):

| Metric | Type | Labels |
|---|---|---|
| `sbproxy_rate_limit_soft_total` | counter | `tenant`, `route` |
| `sbproxy_rate_limit_throttle_total` | counter | `tenant`, `route` |
| `sbproxy_rate_limit_suspend_total` | counter | `tenant` |
| `sbproxy_wallet_debit_throttle_total` | counter | `tenant` |
| `sbproxy_dcr_throttle_total` | counter | `tenant` |
| `sbproxy_audit_writes_dropped_total` | counter | `tenant`, `reason` |

Alert thresholds (per `docs/adr-slo-alert-taxonomy.md` tier conventions):

| Alert | Tier | Triggers when |
|---|---|---|
| `RATE-SUSPEND` | page | Any auto-suspend for a paying-tier workspace. |
| `RATE-DEADLETTER-DRAIN` | page | Audit dead-letter drain backed up >5 minutes. Coordinates with `SLO-AUDIT-WRITE`. |
| `RATE-MANUAL-REVIEW-PENDING` | ticket | Manual-review queue depth >0 for 24 h. |
| `RATE-COMPOSITE` | page | Joint cardinality demotion + capacity throttle for the same workspace inside 5 min. |

## Operator workflows

### Identify the throttled tenant

```promql
topk(5, rate(sbproxy_rate_limit_throttle_total[5m]))
```

The route label is the secondary dimension; if a single route dominates, the inner per-route cap is doing its job and the workspace ceiling has headroom.

### Move a workspace out of `ManualReview`

The portal surfaces the queue. The admin action requires a non-empty `reason`; the audit row records who restored the workspace and why. The workspace returns to `Soft` after a 24-hour observation window during which any throttle event re-promotes to `ManualReview`.

The runbook procedure:

```
sbproxy-admin tenant abuse status --tenant tenant_42
sbproxy-admin tenant abuse restore --tenant tenant_42 --reason "incident #2603 root-caused"
```

Both commands emit `AdminAuditEvent`s.

### Tune a workspace's plan

Plan changes are audited. The runbook covers the upgrade procedure:

```
sbproxy-admin plan set --tenant tenant_42 --tier enterprise --reason "annual contract upgrade"
```

Setting `tier=enterprise` lifts every plan-relative ceiling to the enterprise default; a follow-up `set` per budget can fine-tune.

### Investigate composite alerts

`SLO-ABUSE-COMPOSITE` fires when both cardinality demotion and capacity throttle hit the same workspace inside a 5-minute window. The combination usually means either a real attack or a configuration that pushed legitimate traffic over both budgets. The runbook walks through:

1. Check the per-tenant cardinality demotion in Grafana.
2. Check the throttle and suspend counters.
3. Pull the audit log entries for the window.
4. If legitimate traffic, raise the plan tier or coordinate a contract change.
5. If abusive traffic, AutoSuspend should already have kicked in; if not, force a manual `ManualReview`.

## What this guide does NOT cover

- The exact token-bucket implementation (leaky-bucket, GCRA, sliding-window). Implementation detail in `crates/sbproxy-modules/src/middleware/rate_limit/`.
- Per-region ceiling reconciliation for multi-region deployments. Current ceilings are local-region.
- The customer-facing rate-limit dashboard (portal). Builder lane owns the dashboard; this guide pins the metric names.
- Plan-tier billing model (what a customer pays for "Enterprise"). Out of scope for the proxy.

## See also

- `docs/adr-capacity-rate-limits.md` - the budget table and abuse-tier policy.
- `docs/adr-metric-cardinality.md` - the metric-label cardinality companion.
- `docs/adr-slo-alert-taxonomy.md` - alert tier definitions.
- `docs/adr-admin-action-audit.md` - the audit envelope every transition emits.
- `docs/operator-runbook.md` - `RB-RATE-LIMIT-ESCALATION`, `RB-MANUAL-REVIEW`, plan-tuning procedures.
- `docs/observability.md` - the dashboards that visualise these metrics.
- IETF rate-limit headers draft: <https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/>.
- RFC 9239: <https://datatracker.ietf.org/doc/html/rfc9239>.
