# ADR: Per-agent metric-label cardinality (Wave 1 / A1.1)

*Last modified: 2026-04-30*

## Status

Accepted. Coordinates with `adr-agent-class-taxonomy.md` (G1.1) and is consumed by G1.6 (per-agent metric labels), Q1.5 (metrics snapshot test), and Q1.14 (cardinality budget regression).

## Context

Wave 1 G1.6 adds `agent_id`, `agent_class`, `agent_vendor`, `payment_rail`, and `content_shape` to the existing labelled counters and histograms (`sbproxy_requests_total`, `sbproxy_policy_triggers_total`, the access log). Each new label multiplies the live series count of every metric that carries it. Without an explicit budget, a single misbehaving deployment can blow past Prometheus's per-series memory floor and OOM the metric scrape.

`crates/sbproxy-observe/src/cardinality.rs` already ships a `CardinalityLimiter` with a single workspace-wide cap (default 1000 unique values per label name) and an `__other__` sentinel for over-cap demotion. That existing tool is the foundation; what is missing is a per-metric, per-label policy that says which label values are allowed in the first place, what the budget is, and what the degradation behaviour looks like when a budget is exhausted.

The agent-class taxonomy ADR (G1.1) already bounds `agent_id` to "members of the catalog plus three sentinels." That bound is the only thing that makes per-agent metrics tractable. This ADR formalizes the bound and extends it across every label introduced in Wave 1.

## Decision

Define a per-metric label budget. Enforce it at the metric-update site via a thin wrapper around the existing `CardinalityLimiter`. Document the allowed value set per label so reviewers can flag a PR that adds a new untrusted label dimension.

### Per-metric budget table

For each Wave 1 labelled metric, this table is the source of truth. The series count is the worst-case product of the configured per-label caps, not a separately enforced number.

| Metric | Labels | Per-label cap | Worst-case series |
|---|---|---|---|
| `sbproxy_requests_total` | `hostname`, `method`, `status`, `agent_id`, `agent_class`, `agent_vendor`, `payment_rail`, `content_shape` | hostname=200, method=8, status=12, agent_id=200, agent_class=8, agent_vendor=20, payment_rail=6, content_shape=5 | 9.2e9 nominal, capped at 250k by the global series ceiling (see degradation policy below) |
| `sbproxy_policy_triggers_total` | `hostname`, `policy_type`, `action`, `agent_id`, `agent_class` | hostname=200, policy_type=20, action=8, agent_id=200, agent_class=8 | 5.1e6 nominal, capped at 100k by the global ceiling |
| `sbproxy_request_duration_seconds` | `hostname`, `agent_class`, `payment_rail` | hostname=200, agent_class=8, payment_rail=6 | 9.6k |
| `sbproxy_ai_tokens_total` | `hostname`, `provider`, `direction`, `agent_class` | hostname=200, provider=24, direction=2, agent_class=8 | 76.8k |
| `sbproxy_property_count_distinct` | `workspace_id` (HLL value, not label) | n/a | 1 series per workspace |
| `sbproxy_session_count_distinct` | `workspace_id` | n/a | 1 series per workspace |
| `sbproxy_user_count_distinct` | `workspace_id` | n/a | 1 series per workspace |
| `sbproxy_ledger_redeem_total` | `agent_id`, `agent_vendor`, `payment_rail`, `result` | agent_id=200, agent_vendor=20, payment_rail=6, result=5 | 1.2e5, expected p95 1k |
| `sbproxy_property_dropped_total` | `reason` | reason=5 | 5 |
| `sbproxy_session_dropped_total` | `reason` | reason=3 | 3 |
| `sbproxy_user_dropped_total` | `reason` | reason=4 | 4 |
| `sbproxy_user_cardinality_capped_total` | `workspace_id` | workspace_id=2000 | 2000 |
| `sbproxy_label_demotion_total` | `metric`, `label` | metric=20, label=12 | 240 |

The "nominal" worst-case is the product of caps and is rarely realised; in practice each pair of labels is highly correlated (an agent_id maps to exactly one agent_vendor and one agent_class). The "global series ceiling" is a runtime guardrail, not a per-label cap.

### Allowed values per label

`agent_id`, `agent_class`, `agent_vendor`: must come from the agent-class registry (`adr-agent-class-taxonomy.md`). Any value outside the catalog is replaced with the appropriate sentinel before the metric update:

- An unmatched UA-only signal that does not correspond to a registry entry maps to `agent_id="unknown"`, `agent_class="unknown"`, `agent_vendor="unknown"`.
- An anonymous Web Bot Auth request maps to `agent_id="anonymous"`, `agent_class="anonymous"`, `agent_vendor="anonymous"`.
- A non-agent request maps to `agent_id="human"`, `agent_class="human"`, `agent_vendor="human"`.

The metric-update site never accepts arbitrary strings for these labels. The compiled enum of allowed values is generated from the agent-class catalog at server boot and embedded in the metric handle so a misuse is a type error, not a runtime cardinality blow-up.

`payment_rail`: closed enum, six values: `none`, `x402`, `mpp_card`, `mpp_stablecoin`, `stripe_fiat`, `lightning`. New rails added in later waves require an ADR amendment.

`content_shape`: closed enum, five values: `html`, `markdown`, `json`, `pdf`, `other`. The same shape labels surface in the access log and the ledger payload.

`hostname`: capped at 200 unique values per workspace, demoted to `__other__` past the cap. This is unchanged from today's `CardinalityLimiter` policy. The cap is workspace-scoped, not global, so a noisy tenant cannot starve a quiet one.

`workspace_id` on the `_count_distinct` HLL gauges: capped at 2000 unique workspaces, demoted to `__other__` past the cap. Beyond that scale, operators are expected to configure a sharded Prometheus deployment or use the ClickHouse event store directly.

`reason` and `result` labels (drop counters, redeem result): closed enums declared at metric-registration time. Adding a new value requires an ADR amendment to the metric's owning ADR.

### Hot-key protection

A hot key is a label tuple that is created and updated faster than the rest combined. Two protections, both implemented as wrappers in `sbproxy-observe`:

1. **Creation rate-limit per (metric, label-tuple).** The first time a never-seen label tuple is observed for a metric, the wrapper consults a per-(metric, label-tuple) token bucket. Default refill rate is 50 distinct new tuples per second per metric, with a burst of 200. Attempts to mint a fresh series past the bucket fall back to `__other__` for the offending label and increment `sbproxy_label_demotion_total{metric, label}`. The bucket resets on metric reset (e.g. process restart), not on a wall clock.

2. **Global series ceiling per metric.** Each metric has a hard cap (250k for `sbproxy_requests_total`, 100k for `sbproxy_policy_triggers_total`, 50k otherwise). When the live series count for a metric exceeds the cap, *every* fresh tuple gets `__other__` for the highest-cardinality label until the count falls back below the cap. The wrapper logs a `metric_cardinality_capped` event so operators see the ceiling fire.

The token-bucket and ceiling are both extensions of the existing `CardinalityLimiter`; the wrapper composes the two checks into one `sanitize_tuple(metric, labels) -> Vec<String>` call that the metric handles invoke.

### Degradation policy

When a budget is exhausted, we **degrade, not drop**:

- The metric update still happens, with the offending label(s) replaced by `__other__`. No request is rejected, no error is logged at the request path.
- `sbproxy_label_demotion_total{metric, label}` increments. Operators alert on this counter being non-zero.
- One `tracing::warn!` per (metric, label) pair per minute records the demotion at server level. Beyond the first warning we suppress to avoid flooding the log.

Dropping the metric update entirely would create gaps in `sbproxy_requests_total` that look like a traffic dip; this is much worse than a slightly-aggregated bucket.

### What this ADR does NOT decide

- The metric *names* and which Wave 1 labels they carry. That is owned by G1.6 (sbproxy-rust). This ADR is the budget and value-set policy that G1.6 applies.
- The Prometheus scrape configuration, alerting thresholds, or dashboards. Owned by A1.6 (SLO catalog) and B1.6/B1.7 (dashboards/alerts).
- Per-tenant cardinality fairness in multi-tenant enterprise deployments. The current cap is per-process; a per-workspace fair-share is a future ADR if needed.

## Consequences

- The metric handles take a closed enum or a registry-derived list as their label parameter type, so the compiler refuses arbitrary strings. The `CardinalityLimiter` becomes a runtime safety net for the few labels that have to accept variable input (`hostname`, `workspace_id`).
- `/metrics` series count is bounded by construction. Q1.14 (cardinality budget regression) loads a fixture multi-tenant traffic profile and asserts `wc -l < /metrics` stays under a fixed ceiling.
- A new Wave-2-onwards label addition is an explicit ADR step. The change cost is the right one: labels that go on `sbproxy_requests_total` are forever, deletions break dashboards.
- Hot-key protection means a misbehaving client that mints a fresh `User-Agent` per request cannot drive `agent_id`-equivalent labels off the rails. The taxonomy bound prevents that scenario for `agent_id` directly; the token bucket catches whatever sneaks in via `hostname` or `workspace_id`.
- Operators get one observable signal (`sbproxy_label_demotion_total`) for "your fleet is brushing the cardinality budget." That signal lets capacity planning happen before the metric scrape OOMs.

## Alternatives considered

**Free-form `agent_id` as a Prometheus label.** Rejected. A misconfigured client that rolls a fresh UA per request would create one series per request. Even with the existing `CardinalityLimiter`, the demotion threshold (1000 default) is reached in seconds under a small DDoS, and the legitimate values get mixed with attacker-injected ones in `__other__`.

**Drop the metric update on overflow rather than demote.** Rejected. Dropped updates create gaps in counters that look like real traffic dips, masking incidents. Demotion preserves the rate-of-change signal at the cost of label fidelity, which is the right trade.

**Single global label cap, no per-metric budget.** Rejected. `sbproxy_requests_total` carries fundamentally more labels than `sbproxy_session_dropped_total`. A one-size cap either over-budgets the small metrics (wastes limiter memory) or under-budgets the large ones (drops legitimate traffic into `__other__`).

**Move per-agent counts to ClickHouse only, drop them from `/metrics` entirely.** Considered, but rejected for Wave 1. Operators rely on Prometheus for the basic SLO signal (request rate, error rate, latency), and "request rate by agent" is a load-bearing dashboard. ClickHouse is the right home for high-cardinality dimensions (per-`user_id`, per-`session_id`); the agent-class taxonomy keeps `agent_id` low enough for Prometheus to carry it.

## References

- `docs/AIGOVERNANCE-BUILD.md` §4.1 (Wave 1 architect task A1.1, qa tasks Q1.5 and Q1.14, sbproxy-rust task G1.6).
- `crates/sbproxy-observe/src/cardinality.rs` (existing `CardinalityLimiter` and `OTHER_LABEL` sentinel).
- `crates/sbproxy-observe/src/metrics.rs` (existing metric handles and label sets).
- Companion ADRs: `adr-agent-class-taxonomy.md` (the source of truth for `agent_id` / `agent_class` / `agent_vendor` value sets).
- Helicone parity ADRs that already exclude high-cardinality fields from `/metrics`: `adr-custom-properties.md`, `adr-session-id.md`, `adr-user-id.md`.
