# AI chargeback and spend forecasting
*Last modified: 2026-08-26*

`sbproxy_ai::billing` (WOR-2672) is per-event usage attribution,
chargeback rollups, unified bill generation, and spend forecasting for
AI gateway traffic. It layers onto this crate's existing usage-sink
seam rather than duplicating it, and holds no durable state of its own.

## Layered on the existing usage sink

`ChargebackTracker` implements [`sbproxy_ai::usage_sink::UsageSink`],
the same trait `JsonlFileSink`, `WebhookSink`, `LangfuseSink`, and
`DatadogSink` implement: register it once, and every completed AI
gateway call's `LlmUsageEvent` reaches it automatically, the same way it
already reaches whichever other sinks are configured.

Turn it on from config alone, the same way as the other sinks.
`usage_sinks` is a field of the `ai_proxy` action, so it belongs under
the origin that serves the AI traffic being attributed, not at the top
level of `sb.yml`:

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          provider_type: openai
          api_key: ${OPENAI_API_KEY}
          default_model: gpt-4o-mini
          models: [gpt-4o-mini]
      usage_sinks:
        - type: chargeback
          max_entries: 10000
          max_workspaces: 1000
          max_teams: 1000
```

One chargeback sink is allowed per `ai_proxy` origin; config load rejects a
second.

All three limits are optional and the values above are the defaults. Raw
entries retain the newest `max_entries` rows. Workspace and team maps
reserve one of their configured rows for `"__other__"`; once a map is
full, new caller-provided names fold into that row without losing their
tokens, request count, or cost. Names and other raw string fields are
capped at 256 bytes before retention. Caller-supplied literal
`"unattributed"` and `"__other__"` dimension values are escaped with a
deterministic digest suffix so they cannot impersonate the internal
missing/overflow buckets on the legacy v1 or CSV surfaces.

The configured instance remains queryable after the sink is registered.
Use authenticated `GET /admin/ai-chargeback` for the process-local JSON
view or `GET /admin/ai-chargeback.csv` for workspace/team rollups. Both
exports are deployment-wide: an operator carrying a
`proxy.admin.operators[].tenant` restriction is refused with `403`,
because the team and project rollups aggregate across tenants and no
narrowed view of them can be correct. The
JSON export includes retained raw entries, all rollups, and
`recorded_entries`, `evicted_entries`, `collapsed_workspace_events`, and
`collapsed_team_events`. `schema_version` defaults to `1`;
`schema_version=2` keeps typed dimensions, and `limit` + `cursor` page
only the retained raw `entries` while rollups and counters remain whole
on every page. JSON and CSV are written directly from borrowed tracker
state into a 512 KiB capped response buffer; CSV never snapshots the raw
entry window. An export that exceeds the cap returns `413`. Retry an
oversized JSON page with a smaller `limit`; for an oversized CSV export,
use the paged JSON route. Prometheus exports the process totals as
`sbproxy_ai_chargeback_entries_evicted_total{origin}` and
`sbproxy_ai_chargeback_rollups_collapsed_total{dimension="workspace"|"team",origin}`,
the closed refusal counter
`sbproxy_ai_chargeback_refusals_total{reason,origin}`, the sticky
completeness counter
`sbproxy_ai_chargeback_incomplete_total{reason,origin}`, and the admin
boundary refusal counter
`sbproxy_admin_chargeback_export_refusals_total{format,reason}`. `origin`
names the compiled origin whose sink owns the tracker, so a deployment
running several `ai_proxy` origins can tell whose finance data went
incomplete without reconstructing it from the admin route. Its
cardinality is the configured origin roster.

An embedding can also construct a tracker directly when it needs a typed
handle:

```rust,ignore
use sbproxy_ai::billing::ChargebackTracker;
use sbproxy_ai::usage_sink::UsageSink;
use std::sync::Arc;

let tracker = Arc::new(ChargebackTracker::new());
// Keep `tracker` (the concrete type) for later queries, and hand a
// clone to wherever your embedding registers usage sinks:
let sink: Arc<dyn UsageSink> = tracker.clone();
```

Workspace attribution keys on the event's `tenant_id` (this crate's
multi-tenant boundary); team/project chargeback keys on the event's own
`team` / `project` attribution fields (`SB-Attr-Team`, governed project
tags; see [ai-gateway.md#per-request-attribution](ai-gateway.md#per-request-attribution)).
Either falls back to `"unattributed"` when the caller never set the
corresponding header, so a live tracker never silently drops a record
for lacking a tag; the money was still spent.

### Storage: none

The tracker is in-memory only, by design (WOR-2661 forbids a hard
external-store dependency for this port). Rollups cover the lifetime of
the process, while raw-entry retention is a bounded recent window. An
embedder that needs durable or cross-replica totals periodically exports
`ChargebackTracker::snapshot()` into its own store. The admin endpoints do
not claim persistence across a restart.

### Employee-scoped chargeback: not ported

The enterprise source's per-employee rollup (behind
`#[cfg(feature = "employee-binding")]`, keyed by SSO subject with a
four-level hierarchical budget walk) is not ported. `employee_binding`
is being rescoped on a separate branch (WOR-2667); this port does not
wait on that landing, and `ChargebackTracker` / `WorkspaceTotals` work
standalone at the workspace level without it.

## Workspace and team rollups

```rust,ignore
let team_totals = tracker.total_by_team(); // HashMap<team, cost_usd>
let workspace_totals = tracker.workspace_totals_snapshot(); // HashMap<tenant_id, WorkspaceTotals>
```

## Unified billing statements

Generate a complete bill from one atomic tracker snapshot. This refuses a
period whenever retained rows, all-time rollups, eviction evidence, or refusal
counters cannot prove that the statement is complete:

```rust,ignore
use sbproxy_ai::billing::generate_bill_from_snapshot;

let snapshot = tracker.snapshot();
let period_start = snapshot
    .earliest_retained_timestamp
    .as_deref()
    .expect("example recorded rows");
let latest = chrono::DateTime::parse_from_rfc3339(
    snapshot
        .latest_retained_timestamp
        .as_deref()
        .expect("example recorded rows"),
)
.expect("stored timestamp remains RFC 3339")
.with_timezone(&chrono::Utc);
let period_end = latest
    .checked_add_signed(chrono::TimeDelta::seconds(1))
    .expect("example window stays representable")
    .to_rfc3339();
let bill = generate_bill_from_snapshot(&snapshot, period_start, &period_end)?;
for item in &bill.line_items {
    println!("{} / {}: {} requests, {} tokens, ${:.2}",
        item.provider, item.model, item.requests, item.tokens, item.cost);
}
println!("total: ${:.2}", bill.total);
# Ok::<(), sbproxy_ai::billing::BillError>(())
```

Bounds accept RFC 3339 timestamps or `YYYY-MM-DD` at UTC midnight.
Malformed bounds, empty/reversed periods, malformed entry timestamps,
invalid costs, and arithmetic overflow return `BillError`; an
August-labeled bill cannot silently include July or September usage or a
wrapped monetary aggregate.

### Caller-asserted-complete retained slices

The lower-level retained-slice API is available only when the caller has an
independent completeness guarantee (for example, the requested period is
known to fit wholly inside retention):

```rust,ignore
use sbproxy_ai::billing::generate_bill;

let entries = tracker.entries_snapshot();
let bill = generate_bill(&entries, "2026-08-01", "2026-09-01")?;
# Ok::<(), sbproxy_ai::billing::BillError>(())
```

## Spend forecasting

Given a caller-supplied series of past daily spend, project future spend
and detect budget exhaustion:

```rust,ignore
use sbproxy_ai::billing::{days_until_exhaustion, forecast_spend, will_exceed_budget, UsageDataPoint};

let history = vec![
    UsageDataPoint::new(1, 42.0),
    UsageDataPoint::new(2, 48.0),
    UsageDataPoint::new(3, 51.0),
];
// Each returns None rather than an answer when the series or the budget
// cannot support one, so a non-finite cost cannot read as "under budget".
let next_30_days = forecast_spend(&history, 30);
let over_budget = will_exceed_budget(&history, 1500.0, 30);
let days_left = days_until_exhaustion(&history, 1500.0); // None if burn rate is zero
```

This is a different question from `sbproxy_ai::budget`'s predictive
soft-landing (warn/downgrade thresholds against the CURRENT period's
cap, evaluated fresh on every request): forecasting extrapolates a
trend across historical data to answer "at this burn rate, when do we
run out," which soft-landing does not attempt. The two compose: run a
forecast periodically over the same cost feed soft-landing already
degrades against, to raise the budget before soft-landing has to act.

## Runnable example

[`crates/sbproxy-ai/examples/ai_chargeback_billing.rs`](../crates/sbproxy-ai/examples/ai_chargeback_billing.rs)
feeds a `ChargebackTracker` a batch of synthetic `LlmUsageEvent`s across
two tenants and three provider/model pairs, derives a bill window from
the retained snapshot timestamps, then prints team totals, a unified
bill, and a 30-day forecast:

```bash
cargo run -p sbproxy-ai --example ai_chargeback_billing
```

## See also

- [ai-usage-ledger.md](ai-usage-ledger.md) - the hash-chained, signed
  verifiable usage ledger, a different (tamper-evident) usage sink.
- [value-ledger-economics.md](value-ledger-economics.md) - local-vs-cloud
  savings accounting, a different cost question (what serving locally
  saved) than chargeback's (who spent what).
