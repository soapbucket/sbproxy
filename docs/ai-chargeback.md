# AI chargeback and spend forecasting
*Last modified: 2026-08-22*

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

Turn it on from config alone, the same way as the other sinks:

```yaml
usage_sinks:
  - type: chargeback
    max_entries: 10000
    max_workspaces: 1000
    max_teams: 1000
```

All three limits are optional and the values above are the defaults. Raw
entries retain the newest `max_entries` rows. Workspace and team maps
reserve one of their configured rows for `"__other__"`; once a map is
full, new caller-provided names fold into that row without losing their
tokens, request count, or cost. Names and other raw string fields are
capped at 256 bytes before retention.

The configured instance remains queryable after the sink is registered.
Use authenticated `GET /admin/ai-chargeback` for the atomic JSON view or
`GET /admin/ai-chargeback.csv` for workspace/team rollups. The JSON export
includes retained raw entries, all rollups, and `recorded_entries`,
`evicted_entries`, `collapsed_workspace_events`, and
`collapsed_team_events`. Prometheus exports the process totals as
`sbproxy_ai_chargeback_entries_evicted_total` and
`sbproxy_ai_chargeback_rollups_collapsed_total{dimension="workspace"|"team"}`.

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

Aggregate the same tracker's per-event log into a printable bill, one
line item per (provider, model) pair:

```rust,ignore
use sbproxy_ai::billing::generate_bill;

let entries = tracker.entries_snapshot();
// Half-open period: August 1 inclusive through September 1 exclusive.
let bill = generate_bill(&entries, "2026-08-01", "2026-09-01")?;
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
two tenants and three provider/model pairs, then prints team totals, a
unified bill, and a 30-day forecast:

```bash
cargo run -p sbproxy-ai --example ai_chargeback_billing
```

## See also

- [ai-usage-ledger.md](ai-usage-ledger.md) - the hash-chained, signed
  verifiable usage ledger, a different (tamper-evident) usage sink.
- [value-ledger-economics.md](value-ledger-economics.md) - local-vs-cloud
  savings accounting, a different cost question (what serving locally
  saved) than chargeback's (who spent what).
