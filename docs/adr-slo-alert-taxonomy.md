# ADR: SLO catalog and alert taxonomy (Wave 1 / A1.6)

*Last modified: 2026-04-30*

## Status

Accepted. Builds on `adr-observability.md` (A1.4) and the per-agent metric label policy (A1.1). Implementation lands in B1.6 (dashboards), B1.7 (Prometheus rules), and Q1.13 / Q1.14 (regression tests).

## Context

The build plan (`docs/AIGOVERNANCE-BUILD.md` § 15.4) sketches an initial SLO table. This ADR formalizes it: per-pillar SLI definitions, target levels, burn-rate alert windows, alert-tier semantics, runbook-stub format, and the per-metric cardinality budget that B1.12 enforces in CI.

We need this in Wave 1 because:

1. The PromQL alert rules (B1.7) need a fixed set of SLI expressions to compute.
2. The dashboards (B1.6) need to surface SLO compliance and burn rate.
3. The runbook (S1.3) needs a stable alert-ID-to-section mapping so on-call has somewhere to land.
4. The cardinality budget (Q1.14) blocks PRs that explode `/metrics`. Without a written budget, that test has no source of truth.

## Decision

### SLO catalog v1

The full table. SLOs are 30-day rolling windows unless noted. The error budget is `1 - SLO`. Every entry has an SLI expression in PromQL form and a tier mapping.

| ID | Pillar | SLI | Target | Window | Tier on breach |
|---|---|---|---|---|---|
| SLO-AVAIL-INBOUND | Substrate | inbound request availability (non-5xx / total) | 99.9% | 30d | Page |
| SLO-LATENCY-P95 | Substrate | inbound p95 latency excl. rail wait | < 30 ms | 5 min sustained | Ticket |
| SLO-LATENCY-P99 | Substrate | inbound p99 latency excl. rail wait | < 50 ms | 5 min sustained | Page |
| SLO-LEDGER-REDEEM | Ledger | redeem success rate | 99.95% | 30d | Page |
| SLO-LEDGER-LATENCY | Ledger | redeem p99 latency | < 200 ms | 5 min sustained | Ticket |
| SLO-RAIL-SETTLE | Rails (per rail) | settle success rate | 99.5% | 7d | Page |
| SLO-RAIL-QUORUM | Rails | facilitator quorum (≥ 1 healthy per chain) | 100% | instant | Page (immediate) |
| SLO-AUDIT-WRITE | Audit | batch-write success | 100% | 24h | Page (immediate) |
| SLO-AUDIT-LATENCY | Audit | emit-to-durable latency p99 | < 5 s | 1h sustained | Ticket |
| SLO-DR-RESTORE | DR | restore drill | succeed monthly | calendar | Page on missed |
| SLO-WEBHOOK-IN | Webhooks (in) | inbound verification success | 99.9% | 7d | Ticket |
| SLO-WEBHOOK-OUT | Webhooks (out) | outbound delivery success (incl. retries) | 99% | 7d | Ticket |
| SLO-CONFIG-RELOAD | Config | hot-reload success | 100% | 24h | Page |
| SLO-BOT-AUTH-DIR | Bot Auth | directory freshness (TTL not exceeded) | 99.9% | 7d | Ticket |
| SLO-CARD-BUDGET | Substrate | per-metric series count under cap | 100% | continuous | Log-only (CI gate) |

The PromQL expression for each SLI is pinned in `deploy/alerts/slo-recording.rules.yml` (B1.7). Example for `SLO-AVAIL-INBOUND`:

```
sum(rate(sbproxy_requests_total{status_class!="5xx"}[5m]))
/
sum(rate(sbproxy_requests_total[5m]))
```

Recording rules pre-compute the SLI at 1m, 5m, 1h, 6h, and 24h windows so burn-rate alerts are cheap.

### Burn-rate alert formula

Multi-window, multi-burn-rate alerts (Google SRE workbook chapter 5, "Multiwindow, Multi-Burn-Rate Alerts"). For an SLO with target `T` and error budget `B = 1 - T`, the burn rate at window `W` is:

```
burn_rate(W) = error_rate(W) / B
```

An alert fires when **both**:

1. The short-window burn rate exceeds `R_short`.
2. The long-window burn rate exceeds `R_long`.

The double check protects against single-bucket noise. The standard pairs (page tier):

| Window pair | Burn-rate threshold | Time-to-budget-burn |
|---|---|---|
| 5m AND 1h | 14.4× | 2% of monthly budget in 1h |
| 30m AND 6h | 6× | 5% of monthly budget in 6h |
| 2h AND 24h | 3× | 10% of monthly budget in 24h |

Page tier fires the 14.4× / 6× pairs. Ticket tier fires the 3× pair. Log-only tier records the burn but does not page.

For SLOs with non-30d windows (rail settle: 7d; audit batch-write: 24h), the thresholds rescale: error budget is computed against the actual window, and the same burn-rate multipliers apply. The PromQL recording rule generator (a small Rust binary in `crates/sbproxy-observe/tools/slo-rules-gen`) takes the catalog as input and emits the matching `*-burn.rules.yml`.

### Alert tiers

Three tiers, each with explicit on-call semantics:

**Page (P1, immediate human action).** Goes to PagerDuty, on-call rotation acks within 15 minutes. Examples: ledger down (`SLO-LEDGER-REDEEM` 14.4× burn), audit-log write failure (`SLO-AUDIT-WRITE`), rail quorum loss (`SLO-RAIL-QUORUM`), restore-drill miss (`SLO-DR-RESTORE`), KYA trust-anchor expired (Wave 5), security finding from threat detector (Wave 5).

**Ticket (P2, next business day).** Files an issue in the on-call queue (we use the GitHub Issues label `oncall:ticket`). Examples: classifier drift (Wave 5), latency p95 sustained breach, webhook delivery failure rate, anomaly noise budget exceeded (Wave 5), fingerprint capture overhead breach (Wave 5).

**Log-only (P3).** Fires a Prometheus alert that gets recorded in Alertmanager but routes to the log destination only (no human notification). Examples: cardinality near budget (90% of cap), deprecated-flag use, exemplar emission rate dropping (informational).

Every alert in `deploy/alerts/*.rules.yml` carries a `severity` label of `page`, `ticket`, or `log`. Alertmanager routing trees in `deploy/alertmanager/routes.yml` translate `severity` to receiver. Tier promotion (a ticket alert becoming a page after sustained breach) is configured per-alert via secondary thresholds; the default is "no auto-promotion".

### Alert ID convention

Alert names follow `SBPROXY-<PILLAR>-<SLI>-<WINDOW>` and are required to be unique. The `SBPROXY-` prefix lets multi-tenant Alertmanager fleets disambiguate against other services. Example labels on a fired alert:

```
alertname:  SBPROXY-LEDGER-REDEEM-1H
severity:   page
slo_id:     SLO-LEDGER-REDEEM
runbook_id: RB-LEDGER-REDEEM
window:     1h
burn_rate:  14.4
```

The `runbook_id` label maps 1:1 to a section in `docs/operator-runbook.md` (S1.3 ships the skeleton). The Alertmanager "runbook URL" template is:

```
https://docs.sbproxy.dev/operator-runbook#{{ .Labels.runbook_id | toLower }}
```

Every paging alert MUST have a runbook entry. This is enforced by Q1.13 + a CI check in B1.12 that greps the runbook for every `runbook_id` referenced by `deploy/alerts/`.

### Runbook stub format

Every runbook section follows this template (markdown):

```markdown
### RB-LEDGER-REDEEM
*Symptom*: SBPROXY-LEDGER-REDEEM alert paging; ledger redeem success rate
under 99.95% with sustained burn.

*Quick checks (5 min)*:
1. Confirm ledger endpoint reachable from a proxy pod (`kubectl exec ...`).
2. Check the ledger dashboard panel "Redeem latency p99" for upstream slowness.
3. Check `sbproxy_ledger_circuit_breaker_state` for open breakers.

*Likely causes*:
- Ledger backend partial outage. Confirm with the ledger operator.
- HMAC key mismatch after rotation. Check `SBPROXY_LEDGER_HMAC_KEY`.
- Network egress saturation.

*Mitigations*:
- Failover to standby ledger via `kubectl set env ... SBPROXY_LEDGER_ENDPOINT=...`.
- Toggle the `policy.ai_crawl.ledger_optional` flag to allow soft-fail
  redemption while ledger recovers (revenue-impacting; record in incident).

*Escalation*: ledger operator on-call.

*Postmortem trigger*: any incident exceeding 30 min of sustained P1.
```

The skeleton is a Markdown lint-checked template. CI ensures every alert has matching `RB-*` headings.

### Per-metric cardinality budget

Cardinality is the number of distinct label combinations per metric family. The budget caps how many series each family can produce, and B1.12 / Q1.14 enforce it.

| Metric family | Cardinality cap | Notes |
|---|---|---|
| `sbproxy_requests_total` | 50 000 | Labels: `route`, `status_class`, `agent_class`, `rail`, `tenant_id`. `agent_id` is NOT a label. |
| `sbproxy_request_duration_seconds_bucket` | 100 000 | Same labels as above plus 10 buckets. |
| `sbproxy_policy_triggers_total` | 20 000 | Labels: `policy`, `decision`, `route`, `tenant_id`. |
| `sbproxy_ledger_redeem_total` | 5 000 | Labels: `result`, `tenant_id`. |
| `sbproxy_ledger_redeem_duration_seconds_bucket` | 10 000 | Plus buckets. |
| `sbproxy_outbound_request_total` | 30 000 | Labels: `target`, `result`, `tenant_id`. `target` is enum-bounded (stripe, ledger, registry, directory, kya, oauth, webhook). |
| `sbproxy_audit_emit_total` | 5 000 | Labels: `result`, `tenant_id`. |
| `sbproxy_webhook_in_total` | 10 000 | Labels: `provider`, `result`, `tenant_id`. |
| `sbproxy_webhook_out_total` | 10 000 | Labels: `subscription`, `result`, `tenant_id`. |
| `sbproxy_session_count_distinct` | 1 | HLL gauge; cardinality independent of session count. |
| `sbproxy_property_dropped_total` | 5 000 | Per `adr-custom-properties.md`. |
| `sbproxy_session_dropped_total` | 1 000 | Per `adr-session-id.md`. |

Hard rule: `agent_id`, `request_id`, `session_id`, `user_id` are **never** label values on Prometheus metrics. They are span attributes (per `adr-observability.md`) and log fields (per `adr-log-schema-redaction.md`) only. The per-agent label policy ADR (A1.1) further constrains `agent_id` aggregation.

`tenant_id` is bounded by the customer count plus a cap (default 1 000 tenants per proxy fleet); above the cap, the proxy refuses new tenants and pages on `SLO-CARD-BUDGET`.

The cardinality CI check (B1.12) loads a fixture multi-tenant traffic profile (`test/fixtures/cardinality-profile.yaml`), runs it through the proxy, scrapes `/metrics`, and asserts no metric family exceeds its cap. A new label on an existing metric requires updating the cap **in the same PR**.

### Game-day and chaos coverage

Per `docs/AIGOVERNANCE-BUILD.md` § 15.6:

- Wave 2: Stripe outage + ledger outage scenarios (Q2.14). Asserts `SLO-LEDGER-REDEEM` and `SLO-RAIL-SETTLE` alerts page correctly and the runbook matches reality.
- Wave 3: facilitator failover + Stripe webhook outage (Q3.18). Asserts `SLO-RAIL-QUORUM`.
- Wave 7: GA chaos battery (Q7.6) + 7-day soak (Q7.7).

Each game day MUST verify that:

1. Every paging alert that should fire, did.
2. No alert that shouldn't fire, did.
3. The runbook section linked from the page resolves to current procedure.

### What this ADR does NOT decide

- Per-tenant SLO overrides (premium tenants get tighter targets). Wave 6.
- Customer-facing SLA reporting (different from internal SLOs; legally binding). Wave 6.
- Tail-based trace sampling rules. Lives in the Wave 6 follow-up to `adr-observability.md`.
- Specific dashboard panel layouts. Lives in `deploy/dashboards/*.json` and the JSON's metadata, not this ADR.

## Consequences

- The PromQL recording-rule generator runs at CI time off this catalog; the rules are not hand-edited. Drift is impossible by construction.
- Every paging alert has a runbook section; on-call lands somewhere, never on a 404. Q1.13 regresses both directions.
- Cardinality budgets are enforced in CI, not in production. We catch the breach in PR, not at 3 a.m.
- Adding a new SLO is a doc edit (this ADR) plus a recording rule. Adding a new alert tier requires an Alertmanager routing tree change; the three-tier model is intentional friction against ad-hoc severity escalation.
- The `tenant_id` cap (1 000) is a real production limit. Multi-tenant fleets above that scale need sharding (multiple proxy fleets, each under the cap). That's a Wave 6 follow-up.

## Alternatives considered

**Single-window burn alerts (just check 1h burn).** Rejected. Single-window burns fire on transient spikes (one bad bucket) and miss slow degradations that don't cross the threshold in any single window. The two-window pattern is the SRE-workbook recommendation and balances alert fatigue against actual slow burns.

**Severity per-route instead of per-pillar.** Considered. Rejected because routes are tenant-defined and cardinality-explosive at the Alertmanager layer. Per-pillar plus per-tenant labels gives operators the same drill-down (filter Alertmanager by `tenant_id`) without the cardinality.

**Hard-coded cardinality cap (single number for all metrics).** Rejected. Different metrics have different natural cardinalities (`sbproxy_session_count_distinct` is one HLL gauge; `sbproxy_request_duration_seconds_bucket` is the cross product of routes and statuses and tenants). Per-family caps are necessary.

## References

- `docs/AIGOVERNANCE-BUILD.md` § 4.1 (A1.6), § 15.4 (SLO catalog initial cut), § 15.5 (alert tiering), § 15.6 (game days), § 17 (cross-pillar e2e matrix).
- Companion ADRs: `adr-observability.md` (A1.4), `adr-log-schema-redaction.md` (A1.5), per-agent label policy (`adr-agent-label-cardinality.md`, A1.1, to be written separately).
- Google SRE workbook chapter 5 (Multi-window, multi-burn-rate alerts).
- Implementation: `deploy/alerts/`, `deploy/dashboards/`, `crates/sbproxy-observe/tools/slo-rules-gen/`.
