# ADR: Billing hot path vs async path layering

*Last modified: 2026-05-03*

## Status

Accepted. Builds on `adr-http-ledger-protocol.md`, `adr-schema-versioning.md`, and `adr-webhook-security.md`. Pins the layering rule for any rail-bearing extension code.

## Context

A naive billing layer might invite a synchronous external rail call straight from the proxy's request-serving path. That layering does not survive production load.

Three problems with letting the proxy call a rail directly:

1. **Rail latency leaks into request p99.** A typical external-billing API round-trip is 80 to 200 ms p99. Adding that to every paid request makes the proxy's tail latency a function of an external system's tail latency, which we do not control.
2. **Rail outages become proxy outages.** When the rail degrades, every paid request fails. The proxy has no way to fall back to local state because the rail call is the source of truth in this layering.
3. **Credentials sit at the request edge.** A rail API key has to be reachable from the request-serving path. That is the worst place to keep a high-blast-radius credential.

The fix is the standard split: the proxy talks to a local-or-near-local service that owns the wallet; rail-specific code lives behind workers that consume an async-only trait.

This ADR pins the rule. It introduces a `LedgerClient` trait that is the only billing surface the proxy ever sees, and reserves a separate `BillingRail` trait for async workers.

## Decision

### Two traits, one rule

```rust
// HOT PATH. Lives in sbproxy-modules. The proxy calls only this.
// Synchronous (matches the existing reqwest::blocking::Client pattern in sbproxy-modules).
pub trait LedgerClient: Send + Sync {
    fn redeem(&self, token: &str, host: &str, path: &str, amount_micros: u64, currency: &str) -> Result<RedeemResult, LedgerError>;
    fn authorize(&self, token: &str, host: &str, path: &str, amount_micros: u64, currency: &str) -> Result<AuthorizeResult, LedgerError>;
    fn capture(&self, authorization_id: &str, amount_micros: u64) -> Result<CaptureResult, LedgerError>;
    fn refund_redemption(&self, redemption_id: &str, amount_micros: u64) -> Result<RefundResult, LedgerError>;
}

// ASYNC PATH. Consumed only by workers. NEVER by the proxy.
#[async_trait::async_trait]
pub trait BillingRail: Send + Sync {
    const VERSION: &'static str;
    fn name(&self) -> &str;

    /// Submit a batch of usage events to the rail. Idempotent on
    /// (idempotency_key, rail). Called by the metered-usage worker.
    async fn submit_usage(&self, batch: &[UsageEvent]) -> Result<SubmissionReceipt, RailError>;

    /// Verify and parse an inbound webhook payload that has already
    /// passed the InboundVerifier signature check. Returns the
    /// WalletMutation the caller should apply atomically. Called by
    /// the webhook worker. Idempotent on event_id.
    async fn handle_inbound_webhook(&self, event: WebhookPayload) -> Result<WalletMutation, RailError>;

    /// Submit a refund to the rail. The wallet has already been
    /// credited; this records the rail-side counterpart. Called by
    /// the refund worker. Idempotent on (redemption_id, amount).
    async fn submit_refund(&self, redemption_id: &str, amount_micros: u64, reason: &str) -> Result<RefundReceipt, RailError>;

    /// Reconcile drift between rail state and local ledger state.
    /// Called periodically (default nightly). Returns the diff for
    /// audit + alert.
    async fn reconcile(&self, since: DateTime<Utc>) -> Result<ReconciliationReport, RailError>;
}
```

### The rule, stated as one sentence

> The proxy never calls a rail. The proxy calls a `LedgerClient`; the `LedgerClient` is the only thing that ever talks to the local wallet, the local ledger service, or (for facilitator-bound rails only) a deadline-bounded facilitator. All rail-specific code is reached only via async workers consuming `BillingRail`.

### What lives where

| Concern | Trait | Sync/Async | Hot path? |
|---|---|---|---|
| Inbound 402 challenge | (config + signed quote) | sync | yes |
| Redeem token validation | LedgerClient | sync | yes |
| Atomic wallet debit | (WalletService) | sync | yes (called via LedgerClient adapter) |
| Idempotency + replay | (middleware) | sync | yes |
| Usage submission to rail | BillingRail::submit_usage | async | no |
| Webhook processing | BillingRail::handle_inbound_webhook | async | no |
| Wallet topup | (WalletService::topup) | async-driven | no |
| Refund (rail call) | BillingRail::submit_refund | async | no |
| Drift reconciliation | BillingRail::reconcile | async | no |
| Revenue events to analytics | (event pipeline) | async | no |
| Audit batching | (flusher) | async | no |
| Outbound customer webhooks | (NotifierStore) | async | no |

### Facilitator-bound nuance

Facilitator-bound rails sometimes require a synchronous external check at settlement time. Even there, the proxy never makes that call directly. Instead, the ledger service (reached via `LedgerClient::redeem`) makes the call internally with a tight deadline (default 2s), a circuit breaker that opens after N consecutive failures, and explicit fail-closed semantics. The proxy continues to see only `allow / deny / retry`.

The carve-out is intentional. We do not want to invent a separate "rail-shaped sync trait" for facilitator-bound rails, because the moment we do, every other rail will lobby to use it. The discipline is: if a rail needs a synchronous external check at the request edge, the ledger service owns the call, the deadline, the breaker, and the fail-closed semantics. The proxy stays rail-agnostic.

### Failure semantics

- `LedgerClient` errors map to one of three outcomes per `adr-http-ledger-protocol.md` (`retryable=true` then 503 + Retry-After, `retryable=false` then 402 challenge, success then allow). Hot-path-friendly. Errors never carry rail-specific detail; the protocol error envelope is the same regardless of the underlying rail.
- `BillingRail` errors live in async worker space. Failures land in DLQs (audit DLQ for webhooks, reconciliation drift report for reconcile, dead-rail circuit on `submit_usage`). Operators page on DLQ depth, not on per-request rail latency.

The async-side error budget is therefore decoupled from the request-path SLO. A rail outage shows up as a growing DLQ and a paged on-call, not as an SLO burn on the proxy's request-success rate.

### Where the boundary actually sits

Concretely, the `sbproxy` binary links only the OSS workspace and the `LedgerClient` trait. The ledger service (a separate process, reachable over the HTTP protocol in `adr-http-ledger-protocol.md`) runs the wallet, the idempotency cache, and (for facilitator-bound rails) the synchronous facilitator check. The async workers run in a separate process group; they never share an address space with the proxy.

This is enforced by Cargo dependency rules. `sbproxy-modules` depends on `sbproxy-plugin` (which exports `LedgerClient`); it must not depend on any rail-implementation crate. CI gates the dependency graph (`scripts/check-crate-graph.sh`).

## Consequences

- The hot path is rail-agnostic. The same `sbproxy` binary runs unchanged regardless of which rail (or no rail at all) the operator wires.
- Adding a new rail equals one `BillingRail` impl plus one or two worker registrations. No proxy changes.
- The tradeoff: a rail change that touches only `BillingRail` cannot be reflected in the proxy's hot-path behaviour without going through the local `LedgerClient` (or its underlying wallet state). This is a feature, not a bug. The proxy stays predictable.
- The dependency-graph CI check is load-bearing. If `sbproxy-modules` ever picks up a transitive dependency on a rail-implementation crate, the layering is broken even if no actual call goes through. The check fails the build before that lands.
- Operators see a clean SLO split: request-path SLOs on the proxy, async-pipeline SLOs on the workers. A rail outage shows up as DLQ depth, not as a request-error spike.

## Alternatives considered

**Keep a single `BillingProvider` trait with sync verbs the proxy calls directly.** Rejected. Drags rail latency into p99, makes rail outages equal to proxy outages, hard to bench, mixes credentials closer to the request edge.

**Make `BillingProvider` async and let the proxy `await` it.** Rejected. Still couples the request path to rail latency. Async does not avoid the underlying issue (the rail RTT itself). It also introduces an executor boundary in the proxy hot path that the existing `reqwest::blocking::Client` pattern in `sbproxy-modules` does not have.

**Single trait with two execution modes (sync inline / async deferred), selectable per call site.** Rejected. Invites the wrong default when developers reach for the trait. Two named traits force the right call. The "selectable per call site" pattern accumulates ad-hoc usage and does not survive contact with new contributors.

## References

- `adr-http-ledger-protocol.md` - the wire protocol that LedgerClient speaks.
- `adr-schema-versioning.md` - the trait split's schema-evolution rules.
- `adr-webhook-security.md` - inbound and outbound webhook handling, both async per this ADR.
