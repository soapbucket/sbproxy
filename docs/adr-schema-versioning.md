# ADR: Schema versioning and backwards-compatibility policy

*Last modified: 2026-05-03*

## Status

Accepted. Builds on `adr-log-schema-redaction.md`, `adr-admin-action-audit.md`, and the ledger HTTP protocol ADR. Every later schema lands under this policy; deviations require an ADR amendment.

## Context

Six schemas need a versioning story:

1. **`LedgerClient` trait (sync, hot path).** OSS-defined trait in `sbproxy-modules`. The proxy's only billing surface. Implemented by the in-process `InMemoryLedger` and the HTTP-backed `HttpLedger`. See `adr-billing-hot-path-vs-async.md`.
2. **`BillingRail` trait (async, per-rail).** Trait consumed only by async workers. Implemented by Stripe, MPP, x402, and Lightning. Every new variant exercises the trait shape. See `adr-billing-hot-path-vs-async.md`.
3. **HTTP ledger payload.** Wire format for redeem / authorize / capture / refund. Touched on every paid request.
4. **Access-log schema.** JSON-line format from `adr-log-schema-redaction.md`. Customers ingest into Loki / S3 / their own pipeline.
5. **Registry feed format.** Reputation feed; signed JSON. Mirrored in customer-fetched mirrors.
6. **Audit envelope.** From `adr-admin-action-audit.md`. Customers verify entries with the verifier CLI.

Without a single policy, each schema would invent its own deprecation rules, and customers would have to learn five.

This ADR pins one policy that all five (and every future schema) inherit.

## Decision

### Versioning scheme

Every schema carries a single `schema_version` integer. We use integers, not semver, because schemas don't have a "patch level" meaningful concept; either the wire shape changed (major bump) or it didn't. Minor changes (adding optional fields) do NOT bump the version; they are always backwards-compatible.

Concrete carriage:

| Schema | Version field | Initial value |
|---|---|---|
| `LedgerClient` trait (sync, hot path) | trait surface tracked alongside the HTTP ledger payload version (clients tolerate higher server versions) | tied to ledger payload v1 |
| `BillingRail` trait (async, per-rail) | `const VERSION: &'static str` per impl (decimal-integer-as-string for now; reserved for semver later) | "1" |
| Ledger payload | top-level `"schema_version": 1` | 1 |
| Access-log schema | top-level `"schema_version": "1"` per line (string for forward-compat) | "1" |
| Registry feed | top-level `"format_version": 1` | 1 |
| Audit envelope | top-level `"schema_version": 1` per event | 0 (current v0; bumped to 1 when chain attach lands) |

Schemas that don't carry version inline because they're language-internal (the `RequestEvent` Rust struct, the typed `AdminAuditEvent` struct) are versioned at the protobuf / wire-format level. The Rust struct's version equals the protobuf schema's version.

### Three-rule compatibility model

Three rules cover every schema:

**Rule 1: Adding an optional field is non-breaking.** Old readers ignore unknown optional fields; new readers populate them when present. No version bump. Required for evolution.

**Rule 2: Removing or renaming a field is breaking.** Bumps the major version. Triggers the deprecation window below.

**Rule 3: Changing a field's type is breaking** even if the new type is "compatible" (e.g. u32 → u64). Bumps the version. We don't trust silent widening; producer-consumer pairs in different language ecosystems handle widening differently.

Adding a new variant to a closed enum (e.g. `AuditAction`) is breaking under this rule because old readers can't deserialize the new variant. Adding to an open enum (an enum with a `Other(String)` escape hatch) is non-breaking. The audit envelope's `AuditAction::Other(String)` is intentional; the ledger payload's `result` enum currently closed will need an `Other` variant when we add new rails.

### Deprecation window

For schema breaks:

- **Announce** in the next minor release's CHANGELOG with a deprecation notice.
- **Dual-emit / dual-read** for `N+2` minor releases, where `N` is the release that announced. New writers emit the new shape; consumers tolerate either; old writers continue producing the old shape.
- **Hard cut** in `N+3` (the third release after announcement). Documentation is updated, the dual-read path is removed.

For sbproxy's release cadence (one minor every 4-6 weeks), this gives customers ~3-5 months of overlap. The exact dates land in `CHANGELOG.md`.

A schema break can compress the window to `N+1` only if:

1. The break is forced by a security issue (e.g. the field carried PII that we now redact).
2. An ADR amendment documents the specific exemption.
3. The release notes prominently flag it.

### Version negotiation rules

Where producer and consumer can negotiate (`BillingRail`, ledger client / server):

1. The newer side advertises its highest supported version.
2. The older side responds with the highest version it supports.
3. The session uses `min(producer_max, consumer_max)`.

Concrete:

- **`BillingRail` trait:** the implementing crate sets `const VERSION: &'static str` (decimal-integer-as-string, e.g. `"1"`; reserved as `&'static str` so a future semver flip ("1.1") is non-breaking). The crate also exports a `BILLING_RAIL_SCHEMA_VERSION` constant for canonical mapping. The consumer (the async worker registry, never the proxy) parses `VERSION` to a numeric form at boot and checks that every loaded rail's `VERSION >= worker_min_version`. If not, the rail refuses to load and the worker process logs a startup warning. `worker_min_version` ratchets up: bumping it is a deliberate compatibility break documented in the release.
- **`LedgerClient` trait:** no separate `VERSION` constant. The trait is consumed inside the proxy binary, in lockstep with the OSS workspace it ships in; cross-version skew between the proxy and its in-process `LedgerClient` impl is impossible. When the proxy speaks to a remote ledger over HTTP, the version negotiation lives at the wire layer (next bullet), not the trait layer.
- **Ledger HTTP protocol:** the client sends `Sb-Ledger-Schema-Version: 1` request header. The ledger server responds with `Sb-Ledger-Schema-Version: 1` (or higher; clients must tolerate higher, then downgrade). On mismatch beyond tolerance, the ledger returns 426 Upgrade Required.
- **Registry feed:** the feed-fetcher reads `format_version` from the signed feed body. If the feed advertises a version above the fetcher's max, the fetcher logs a warning and uses only the fields it understands.
- **Access-log schema:** producer-only; consumers (customer ingestion pipelines) read whatever they can. The `schema_version` field lets them branch.
- **Audit envelope:** consumer is the verifier CLI shipped from the same release; same-version invariant. Cross-version verification (older v0 events read by a newer v1 verifier) is explicitly supported.

### Breaking-change checklist (RFC-style)

Every breaking schema change ships a checklist as part of its PR:

```markdown
## Breaking change checklist (schema X, version N → N+1)

- [ ] **Impact assessment.** Who reads this schema? List all known
      producers and consumers (internal + external).
- [ ] **Migration script.** If state migrates (e.g. database rows
      tagged with version), the script lives in `migrations/` and is
      idempotent.
- [ ] **Dual-write window.** Producer emits both old and new shapes
      from release `N` to release `N+2`.
- [ ] **Dual-read window.** Consumer accepts both shapes from
      release `N` to release `N+2`.
- [ ] **Rollback plan.** If `N+1` is rolled back to `N`, what state
      is recoverable? What's lost?
- [ ] **Documentation update.** Schema reference doc (`docs/schemas/`)
      updated; migration guide (`docs/migrations/schema-X-vN-to-N+1.md`)
      lands in the same PR.
- [ ] **CHANGELOG entry.** Under "Breaking changes" with the deprecation
      window dates.
- [ ] **Cargo `--cfg` bridge** (if applicable; see § Cargo `--cfg`
      bridge below).
- [ ] **Test coverage.** Round-trip test for old shape, new shape, and
      mixed-stream consumer.
```

The checklist is enforced by a CI check (`scripts/check-schema-breaks.sh`) that scans for `BREAKING-SCHEMA:` markers in PR descriptions and verifies the corresponding files exist.

### Cargo `--cfg` bridge for in-flight rollouts

For schemas internal to the Rust workspace where a long deprecation window is overhead, we use Cargo `--cfg` flags to bridge in-flight rollouts:

```rust
#[cfg(feature = "request-event-v1")]
pub fn emit_request_event_v1(ev: RequestEvent) { /* old shape */ }

#[cfg(feature = "request-event-v2")]
pub fn emit_request_event_v2(ev: RequestEventV2) { /* new shape */ }
```

The bridge pattern:

1. Add the new shape under a new feature flag (`request-event-v2`).
2. Default features keep the old shape.
3. Customers opt in via `--features request-event-v2` for early testing.
4. After the deprecation window, the new shape becomes default; the old one stays under `--features request-event-v1` for one more release.
5. The old feature is removed.

This is **not** the recommended path for cross-language wire formats (ledger HTTP, registry feed, access-log JSON). For those, the dual-emit/dual-read window is the right tool. The `--cfg` bridge is for Rust-internal evolution where rebuilding is cheap.

### Per-schema specifics

**`LedgerClient` trait (`sbproxy-modules`):**

```rust
/// HOT PATH trait. Lives in sbproxy-modules. The proxy calls this.
/// See adr-billing-hot-path-vs-async.md.
pub trait LedgerClient: Send + Sync {
    fn redeem(&self, ...) -> Result<RedeemResult, LedgerError>;
    fn authorize(&self, ...) -> Result<AuthorizeResult, LedgerError>;
    fn capture(&self, ...) -> Result<CaptureResult, LedgerError>;
    fn refund_redemption(&self, ...) -> Result<RefundResult, LedgerError>;
}
```

The trait surface lives inside the OSS workspace and ships in lockstep with the proxy binary. There is no per-impl `VERSION` constant; cross-version skew is impossible inside one binary. When the underlying impl is `HttpLedger` (the wire-backed adapter), the wire protocol version is negotiated per `adr-http-ledger-protocol.md` (`Sb-Ledger-Schema-Version` header). When the underlying impl is an in-process wallet adapter, the proxy and the adapter ship together and trivially agree.

Adding a method to the trait is a breaking change for OSS contributors who implement `LedgerClient` themselves. The deprecation window in this ADR applies. Adding an optional default-method (Rust default-impl on the trait) is non-breaking and does not require a window.

**`BillingRail` trait:**

```rust
/// ASYNC PATH trait. One impl per rail. Consumed by async workers.
/// NEVER called from the proxy hot path.
#[async_trait::async_trait]
pub trait BillingRail: Send + Sync {
    const VERSION: &'static str;
    fn name(&self) -> &str;
    async fn submit_usage(&self, batch: &[UsageEvent]) -> Result<SubmissionReceipt, RailError>;
    async fn handle_inbound_webhook(&self, event: WebhookPayload) -> Result<WalletMutation, RailError>;
    async fn submit_refund(&self, redemption_id: &str, amount_micros: u64, reason: &str) -> Result<RefundReceipt, RailError>;
    async fn reconcile(&self, since: DateTime<Utc>) -> Result<ReconciliationReport, RailError>;
}
```

`UsageEvent`, `SubmissionReceipt`, `WebhookPayload`, `WalletMutation`, `RefundReceipt`, `ReconciliationReport`, `RailError` are versioned structs under a `v1::` module. A v2 of the trait lives in `v2::` alongside; the worker registry selects per rail's `VERSION`.

The four-verb shape (`submit_usage / handle_inbound_webhook / submit_refund / reconcile`) is the async rail abstraction. It is distinct from the four wire-protocol verbs in `adr-http-ledger-protocol.md` (`redeem / authorize / capture / refund`); the rail abstraction sits in async worker space and produces wallet mutations that the local ledger service applies. Stripe maps inbound topup webhooks (`payment_intent.succeeded`) to `WalletMutation::Topup`; x402 settlement notifications map to `WalletMutation::Settlement`; MPP rail callbacks map similarly. The proxy never sees any of this.

**Ledger payload:** wire format defined in `crates/sbproxy-modules/src/policy/ai_crawl_ledger.rs`. JSON over HTTP. Top-level fields:

```json
{
  "schema_version": 1,
  "operation": "redeem",
  "idempotency_key": "01J...",
  "agent_id": "...",
  "amount_micros": 1000000,
  "currency": "USD",
  "metadata": { ... }
}
```

`schema_version: 1` is required. Servers that get `schema_version: 2` from a forward client respond 426 Upgrade Required unless they support both.

**Access-log schema:** per `adr-log-schema-redaction.md`. Top-level `schema_version: "1"` (string for forward-compat with semver-like values, e.g. "1.1" if we ever soften the integer rule).

**Registry feed:** top-level `format_version: 1` and a signed JSON payload. Format is defined in `adr-agent-registry-feed.md`; this ADR pins the version-handling rules.

**Audit envelope:** per `adr-admin-action-audit.md`. `schema_version: 0` for the current signed-batch v0. `schema_version: 1` lands when `chain_position` becomes mandatory (the migrator backfills v0 entries to v1). The verifier CLI accepts both.

### Forbidden patterns

- **Silent re-typing.** Changing a field from int to string (or u32 to u64) without a version bump. Always breaks at least one consumer.
- **Reusing field names with new semantics.** Renaming a field is a break, even if the new field "means the same thing."
- **Multi-purpose fields.** A single field that means different things in different contexts (`object: { type: "wallet", ... } | { type: "agent", ... }`) is fine, but only if the discriminator (`type`) is required and the parser dispatches on it.
- **Hard-coded version checks elsewhere.** Version checks live in one place per schema (the version-negotiation handshake or the parser entry point). Scattered version checks at random call sites accumulate bit rot.

### What this ADR does NOT decide

- HTTP API versioning (URL path `/v1/`, `/v2/`). That's a customer-facing contract, lives in `adr-http-api-versioning.md`. The schema policy applies inside whatever HTTP version is current.
- Database schema migrations (Postgres ALTER TABLE rules). Those live in `adr-database-migrations.md`. This ADR's compatibility rules apply to wire formats; database migrations have their own forward/backward-compat constraints.
- Portal API versioning. Inherits this policy; portal-specific rules live in the portal repo.

## Consequences

- One policy across five schemas. New developers learn it once.
- Every breaking change carries a checklist; CI gates the existence of the migration doc and CHANGELOG entry. We won't ship a break without paperwork.
- The dual-emit/dual-read window is real engineering cost (the producer emits both shapes for around 3 months), but it's the price of trustworthy upgrade paths. Customers who self-host can upgrade on their schedule.
- Closed enums (`AuditAction`, ledger result codes) need an `Other` escape hatch where future variants are likely. This ADR codifies which enums are closed; future ADRs revisit if the cost is too high.
- Cargo `--cfg` bridge gives us a low-friction tool for Rust-internal evolution. Cross-language wire formats don't get that shortcut and pay the dual-emit cost.
- The `worker_min_version` ratchet for `BillingRail` lets us drop support for ancient rail implementations without breaking anyone we care about. It's a lever; we use it sparingly. (Note: this ratchet lives in the async worker registry, not the proxy core, per `adr-billing-hot-path-vs-async.md`.)

## Alternatives considered

**Semver per schema (1.2.3 strings instead of integer versions).** Rejected. Schemas don't have a meaningful "patch level"; either the wire changed or it didn't. Semver invites bikeshedding ("is this a minor or a patch?") without adding information. The string-or-integer choice for the access log is a forward-compat hedge: if we ever decide to add minor levels, we can without re-encoding all old logs.

**Single global schema version (one number for the entire system).** Rejected. Schemas evolve at different rates; a global version forces a re-cut every time any schema changes. Per-schema versions let the access log evolve weekly (minor adds) while the ledger payload stays at v1 for a year.

**No version field; rely on shape detection.** Rejected. Shape detection ("does this JSON have field X? then it's v2") accumulates fragile heuristics; one ambiguous shape and consumers diverge. Explicit version is cheap (one int per record) and unambiguous.

**Permissive backwards-compat (any new shape that older consumers can still parse is non-breaking, no version bump).** Considered. Rejected because "older consumers can still parse" is vague; in practice we'd find that some consumer relied on a strict-shape assumption and we broke it without telling anyone. Explicit is better than implicit.

## References

- Companion ADRs: `adr-admin-action-audit.md`, `adr-log-schema-redaction.md`, `adr-billing-hot-path-vs-async.md` (the trait split that motivates the `LedgerClient` / `BillingRail` separation here), future `adr-agent-registry-feed.md`, future `adr-ledger-protocol.md`.
- The Cargo `--cfg` bridge pattern: <https://doc.rust-lang.org/cargo/reference/features.html>.
- Semver vs schema versioning, prior art: <https://protobuf.dev/programming-guides/proto3/#updating>.
