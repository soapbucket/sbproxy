# ADR: Webhook security policy, inbound and outbound

*Last modified: 2026-05-03*

## Status

Accepted. Builds on `adr-observability.md` and `adr-admin-action-audit.md`.

## Context

The gateway sits at the edge of two webhook stories:

**Inbound.** External providers POST to us. Stripe events. MPP rail callbacks. x402 facilitator notifications. Each provider uses its own signature scheme, replay-protection conventions, and IP profile. Without a single contract, every provider's adapter reinvents verification, replay, and idempotency, and "is this Stripe event still valid?" lives in three places.

**Outbound.** We POST to customer-supplied URLs. Wallet low-balance, agent registered, audit-export-ready, classifier-drift, alert-fire. The customer's endpoint must verify it's us, not an attacker forging notifications. Retries, deadlettering, key rotation, and per-tenant subscription all need a single framework.

Both halves require the same fundamental building blocks (signature scheme, idempotency, replay protection); we ship them together so future providers do not reinvent.

## Decision

### Inbound: per-provider verifier registry

An `InboundWebhookVerifier` trait in `sbproxy-modules::webhook`:

```rust
pub trait InboundWebhookVerifier: Send + Sync {
    /// Provider identifier (`stripe`, `mpp`, `x402-facilitator-coinbase`, ...).
    fn provider(&self) -> &'static str;

    /// Verify the HTTP request. Returns the canonical event-id that the
    /// caller persists in the replay cache.
    fn verify(&self, req: &Request) -> Result<VerifiedEvent, VerifyError>;
}

pub struct VerifiedEvent {
    pub provider:   &'static str,
    pub event_id:   String,        // provider-supplied; idempotency key
    pub event_type: String,
    pub payload:    serde_json::Value,
    pub received_ts_ms: u64,
}
```

Each provider's adapter implements `InboundWebhookVerifier`. The middleware that fronts every inbound webhook endpoint does:

1. **Signature verification** via the trait.
2. **IP allowlist check** (configurable per provider; default is permissive in OSS, allowlist-required in enterprise).
3. **Replay protection** via a Redis-backed cache (24h TTL on the digest of the verified event-id + signature). Duplicate within window returns 200 OK without re-processing (idempotent ACK to the provider).
4. **Idempotency-key dedup** on the application layer using `VerifiedEvent.event_id`.
5. **Audit emission** per `adr-admin-action-audit.md` with `subject = AuditSubject::Service { principal_id: provider }`.

#### Stripe inbound (concrete shape)

Stripe signs with HMAC-SHA256 over `<timestamp>.<payload>` and sends `Stripe-Signature: t=<ts>,v1=<sig>,...`. The verifier:

1. Parses the header for `t` and `v1` values.
2. Computes `HMAC-SHA256(secret, t + "." + raw_body)`.
3. Constant-time compares against `v1`.
4. Rejects if `|now - t| > tolerance` (default 5 min). `tolerance` is configurable per provider.
5. Returns `VerifiedEvent { event_id: stripe_event.id, ... }`.

The signing secret rotates via dual-secret config:

```yaml
inbound_webhooks:
  stripe:
    primary_secret: ${STRIPE_WEBHOOK_SECRET}
    secondary_secret: ${STRIPE_WEBHOOK_SECRET_OLD}  # accepted for 30d after rotation
    timestamp_tolerance_seconds: 300
    ip_allowlist:
      - 3.18.12.0/24       # Stripe CIDR ranges (refresh per Stripe docs)
      - 3.130.192.0/24
    replay_window_seconds: 86400
```

Verification accepts either secret during rotation, then the secondary is removed.

#### MPP / x402 inbound

Same trait, different signature scheme (Ed25519 over a canonicalized payload). The replay cache and idempotency-key dedup reuse the framework verbatim.

#### Replay-protection cache

Redis is the production backend (key: `webhook:replay:{provider}:{digest}`, value: `1`, TTL: 24h). The `digest` is `SHA-256(event_id || signature)` so a replayed payload with a forged signature won't accidentally hit a different cache entry.

For OSS deployments without Redis, the framework falls back to an in-memory LRU (10 000 entries default). This is single-instance only; multi-replica OSS deployments without Redis are vulnerable to cross-replica replay and the framework logs a startup warning.

Replay collisions count via `sbproxy_webhook_in_replay_total{provider}`; a sustained nonzero rate fires the `SBPROXY-WEBHOOK-IN-REPLAY` ticket alert.

#### IP allowlist enforcement

The allowlist is a list of CIDRs per provider. The check runs after TLS terminates and uses the **post-trusted-proxy resolved client IP** (per the trusted-proxy CIDR config; not raw `X-Forwarded-For`). Failures return 403 and emit `sbproxy_webhook_in_rejected_total{provider, reason="ip"}`.

Allowlist refreshing is operator-managed. Stripe and major providers publish CIDR lists; the operator runbook documents the refresh procedure.

#### Idempotency-key handling

Some providers (Stripe with `Idempotency-Key` request header) send the same event with the same key on retry. We persist the `VerifiedEvent.event_id` after first successful processing and short-circuit subsequent retries to a 200 ACK without reprocessing. The persistence is the same Redis cache as replay protection (same key namespace; the cache entry's existence is the dedup signal).

For providers that do not send an idempotency key, we synthesize one from `(provider, event_type, hash(payload))`. The synthesis is sound only when the provider guarantees same-payload-on-retry semantics; documented per provider.

### Outbound: per-tenant subscription model

Customers register webhook subscriptions through the portal:

```yaml
# subscription record (stored in Postgres, surfaced via portal UI)
subscription_id: sub_01J...           # ULID
tenant_id:       tenant_42
url:             https://api.customer.example/sbproxy/events
events:                                # event-type filter; * = all
  - wallet.low_balance
  - agent.registered
  - agent.revoked
  - audit.export_ready
signing:
  algorithm:     ed25519               # ed25519 (preferred) | hmac-sha256
  primary_key_id: kid_01J...
  secondary_key_id: null               # populated during rotation
status: active                         # active | paused | failing | disabled
```

The outbound framework handles signing, retries, deadlettering, and per-tenant fan-out. Concrete events land in follow-on work.

#### Signing: Ed25519 preferred, HMAC-SHA256 fallback

**Ed25519 (default).** We sign each delivery with the tenant's Ed25519 private key. The customer fetches our public key via `GET https://<gateway-host>/.well-known/sbproxy-webhook-keys` (a JWKS-shaped document, signed by a long-lived root) and verifies. Public-key crypto means a leaked verifier in the customer's stack does not enable the customer to forge events.

**HMAC-SHA256 (fallback).** A shared secret per subscription. Used only when the customer explicitly opts in (some legacy ingestion pipelines don't speak Ed25519). The shared secret is delivered once at subscription creation and never displayed again; a re-issue is a key rotation.

The signature lands in two response headers:

```
Sbproxy-Signature: t=<ts>,kid=<key-id>,alg=ed25519,v1=<base64-sig>
Sbproxy-Event-Id:  <event-id-ulid>
```

The signed input is `t + "." + raw_body` (matching Stripe's convention so customers' existing Stripe-style verifiers can be adapted). The `kid` lets verifiers select the right public key during rotation.

#### Key rotation: dual-key window

Tenants get one signing key at subscription creation. Rotation:

1. Operator (or scheduled rotator) creates a new key with `secondary_key_id`. Both keys are now active.
2. The framework signs new deliveries with the **primary** key.
3. After 30 days (configurable: `rotation.dual_window_days`), the primary is replaced by the secondary; the old primary is retired.
4. Customers see both public keys in JWKS during the dual window; they verify with whichever `kid` the request carries.

The 30-day window is enough for customer-side cache TTL and rolling deploys. Compromised-key emergency rotation compresses to 24 hours via an operator command (`sbproxy-admin rotate-webhook-key --tenant=... --immediate`); this is a paged procedure documented in the runbook (RB-WEBHOOK-KEY-COMPROMISE).

#### Retry policy: exponential backoff

Failed deliveries (non-2xx response, connection error, timeout) retry with exponential backoff:

| Attempt | Delay before retry |
|---|---|
| 1 (initial send) | 0 |
| 2 | 1 s |
| 3 | 5 s |
| 4 | 30 s |
| 5 | 5 min |
| 6 | 30 min |

After attempt 6 (around 35 minutes total), the delivery moves to the deadletter queue. Subscriptions that accumulate consecutive failures across multiple events are auto-paused at a configurable threshold (default: 50 consecutive failures, around 28 hours of bad endpoint at typical event rates) and the tenant is notified via portal email plus a status flip to `failing`.

Per-attempt timeout: 10 s. Per-attempt body size cap: 1 MiB (events larger are dropped to deadletter pre-retry with `oversize` reason).

The retry loop runs in `sbproxy-observe::notify::retry` with a bounded worker pool per tenant (default 4 workers; configurable). Per-tenant fan-out is bounded so a slow customer doesn't starve others.

#### Deadletter queue

Postgres-backed table `webhook_deadletter`:

```sql
CREATE TABLE webhook_deadletter (
    deadletter_id      UUID PRIMARY KEY,
    subscription_id    TEXT NOT NULL,
    tenant_id          TEXT NOT NULL,
    event_id           TEXT NOT NULL,
    event_type         TEXT NOT NULL,
    payload            JSONB NOT NULL,
    last_attempt_ts    TIMESTAMPTZ NOT NULL,
    last_status_code   INT,
    last_error_message TEXT,
    attempt_count      INT NOT NULL,
    moved_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    replayed_at        TIMESTAMPTZ                    -- null until replayed
);
```

Customers inspect their deadletters via the portal (`/portal/webhooks/deadletters`). Operators can replay a deadlettered event with the admin CLI (`sbproxy-admin webhook replay --deadletter-id=...`). Replay is itself an audit event per `adr-admin-action-audit.md`.

Default retention: 30 days. After retention, deadletter entries are purged; the audit log retains the metadata.

#### Per-tenant subscription registry

Subscriptions are scoped per tenant. The registry skeleton ships first (Postgres schema, CRUD endpoints behind admin auth). Concrete events (`wallet.low_balance`, `wallet.topup_succeeded`, `agent.registered`, `agent.approved`, `agent.revoked`) wire in via follow-on work.

A tenant can subscribe to:

- A specific event type (`wallet.low_balance`).
- An event-type prefix (`wallet.*`).
- All events (`*`).

The dispatcher matches event types against active subscriptions at fan-out time. Subscription matching is O(N_tenant) per event; for very large tenant counts we precompute per-event-type subscription lists at registry mutation time.

#### Outbound headers (full set)

Every outbound request carries:

```
Sbproxy-Signature:     t=<ts>,kid=<key-id>,alg=ed25519,v1=<base64-sig>
Sbproxy-Event-Id:      <event-id-ulid>
Sbproxy-Event-Type:    wallet.low_balance
Sbproxy-Tenant-Id:     <tenant-id>
Sbproxy-Subscription-Id: <subscription-id>
Sbproxy-Delivery-Id:   <delivery-id-ulid>      # unique per attempt; for log correlation
Sbproxy-Attempt:       <attempt-number>        # 1-indexed
Content-Type:          application/json
User-Agent:            sbproxy/<version> (+https://docs.sbproxy.dev/webhooks)
traceparent:           <W3C TraceContext>      # see adr-observability.md
```

`Sbproxy-Delivery-Id` rotates per attempt so customer-side dedup using the delivery ID stays strict; `Sbproxy-Event-Id` is stable across retries so customer-side idempotency remains correct.

### Audit and observability

Every inbound verification (success or failure) emits `sbproxy_webhook_in_total{provider, result}`. Every outbound delivery emits `sbproxy_webhook_out_total{subscription, result}` and `sbproxy_webhook_out_attempts_total{subscription}`.

Failed verifications and signing failures emit an `AdminAuditEvent` per `adr-admin-action-audit.md`:

- Inbound: `subject = Service { principal_id: provider }`, `result = Failure { ... }`, target = `AuditTarget::Other { kind: "webhook_in", id: event_id }`.
- Outbound: `subject = System { component: "webhook_out" }`, `result = Failure { ... }`, target = `AuditTarget::Subscription { subscription_id }`.

The audit emission is best-effort (won't block delivery / verification on audit append failure) but counted; sustained audit-emission failures page on `SLO-AUDIT-WRITE`.

### Configuration shape (sb.yml + portal)

```yaml
inbound_webhooks:
  stripe:
    primary_secret:   ${STRIPE_WEBHOOK_SECRET}
    secondary_secret: ${STRIPE_WEBHOOK_SECRET_OLD}
    ip_allowlist:     [3.18.12.0/24, ...]
    timestamp_tolerance_seconds: 300
    replay_window_seconds:        86400
  mpp:
    public_keys:      [<jwks-url>]
    ...

outbound_webhooks:
  default_signing_algorithm: ed25519
  default_retry_schedule_seconds: [0, 1, 5, 30, 300, 1800]
  delivery_timeout_seconds: 10
  per_attempt_body_max_bytes: 1048576
  deadletter_retention_days: 30
  per_tenant_workers: 4
  rotation:
    dual_window_days: 30
```

Per-subscription overrides (custom retry schedule, custom timeout) are configurable via portal.

### What this ADR does NOT decide

- Specific event payload schemas (`wallet.low_balance` JSON shape). Per-event payload schemas live in `docs/webhooks/events/*.md` and follow `adr-schema-versioning.md`.
- Customer-side verification SDK. Each language ecosystem ships its own; the verification recipe is documented in `docs/webhooks.md`.
- Webhooks for the portal UI's user-action notifications (e.g. "your invoice is ready" emails). Those go through the email pipeline, not webhooks.
- The JWKS root signing key for `/.well-known/sbproxy-webhook-keys`. Lives in `adr-jwks-root.md` (deferred).

## Consequences

- One framework: the same retry / deadletter / observability path serves wallet events, agent events, audit events, alert events, and any future event class. No event-type-specific delivery code.
- Ed25519 default keeps the customer's key surface small (public key only). HMAC fallback exists for legacy ingestion pipelines but is opt-in.
- Replay-protection requires Redis in production. OSS deployments without Redis log a warning and accept the in-memory LRU's single-instance limitation; this is documented and operators choose.
- Per-tenant fan-out is bounded; a slow customer cannot DoS other tenants' deliveries.
- The dual-key 30-day rotation window is the right balance for routine rotation; the 24-hour emergency procedure is the safety valve for compromise.
- Deadletter inspection via the portal closes the loop: customers see their failed deliveries and can fix their endpoints without operator help.
- Audit emission on every webhook event (in and out) is heavy. We intentionally pay this; webhook traffic is governance-relevant by definition.

## Alternatives considered

**HMAC-SHA256 only for outbound.** Considered because of operational simplicity (one symmetric secret per subscription). Rejected as default because a leaked secret on the customer side enables forgery; Ed25519 split keys remove that failure mode. HMAC remains as fallback for legacy callers.

**Single global signing key for all outbound webhooks.** Rejected. A single key compromise blast-radius is the entire customer base. Per-tenant keys keep blast-radius to one tenant, and rotation is per-tenant.

**Synchronous deadletter (return 5xx to provider on inbound failure, no retry queue).** Rejected for outbound. Customers expect at-least-once delivery; dropping events on first failure breaks their reconciliation. For inbound, providers handle their own retries; we just verify-or-reject and return the appropriate status code.

**Webhook signing with JWS detached signatures instead of header-based.** Considered for OAuth-style use cases. Rejected because every existing webhook ecosystem (Stripe, GitHub, Shopify) uses header-based signing; matching the convention reduces customer integration friction. JWS-detached is a viable v2 if a customer base demands it.

**Per-event signing keys (rotate per event).** Rejected as overkill. The dual-key rotation window already gives us the operational properties; per-event rotation explodes the JWKS endpoint and customer cache complexity.

## References

- Companion ADRs: `adr-observability.md`, `adr-admin-action-audit.md`, `adr-schema-versioning.md`.
- Implementation surfaces: `sbproxy-observe::notify` (outbound), `sbproxy-modules::webhook` (inbound).
- Stripe signature reference: <https://docs.stripe.com/webhooks/signatures>.
- W3C TraceContext: <https://www.w3.org/TR/trace-context/>.
- JWKS for verification keys: RFC 7517.
