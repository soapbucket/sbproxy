# ADR: HTTP ledger protocol

*Last modified: 2026-05-03*

## Status

Accepted. Builds on `adr-agent-class-taxonomy.md`. Consumed by the `HttpLedger` client and downstream rail adapters.

## Context

`crates/sbproxy-modules/src/policy/ai_crawl.rs` already defines a `Ledger` trait with a single `redeem(token, host, path) -> bool` method, served by an in-memory `InMemoryLedger`. That is enough for an OSS demo and the existing e2e test, but it is not a production billing surface. Real deployments need:

- a network-callable backend so multiple proxy instances share one redemption set,
- request authenticity (an attacker on the network cannot forge a redeem),
- exactly-once semantics under retry (a network blip must not double-debit the agent),
- a clean error envelope so the policy knows whether to retry, fail closed, or fail open,
- a circuit breaker so a ledger outage does not cascade into the request path.

The ledger trait commits to `authorize`, `capture`, `refund`, and `redeem` as the four shapes. This ADR fixes the wire format for all four.

## Decision

The HTTP wire protocol described here is what `LedgerClient` (per `adr-billing-hot-path-vs-async.md`) speaks. The proxy never speaks any rail's protocol directly; rail-specific code (Stripe, MPP, x402) is implemented as `BillingRail` and consumed only by async workers. Cross-link: `adr-billing-hot-path-vs-async.md`.

Define a JSON-over-HTTPS protocol with HMAC-SHA256 request signing, an `Idempotency-Key` header, exponential-backoff retries with a circuit breaker, and a uniform error envelope. The same envelope serves all four verbs; only the path and the `payload` field shape change between verbs.

### Endpoints

Base URL configured via `SBPROXY_LEDGER_ENDPOINT`. All endpoints are HTTPS. Plain HTTP is rejected at config-load time with a hard error.

| Verb | Path | Idempotent |
|---|---|---|
| Redeem | `POST /v1/ledger/redeem` | Yes (by `idempotency_key`) |
| Authorize | `POST /v1/ledger/authorize` | Yes |
| Capture | `POST /v1/ledger/capture` | Yes |
| Refund | `POST /v1/ledger/refund` | Yes |
| Health | `GET /v1/ledger/healthz` | n/a |

### Request envelope

Every request (all four verbs) shares the top-level envelope:

```json
{
  "v": 1,
  "request_id": "01HZX...",
  "timestamp": "2026-04-30T12:34:56.789Z",
  "nonce": "8f4a...32-hex...",
  "agent_id": "openai-gptbot",
  "agent_vendor": "OpenAI",
  "workspace_id": "ws_abc",
  "payload": { /* verb-specific */ }
}
```

| Field | Type | Notes |
|---|---|---|
| `v` | integer | Protocol version. `1` for the current schema. Bumped only by an ADR amendment. |
| `request_id` | ULID (26 chars) | Same ID surfaced in `X-Request-Id` and `RequestEvent.request_id`. Lets the ledger correlate to access logs. |
| `timestamp` | RFC 3339, UTC, millisecond precision | Used for replay protection. The ledger rejects timestamps more than 60 s skewed from its own clock. |
| `nonce` | 32-byte random, hex-encoded | Replay protection, scoped to (`agent_id`, 5-minute window). |
| `agent_id` | string | Drawn from the agent-class taxonomy (`adr-agent-class-taxonomy.md`). Reserved values `unknown`, `anonymous`, `human` are valid. |
| `agent_vendor` | string | Convenience copy of the taxonomy `vendor`. Carried so the ledger does not need to load the taxonomy. |
| `workspace_id` | string | Tenant key. `default` in single-tenant deployments. |
| `payload` | object | Verb-specific shape, see below. |

Verb payloads:

```json
// /v1/ledger/redeem
{ "token": "tok_abc...", "host": "example.com", "path": "/articles/foo",
  "amount_micros": 1000, "currency": "USD", "content_shape": "markdown" }

// /v1/ledger/authorize
{ "amount_micros": 5000, "currency": "USD", "host": "example.com",
  "path": "/articles/foo", "expires_in_seconds": 300 }

// /v1/ledger/capture
{ "authorization_id": "auth_xyz", "amount_micros": 1000 }

// /v1/ledger/refund
{ "redemption_id": "red_abc", "amount_micros": 1000, "reason": "operator_initiated" }
```

`amount_micros` is a `u64` in micro-units of `currency` (1e-6 of one unit). USD micros at 1e-6 hits 18 trillion at u64 saturation, which is fine. Float prices never enter the protocol; this is the same rationale as `cost_usd_micros` in the event envelope ADR.

`content_shape` is one of the closed values from `adr-metric-cardinality.md` (`html`, `markdown`, `json`, `pdf`, `other`).

### Headers

Required on every request:

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `Idempotency-Key` | Caller-generated ULID. The ledger keys exactly-once semantics on this. |
| `X-Sb-Ledger-Signature` | `v1=<hex hmac>` |
| `X-Sb-Ledger-Key-Id` | The HMAC key ID the signature was computed with. |
| `X-Sb-Request-Id` | Same ULID as the envelope's `request_id`. Echo for log correlation. |

`Idempotency-Key` and `request_id` are different on purpose: `request_id` identifies the *inbound 402 request from the agent*, while `Idempotency-Key` identifies *this attempt to talk to the ledger about that request*. A retry of a failed ledger call uses the *same* `Idempotency-Key`; a fresh redemption of the same token would use a *different* one (and would correctly be rejected by the ledger as a double-redeem).

### Signing

HMAC-SHA256 over the canonical signing string. Key material is loaded from the file pointed to by `SBPROXY_LEDGER_HMAC_KEY_FILE`; the file format is one or more lines of `<key_id>=<base64-key-bytes>`. Multiple keys present means rotation is in flight; the client signs with the *first* key (the active one) and the ledger accepts any key in its rotation window.

Canonical signing string:

```
<v>\n
<request_id>\n
<timestamp>\n
<nonce>\n
<workspace_id>\n
<HTTP method, uppercase>\n
<request path, no scheme/host/query>\n
<sha256-hex of request body>
```

Eight lines, `\n`-separated, no trailing newline. The hashed body, not the body itself, prevents the signing string from carrying the full payload while still binding the signature to it.

Signature header value: `v1=<lowercase hex of HMAC-SHA256>`. The `v1=` prefix lets us migrate to a different MAC (e.g. Ed25519) without breaking peers; receivers reject any value whose prefix is not in their accept list.

The client uses `subtle::ConstantTimeEq` on any signature comparison it performs (e.g. inbound webhook callbacks). Outbound, only the generation matters and is not timing-sensitive.

### Response envelope

Success:

```json
{
  "v": 1,
  "request_id": "01HZX...",
  "result": {
    "redeemed": true,
    "redemption_id": "red_abc",
    "remaining_balance_micros": 9000
  }
}
```

The `result` shape is verb-specific. `redeem` returns `{ redeemed: bool, redemption_id?: string, remaining_balance_micros?: u64 }`. `authorize` returns `{ authorization_id: string, expires_at: rfc3339 }`. `capture` returns `{ captured_amount_micros: u64, redemption_id: string }`. `refund` returns `{ refunded_amount_micros: u64, refund_id: string }`.

Error:

```json
{
  "v": 1,
  "request_id": "01HZX...",
  "error": {
    "code": "ledger.token_already_spent",
    "message": "Token tok_abc has already been redeemed.",
    "retryable": false,
    "retry_after_seconds": null
  }
}
```

| Field | Type | Notes |
|---|---|---|
| `code` | string, dotted | Machine-readable. `ledger.token_already_spent`, `ledger.signature_invalid`, `ledger.timestamp_skewed`, `ledger.idempotency_conflict`, `ledger.rate_limited`, `ledger.unavailable`, `ledger.bad_request`, `ledger.internal`. The set is closed; new codes need an ADR amendment. |
| `message` | string | Human-readable. Safe to log. Never echoes the payload. |
| `retryable` | bool | Hint to the client. `true` only for transient failures (`ledger.unavailable`, `ledger.rate_limited`, 5xx). Hard-failure codes (`ledger.token_already_spent`, `ledger.signature_invalid`) set `false`. |
| `retry_after_seconds` | u32, optional | When set, the client respects this in lieu of its own backoff schedule. Mirrored in the standard `Retry-After` HTTP header. |

HTTP status codes:

- 200: success (envelope.result present).
- 400: `ledger.bad_request`, `ledger.signature_invalid`, `ledger.timestamp_skewed`. Not retryable.
- 401: `ledger.signature_invalid` when key ID is unknown. Not retryable.
- 409: `ledger.token_already_spent`, `ledger.idempotency_conflict`. Not retryable; the latter means "you replayed this Idempotency-Key with a different body".
- 429: `ledger.rate_limited`. Retryable, observe `Retry-After`.
- 503: `ledger.unavailable`. Retryable.
- Any other 5xx: treated as `ledger.internal`, retryable.

### Idempotency

The ledger stores `(Idempotency-Key, request body hash, response body)` for at least 24 h. A repeat of the same `Idempotency-Key` returns the cached response *only if* the body hash matches. A repeat with a different body returns 409 `ledger.idempotency_conflict`.

The client generates a fresh `Idempotency-Key` per *logical* operation. A retry of a network failure for the same logical operation reuses the key. The `HttpLedger` client generates the key once, stores it on the in-flight request struct, and reuses it across retries.

### Retry policy

Exponential backoff with full jitter, max 5 attempts, per-attempt deadline 5 s, total deadline 30 s. Schedule: 0 ms, 250 ms, 500 ms, 1 s, 2 s base delay, each with `[0, base)` jitter added. Retry only on:

- network errors (DNS failure, TCP RST, TLS handshake failure, read timeout),
- HTTP status 429 (honor `Retry-After`),
- HTTP status 503 / 502 / 504,
- error envelope with `retryable: true`.

Do not retry on 4xx other than 429, on a `retryable: false` envelope, or after the total deadline. The 5-attempt cap prevents a slow-failing ledger from holding a request for 30 s+.

### Circuit breaker

Per-ledger-endpoint state machine, half-open / open / closed, in `sbproxy-platform/circuit_breaker.rs` (existing crate). Open after 10 consecutive failures over a 30 s sliding window. Half-open after 5 s, allowing one probe; close on probe success, re-open on probe failure.

When the breaker is open the client returns a synthetic `error.code = "ledger.unavailable"` envelope with `retryable: true` immediately, no network call. The policy at the request path treats this as "ledger is down": the configured `on_ledger_failure` action runs (default `fail_closed`, configurable to `fail_open` for low-stakes preview content).

The breaker emits two metrics:

- `sbproxy_ledger_circuit_breaker_state{endpoint}` (gauge: 0 closed, 1 half-open, 2 open),
- `sbproxy_ledger_circuit_breaker_transitions_total{endpoint, from, to}` (counter).

Both surface on the Grafana dashboards.

### Health probe

`GET /v1/ledger/healthz` returns `200 {"status":"ok"}` when the ledger is serving. The OSS proxy hits this every 30 s and surfaces the result on `/readyz`. A failing healthz does not by itself open the breaker; the breaker only opens on actual redeem failures.

### What this ADR does NOT decide

- The wallet model (balance, hold, debit). Owned by `adr-wallet-model.md`.
- x402 / MPP-specific payload extensions. The `authorize` / `capture` / `refund` shapes here are the common subset; rail-specific fields land via per-rail extension ADRs.
- Audit-log integration of ledger events. Owned by `adr-admin-action-audit.md`.

## Consequences

- One protocol covers the OSS HTTP ledger and downstream Stripe / x402 / MPP adapters. Per-rail adapters extend the `payload` field rather than redesigning the envelope.
- HMAC-SHA256 signing plus a 60 s timestamp window plus a 5-minute nonce cache makes replay attacks impractical. An attacker needs the active HMAC key, which lives only on the proxy host's secret mount.
- Idempotency-keyed retries make exactly-once semantics observable. A network blip during redeem cannot cause a double debit; the ledger short-circuits the second attempt with the cached response.
- The circuit breaker bounds the failure-mode latency. A dead ledger costs the request path one round-trip at most before the breaker opens and the policy's `on_ledger_failure` action runs.
- The closed error-code set means dashboards and alerts can filter on `code` without a regex maintenance burden. Adding a new code is an ADR amendment.
- The signing string includes the body hash but not the body itself, so signature traces are short and the body can be rotated through compression/encryption layers without the signature breaking.

## Alternatives considered

**gRPC instead of JSON-over-HTTPS.** Rejected. The OSS proxy already speaks HTTP/1.1 and HTTP/2 fluently; adding gRPC requires `prost`, `tonic`, and a generated client. JSON over HTTP is debuggable with `curl`, which matters for ops. The body sizes are small (under 1 KiB typical) so the wire-size argument for protobuf does not bite.

**Mutual TLS instead of HMAC.** Considered. mTLS would give us identity at the transport layer for free. Rejected because cert lifecycle (CA bootstrap, rotation, revocation) is itself a substantial ADR, and HMAC is the lower-friction choice when the proxy and the ledger are operated by the same party. A future revision may elevate to mTLS for cross-org ledger calls (e.g. third-party x402 facilitators); the `v1=` signature prefix leaves room.

**No idempotency key, rely on token uniqueness.** Rejected. Tokens are caller-supplied and can be replayed; the idempotency key is request-specific and lets the ledger distinguish "agent retried the redemption" (a real double-spend attempt) from "proxy retried after a network blip" (legitimate retry).

**Per-verb response shapes without a shared envelope.** Rejected. Every consumer would have to carry verb-specific decode logic; the shared `{v, request_id, result|error}` envelope means one type covers the protocol surface. The shape variation lives in `result` / `payload`.

**Plain HTTP allowed for local development.** Rejected. The risk of a misconfigured production deployment is not worth saving the operator three lines of `localhost` TLS setup. `examples/00-observability-stack/` ships self-signed certs anyway.

## References

- `crates/sbproxy-modules/src/policy/ai_crawl.rs` (existing `Ledger` trait and `InMemoryLedger`).
- Companion ADRs: `adr-agent-class-taxonomy.md` (the source of `agent_id`), `adr-event-envelope.md` (the source of `request_id`), `adr-billing-hot-path-vs-async.md` (the trait that speaks this protocol).
- IETF Idempotency-Key draft: `draft-ietf-httpapi-idempotency-key-header`.
- HMAC-SHA256: RFC 2104.
