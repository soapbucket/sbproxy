# Payment HTTP Authentication settling on Stripe

*Last modified: 2026-08-01*

A markdown feed that costs $0.005 to a declared AI crawler, charged
through the IETF Payment authentication scheme with Stripe PaymentIntents
underneath. The example is where the two halves stay visibly separate:
`protocols.payment_auth` is the wire protocol, `rails.stripe` is what
moves the money, and `usage_reporters.stripe_meter` records consumption
without being able to settle anything.

Payment HTTP Authentication is a credential transport, not a network. That
is why there is no `mpp` rail to configure, and why enabling
`protocols.payment_auth` without `rails.stripe` is a load error.

## What is in the bundle

| File | Role |
|---|---|
| `sb.yml` | `protocols.payment_auth`, `rails.stripe`, and the meter reporter |
| `docker-compose.yml` | `sbproxy` plus a markdown feed origin, and an optional Stripe stand-in |
| `mock-origin/` | nginx serving one canned markdown body |
| `wiremock-stripe/` | Stripe-shaped JSON for offline work on the settlement path |
| `Makefile` | `up`, `up-wiremock`, `down`, `logs`, `test` |
| `smoke.json` | Liveness manifest for `scripts/examples-smoke.sh` |

## Prerequisites

Config validation needs nothing at all. Serving needs a binding key, a
32-byte recovery key, and a Stripe test key.

```bash
cargo build -p sbproxy --release --features payments,payment-mpp,payment-stripe
sbproxy validate -f examples/rail-mpp-stripe-test/sb.yml
```

```bash
export SBPROXY_PAYMENT_BINDING_KEY="$(openssl rand -hex 32)"
export SBPROXY_PAYMENT_RECOVERY_KEY="$(openssl rand -hex 32)"
export STRIPE_SECRET_KEY=sk_test_...
docker compose up -d --wait
```

A test key comes from the Stripe dashboard under `Developers > API keys`;
new accounts default to test mode. Nothing in this example charges a real
card, and no key is committed here.

## Why the recovery key is not optional

Enabling `rails.stripe` without `recovery_encryption` fails at load:

```text
proxy.payments.recovery_encryption is required when
proxy.payments.rails.stripe is set, because a crashed create must be
recoverable under the same idempotency key and the Payment Auth form of
that request contains a single-use payment token
```

A process that dies between stamping a dispatch and recording the response
leaves a write whose fate is unknown. The only safe resolution is
replaying byte-identical request bytes under the same idempotency key,
which means those bytes have to survive the crash, which means they have
to be encrypted, because in the Payment Auth form they contain a
single-use payment token. The rail refuses to start without the key that
seals them.

The key must decode to exactly 32 bytes. Load-time validation only checks
that the field names a secret; startup checks the length.

## The challenge

```bash
curl -is \
  -H 'Host: feed.test.sbproxy.dev' \
  -H 'User-Agent: ClaudeBot/1.0' \
  -H 'Accept-Payment: stripe;intent=charge' \
  http://127.0.0.1:8080/feed/articles/2026
```

```http
HTTP/1.1 402 Payment Required
Cache-Control: no-store
WWW-Authenticate: Payment id="...", realm="feed.test.sbproxy.dev", method="stripe", intent="charge", request="...", expires="2026-08-01T12:05:00Z", opaque="..."
Content-Type: application/problem+json
```

`Accept-Payment` is preference only. It carries no token, no signature,
and no amount, and it never authorizes a request. It picks which challenge
comes back.

Each offered challenge is its own `WWW-Authenticate` field. Parameters
appear in a fixed order and every value is quoted.
[docs/402-challenge.md](../../docs/402-challenge.md) has the full
parameter table, the seven-slot binding input, and the exact fixture
bytes.

## The retry

The client decodes `request`, obtains a single-use payment token for that
charge, and retries with one `Authorization` field:

```bash
curl -is \
  -H 'Host: feed.test.sbproxy.dev' \
  -H 'User-Agent: ClaudeBot/1.0' \
  -H "Authorization: Payment $CREDENTIAL" \
  http://127.0.0.1:8080/feed/articles/2026
```

Two `Payment` credentials on one request are a 400, not a 402: the request
is malformed rather than unpaid. A `Bearer` field alongside the `Payment`
field is skipped rather than rejected, so ordinary authentication still
works on a paid route.

On success the response carries `Cache-Control: private` and one
`Payment-Receipt` field whose `reference` is the PaymentIntent id, so the
payment is findable in the Stripe dashboard. No error response ever
carries a receipt.

## Settlement and usage reporting are different things

Both talk to Stripe. Only one can open a route.

| | PaymentIntents | Meter Events |
|---|---|---|
| Config block | `rails.stripe` | `usage_reporters.stripe_meter` |
| Registry | Settlement adapters | Usage reporters |
| Can produce a receipt | Yes | No |
| Can move an intent to `Succeeded` | Yes | No |
| Runs on | The request path, under one bounded deadline | The worker's queue |

The separation is enforced by the types rather than by a code comment. A
usage reporter has no way to construct a settlement receipt and no way to
reach the transition that commits one.

## Direct PaymentIntent mode

`direct_payment_intent.enabled: true` also offers Stripe directly, for
clients that already speak it. The challenge creates a manual-capture
PaymentIntent and returns its one-shot client secret in the immediate
response body. That value is never persisted, never hashed, and never
logged. The client confirms, retries, and the proxy retrieves, captures,
and requires `succeeded` before the origin is called.

`capture_method: automatic` is rejected at load. Preparing a challenge
must not take money for a resource that has not been delivered.

## Offline work on the settlement path

```bash
docker compose --profile wiremock up -d --wait
```

The wiremock container serves Stripe-shaped JSON on the endpoints the rail
calls. Mappings live under `wiremock-stripe/mappings/`. It is for
developing against the wire shapes without a Stripe account; it proves
nothing about settlement, because a stub asserting success is not a
provider confirming one.

## Clean up

```bash
docker compose down -v
```

## Related

- [docs/payment-settlement.md](../../docs/payment-settlement.md) - every `proxy.payments` field, the state table, and the unsupported boundaries.
- [docs/402-challenge.md](../../docs/402-challenge.md) - challenge parameters, credential shape, problem documents, and receipt encoding.
- `examples/rail-x402-base-sepolia/` - x402 v2 `exact`.
- `examples/rail-lightning/` - CLN and LND as alternative backends.
- `examples/multi-rail-accept-payment/` - several rails on one route.
