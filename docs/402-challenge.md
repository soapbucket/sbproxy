# 402 challenge contract

*Last modified: 2026-08-09*

The exact bytes SBproxy puts on the wire when a request has to be paid
for, and the exact bytes it accepts back. This page is the wire reference.
The operator guide to configuring settlement is
[payment-settlement.md](payment-settlement.md), and the policy that
decides which requests are payable is
[ai-crawl-control.md](ai-crawl-control.md).

## The flow this contract describes

1. The route computes a price.
2. SBproxy builds one normalized requirement from that price and
   `proxy.payments`, and from nothing else.
3. The client says which method it prefers.
4. SBproxy signs the requirement, persists it as a pending intent, and
   answers 402 with one protocol challenge.
5. The client fulfills the challenge and retries with the protocol
   credential.
6. SBproxy verifies the credential locally, then performs the rail's
   required verification and settlement inside one bounded deadline.
7. SQLite records the settlement.
8. Only then does the origin see the request.

Steps 6 through 8 are ordered on purpose. Nothing between the challenge
and the committed record opens the route.

## Accept-Payment is a preference, never a credential

`Accept-Payment` is a request header listing the payment methods the
client can use, in the client's own order of preference. It carries no
signature, no token, no address, no amount, and no proof of anything. It
selects which challenge is emitted. It never authorizes a request.

```http
Accept-Payment: stripe;intent=charge;q=1.0, x402;q=0.5
```

The grammar is a comma-separated list. Each entry is a method token,
optionally followed by `;intent=<token>` and `;q=<quality>`.

| Parameter | Rules |
|---|---|
| method | Lowercased. 1 to 64 bytes of ASCII alphanumerics, `-`, `_`, or `.`. |
| `intent` | Same token rules. Optional. |
| `q` | Absent means `1.0`. At most three fractional digits. A value above `1.0` is invalid. |

Parsing is per entry, never per request. A duplicate `intent`, a duplicate
`q`, an unknown parameter, a quality above 1.0, or a malformed token drops
that one entry and leaves the rest intact. A malformed header is never a
reason to refuse a payable request. Entries sort by descending quality,
and the client's own order is preserved within one quality.

## Payment HTTP Authentication

Pinned to `draft-ryan-httpauth-payment-01`. No protocol version appears on
the wire. This release implements exactly one registered pair, `stripe`
plus `charge`, from `draft-stripe-charge-00`.

### The challenge

One offered challenge means one `WWW-Authenticate` field. Two offered
challenges means two separate fields, never one field carrying both.

```http
HTTP/1.1 402 Payment Required
Cache-Control: no-store
WWW-Authenticate: Payment id="zALONMyg62ie-ZqvHAWSvZU82ywJfV8mXk-mB2H585E", realm="api.example.com", method="stripe", intent="charge", request="eyJhbW91bnQiOiIxMDAwIiwi...", expires="2026-07-29T20:05:00Z", digest="sha-256=:ikRyUhC53NT+/Z8Oyge3CuReaSdKMQX7JetCaiz4u/Q=:", opaque="eyJpbnRlbnRfaWQiOiJzdGxfMDEiLCJwcm92aWRlciI6InN0cmlwZSJ9"
```

Parameters appear in this order, each value double-quoted, separated by a
comma and one space.

| Parameter | Required | Value |
|---|---|---|
| `id` | yes | Unpadded base64url of the challenge MAC. See "Binding" below. |
| `realm` | yes | The protection space from `protocols.payment_auth.realm`. |
| `method` | yes | `stripe`. |
| `intent` | yes | `charge`. |
| `request` | yes | Unpadded base64url of the JCS form of the charge request object. |
| `expires` | yes | Exactly `YYYY-MM-DDTHH:MM:SSZ`, 20 bytes. No offsets, no fractional seconds, no lowercase separators. |
| `digest` | when the request has a body | The RFC 9530 parameter over the exact request bytes. |
| `opaque` | when routing state is carried | Unpadded base64url of the JCS form of the opaque object. |

An absent optional parameter is omitted entirely and never emitted empty.
A rendered challenge is capped at 8 KiB. Unknown parameters on a received
challenge are ignored, as draft-01 requires, but a repeated parameter, an
unquoted value, an empty value, or a value containing a backslash is
rejected.

The `request` object is the pinned charge request:

```json
{"amount":"1000","currency":"usd","externalId":"quote_01","methodDetails":{"metadata":{"quote_id":"quote_01"},"networkId":"profile_test_123","paymentMethodTypes":["card"]}}
```

The `opaque` object carries non-secret routing state only:

```json
{"intent_id":"stl_01","provider":"stripe"}
```

### Binding

`id` is HMAC-SHA256 over exactly seven slots joined by `|`, encoded as
unpadded base64url. An absent optional slot is an empty string, not a
skipped separator.

```text
realm|method|intent|request|expires|digest|opaque
```

The key is `proxy.payments.challenge_binding_key`. Comparison is constant
time. Because the realm is the first slot, changing it invalidates every
outstanding challenge.

### The credential

Exactly one `Authorization` field carrying the `Payment` scheme. The token
is unpadded base64url of UTF-8 JSON.

```http
Authorization: Payment eyJjaGFsbGVuZ2UiOnsiZGlnZXN0Ijoic2hhLTI1Nj06aWtSeVVoQzUzTlQr...
```

Decoded:

```json
{"challenge":{"digest":"sha-256=:ikRyUhC53NT+/Z8Oyge3CuReaSdKMQX7JetCaiz4u/Q=:","expires":"2026-07-29T20:05:00Z","id":"zALONMyg62ie-ZqvHAWSvZU82ywJfV8mXk-mB2H585E","intent":"charge","method":"stripe","opaque":"eyJpbnRlbnRfaWQiOiJzdGxfMDEiLCJwcm92aWRlciI6InN0cmlwZSJ9","realm":"api.example.com","request":"eyJhbW91bnQiOiIxMDAwIiwi..."},"payload":{"spt":"spt_test_123"}}
```

`challenge` echoes the eight challenge parameters. `payload` is the pinned
Stripe charge payload: a required `spt` and an optional `externalId`.
Unknown members are ignored at the top level and rejected inside
`payload`.

A credential is refused as malformed when the token is over 16 KiB, is not
strict unpadded base64url, decodes to invalid UTF-8 or invalid JSON,
repeats a JSON key, nests deeper than 16 levels, carries an `spt` that
does not begin with `spt_` or exceeds 4 KiB, or carries an `externalId`
that is empty or over 255 bytes. Padding characters, `+`, and `/` in
base64url positions are refused rather than repaired. A field carrying a
different scheme, such as `Bearer`, is skipped rather than rejected. Two
`Payment` credentials on one request are a 400.

Verification runs in a fixed order and coerces nothing: strip the scheme,
decode, check the binding, check expiry, check the body digest, decode
`request`, decode `opaque`. An expired challenge is not renewed and a
mismatched digest is not recomputed.

### Body digest

The digest parameter is the RFC 9530 structured-field byte sequence over
the exact request bytes:

```text
sha-256=:ikRyUhC53NT+/Z8Oyge3CuReaSdKMQX7JetCaiz4u/Q=:
```

That inner value is standard base64 with padding, and it is the one place
in this contract that is not base64url. For the body `{"prompt":"hello"}`
with no trailing newline, the parameter is exactly the string above.

Presence is strict in both directions. A request with a body and no digest
is refused, and a digest with no body is refused. A request with neither
passes. The bytes are read once, capped at
`proxy.payments.max_body_bytes`, and replayed to the origin unchanged only
after settlement. A body over the cap is answered 413 before any challenge
or provider work.

### Errors

Every failure is a Problem Details document with
`Content-Type: application/problem+json` and exactly three members.

```json
{"type":"https://paymentauth.org/problems/verification-failed","title":"Payment verification failed","status":402}
```

| Code | Type URI suffix | Status | Title |
|---|---|---|---|
| `payment-required` | `/payment-required` | 402 | Payment required |
| `payment-insufficient` | `/payment-insufficient` | 402 | Payment insufficient |
| `payment-expired` | `/payment-expired` | 402 | Payment challenge expired |
| `verification-failed` | `/verification-failed` | 402 | Payment verification failed |
| `method-unsupported` | `/method-unsupported` | 400 | Payment method not supported |
| `malformed-credential` | `/malformed-credential` | 402 | Malformed payment credential |
| `invalid-challenge` | `/invalid-challenge` | 402 | Invalid payment challenge |

The URI prefix is `https://paymentauth.org/problems/`. The `status` member
is the status the response actually carries, which is not always the
code's registered status: two `Payment` credentials on one request produce
the `malformed-credential` type with `status: 400`, because the request is
malformed rather than unpaid.

Four refusals carry no problem document at all: a body over the cap (413),
a challenge that would exceed 8 KiB (500), a Payment flow attempted over
cleartext (421), and an internal error (500).

A fresh challenge accompanies a refusal only when the status is 402. The
400, 413, 421, and 500 answers do not re-challenge.

### Cache control and the receipt

Every 402 carries `Cache-Control: no-store`. A successful paid 2xx carries
`Cache-Control: private` and one `Payment-Receipt` field. No error
response ever carries a receipt.

The receipt is the JCS form of four required members, encoded as unpadded
base64url:

```json
{"method":"stripe","reference":"pi_test_123","status":"success","timestamp":"2026-07-29T20:00:00Z"}
```

```http
Payment-Receipt: eyJtZXRob2QiOiJzdHJpcGUiLCJyZWZlcmVuY2UiOiJwaV90ZXN0XzEyMyIsInN0YXR1cyI6InN1Y2Nlc3MiLCJ0aW1lc3RhbXAiOiIyMDI2LTA3LTI5VDIwOjAwOjAwWiJ9
```

`reference` is the provider's own identifier, so an operator can look the
payment up at the provider. `status` is always `success`, because a
receipt is only ever written for a settled payment.

## Direct Stripe PaymentIntent mode

An alternative to Payment HTTP Authentication for clients that already
speak Stripe. Enable it with
`proxy.payments.rails.stripe.direct_payment_intent.enabled: true`.

The challenge creates a manual-capture PaymentIntent and returns its
one-shot client secret in the immediate response body. That value is never
persisted, never hashed, and never logged. The client confirms the
PaymentIntent, then retries the original request. The proxy retrieves the
challenge-bound PaymentIntent, captures it, confirms the authoritative
result is `succeeded`, and only then allows the origin.

Automatic capture is refused by config validation. Challenge preparation
must not take money for a resource it has not delivered.

## x402 v2 `exact`

Three header fields, all standard RFC 4648 base64 with padding over
compact UTF-8 JSON. Base64url is rejected, and so is stripped padding. A
header value is capped at 64 KiB.

| Field | Direction | Carries |
|---|---|---|
| `PAYMENT-REQUIRED` | 402 response | The `PaymentRequired` object below |
| `PAYMENT-SIGNATURE` | credential retry | The `PaymentPayload` object below |
| `PAYMENT-RESPONSE` | settled 2xx only | The facilitator's exact settle response |

There is no `X-` prefix on any of them, and x402 never emits
`Payment-Receipt`.

### The challenge object

```json
{
  "x402Version": 2,
  "resource": {"url": "https://blog.example.com/article"},
  "accepts": [
    {
      "scheme": "exact",
      "network": "eip155:84532",
      "amount": "1000",
      "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      "payTo": "0x1111111111111111111111111111111111111111",
      "maxTimeoutSeconds": 60,
      "extra": {"name": "USDC", "version": "2"}
    }
  ],
  "extensions": {
    "sbproxy-requirement": {
      "info": {"id": "<requirement id>", "quote": "<quote JWS>"},
      "schema": {}
    }
  }
}
```

`resource` may also carry `description`, `mimeType`, `serviceName`,
`tags`, and `iconUrl`. An optional top-level `error` string appears when
the 402 follows a failed attempt. Unknown top-level fields are rejected.

`sbproxy-requirement` is the only SBProxy extension in the envelope, and
it lives under `extensions` rather than as an undocumented top-level
field. Its `schema` member is a JSON Schema Draft 2020-12 object with
`additionalProperties: false`, requiring a string `id` matching
`^[A-Za-z0-9_-]{16,128}$` and a string `quote` of length 1 through 4096.
`id` is the durable requirement id and `quote` is its signed quote JWS.

### The credential object

```json
{
  "x402Version": 2,
  "resource": {},
  "accepted": {},
  "payload": {},
  "extensions": {}
}
```

`resource`, `accepted`, and `extensions` must be exact echoes of the
challenge. `accepted` is the one `accepts` entry the client chose.
`payload` is the scheme's signed object and is never interpreted by the
proxy; it is canonicalized and hashed to bind the credential to one
intent.

The echo is checked before the facilitator is contacted. A changed
extension, a changed requirement, a duplicate header, a duplicate JSON
key, an unknown top-level field, an oversized body, or an `x402Version`
other than 2 all stop the request locally.

### Facilitator calls

Both endpoints are formed by keeping the configured API root's path,
stripping only trailing slashes, and appending `/verify` or `/settle`.
Nothing else is ever constructed. Both calls post identical bytes:

```json
{"x402Version":2,"paymentPayload":{},"paymentRequirements":{}}
```

The verify response is read for `isValid`, and optionally
`invalidReason`, `payer`, and `extra`. An `isValid` that is `false` or
absent is a refusal, and settle is never prepared or sent.

The settle response is read for `success`, and optionally `errorReason`,
`payer`, `transaction`, `network`, `amount`, and `extensions`. Settlement
counts only when `success` is `true`, `transaction` is non-empty,
`network` equals the accepted requirement's network exactly, `amount`
equals the accepted amount exactly whenever the response includes it, and
the two responses' `payer` values agree whenever both are present.
Anything else is ambiguous and goes to reconciliation rather than to the
origin.

On success the origin is called and the exact settle response is echoed
back as `PAYMENT-RESPONSE`.

## Legacy `Crawler-Payment` compatibility

Crawlers that send no payment preference still get the long-standing Pay
Per Crawl shape, so nothing that works today stops working.

```http
HTTP/1.1 402 Payment Required
Crawler-Payment: realm="ai-crawl" currency="USD" price="0.001"
Content-Type: application/json
```

```json
{
  "error": "payment_required",
  "price": "0.001",
  "currency": "USD",
  "target": "blog.example.com/article",
  "header": "crawler-payment"
}
```

`header` names the request header the crawler sets on its retry. The
default is `crawler-payment`, overridden by the policy's `header:` field.

### Cloudflare Pay Per Crawl interop

`cloudflare_compat: true` on the `ai_crawl_control` policy speaks
Cloudflare's header set instead. The 402 carries
`crawler-price: <currency> <amount>`, the crawler retries with
`crawler-exact-price` or `crawler-max-price` alongside its token, and a
served request carries `crawler-charged: <currency> <amount>` so the
crawler learns exactly what it paid. A `crawler-max-price` below the
quote, or a `crawler-exact-price` that does not equal it, re-quotes with a
fresh 402 and spends nothing.

An operator running the `bot_auth` verifier can require those inbound
price headers to be signed components by listing the header name in an
agent's `required_components`, so a retry whose signature does not cover
the price header is rejected before the ledger is consulted.

### Always-free paths

These are never charged, so a crawler can always read the site's policy
without paying to learn it:

- `/robots.txt`
- `/sitemap.xml`
- `/security.txt`
- `/.well-known/security.txt`
- `/crawlers.json`

The policy's `free_paths:` list extends this built-in allowlist. A
trailing `*` is a prefix match; anything else matches exactly. The
built-in list always applies, so an operator cannot accidentally start
charging for `robots.txt`.

## Multi-rail negotiation body

When a client opts in with `Accept-Payment` or with an `Accept` value of
`application/sbproxy-multi-rail+json`, `application/x402+json`, or
`application/mpp+json`, the policy answers with a body listing one entry
per advertised rail, each carrying its own quote-token JWS.

```json
{
  "rails": [
    {
      "kind": "x402",
      "version": "2",
      "amount_micros": 1000,
      "currency": "USD",
      "expires_at": "2026-08-01T12:34:56Z",
      "quote_token": "eyJhbGc..."
    }
  ],
  "agent_choice_method": "header_negotiation",
  "policy": "first_match_wins"
}
```

`rails[].kind` is a closed set; an unknown kind is rejected at validate
time. Entry order is the operator's declared preference and breaks ties
after the client's own quality sort. Each entry gets its own nonce, so a
quote cannot be replayed across rails.

The `application/x402+json` and `application/mpp+json` values are narrow
opt-ins: a client sending one of them is asking for that rail's entry
rather than for the full list.

When the client's preference set has no overlap with the route's
advertised rails, the answer is 406:

```json
{
  "error": "no_acceptable_rail",
  "supported_rails": ["x402", "mpp"],
  "target": "blog.example.com/article"
}
```

`supported_rails` is the operator's declared offered set on the matched
tier, which is what the client should choose from on its retry.

## Quote tokens

Each advertised rail carries its own `quote_token`, a JWS signed by the
proxy under a key whose JWKS the operator publishes at
`/.well-known/sbproxy/quote-keys.json`. The token binds the rail, the
amount, the route, and a per-rail nonce, so a client cannot replay a quote
across rails or reuse it after expiry.

The document can carry more than one key, so resolve a token by the `kid`
in its header rather than by taking the first entry. An origin
mid-rotation publishes two: the key it signs under now, and the
`previous_key_id` it still verifies for the length of the rotation window.
A multi-tenant deployment publishes one document covering every origin's
issuer, which is a different reason for the same shape.

On the retry the token is authenticated and its claims validated without
consuming the nonce, which is why the same client `Idempotency-Key` with
the same credential can resume a retry or read a committed receipt, while
a different credential cannot reuse the quote. The nonce is spent later
and separately, in its own durable write, once a committed receipt has
authorized a response. Spending it any earlier would burn the quote while
parsing a signature and leave an interrupted payment unresumable. See
[payment-settlement.md](payment-settlement.md#replay-protection-and-where-it-stops)
for what that spend covers and where it stops.

## Related

- [payment-settlement.md](payment-settlement.md) - configuring rails, durable state, timeouts, reconciliation, and the exact unsupported boundaries.
- [ai-crawl-control.md](ai-crawl-control.md) - pricing, tiers, agent classes, and the ledger.
- `examples/rail-x402-base-sepolia/` - x402 v2 `exact` on a priced route.
- `examples/rail-mpp-stripe-test/` - Payment HTTP Authentication settling on Stripe.
- `examples/rail-lightning/` - CLN and LND as alternative backends.
- `examples/multi-rail-accept-payment/` - several rails on one route.
- `examples/quote-token-replay-jwks/` - the JWKS endpoint and single-use quote enforcement.
