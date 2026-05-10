# 402 Challenge contract
*Last modified: 2026-05-08*

The wire format the proxy uses when it returns `402 Payment Required`
to an AI crawler. This document is the canonical reference for the
challenge body shape and for the line that splits OSS-advertises from
enterprise-settles.

The behavioural policy that emits these bodies is `ai_crawl_control`;
see [`ai-crawl-control.md`](ai-crawl-control.md) for configuration,
agent classes, ledger, and tiered pricing.

## Two challenge shapes

The OSS proxy emits one of two 402 shapes, picked per request:

1. **Single-rail (default).** Returned to legacy crawlers and to any
   request that has not opted in to multi-rail negotiation. Carries
   the `Crawler-Payment` response header and a flat JSON body with the
   price and currency. This is the long-standing Pay Per Crawl shape.

2. **Multi-rail (opt-in).** Returned when the agent opts in via either
   the `Accept-Payment` request header (a q-value list of rail names)
   or one of the multi-rail `Accept` MIME types
   (`application/sbproxy-multi-rail+json`, `application/x402+json`,
   `application/mpp+json`). Carries `Content-Type:
   application/sbproxy-multi-rail+json` and a JSON body that lists
   one entry per advertised rail, each with its own per-rail
   quote-token JWS.

The multi-rail body is the negotiation contract. It is fully defined
in OSS so the same proxy binary can advertise rails whether or not the
operator is running an enterprise build that can settle them.

## OSS advertises, enterprise settles

The split between what OSS does and what the enterprise build does is
deliberate, and matches the framing the rail-Lightning example PR
uses (see `examples/rail-lightning/README.md`).

What the OSS proxy does today:

- Parses the `Accept-Payment` header (RFC-style q-values) and the
  multi-rail `Accept` MIME types.
- Filters the agent's preference set against the operator's per-tier
  `rails:` override and the top-level `rails:` block.
- Emits the multi-rail 402 body with one entry per surviving rail,
  each carrying its own quote-token JWS (separate nonce per rail).
- Responds 406 `no_acceptable_rail` when the preference set has no
  overlap with the offered rails, listing the operator's offered set
  on the response.
- Falls back to the single-rail format for legacy crawlers that did
  not opt in.
- Honours the in-memory ledger (`valid_tokens:`) and the HTTPS-only
  HTTP ledger client for accept-payment redemption.

What the OSS proxy cannot do today:

- Settle a real-money payment on a stablecoin or fiat rail.
- Verify an x402 redemption token against a facilitator.
- Capture a Stripe `payment_intent`.
- Open or close a Lightning invoice.

Settlement on those rails requires the enterprise build, gated behind
cargo features:

| Feature              | Settles                                        |
|----------------------|------------------------------------------------|
| `stripe`             | Stripe fiat (cards, ACH).                      |
| `x402`               | x402 v2 stablecoin-on-chain via a facilitator. |
| `mpp`                | Stripe Multi-Party Payments.                   |
| `lightning-cln`      | Core Lightning node.                           |
| `lightning-lnd`      | LND node.                                      |
| `lightning-phoenixd` | Phoenix self-custodial daemon.                 |

Each enterprise feature registers a `BillingRail` impl into the OSS
plugin trait registry under the canonical rail name the OSS schema
already understands (`x402`, `mpp`, `lightning`). The OSS YAML schema
in `sb.yml` does not change across enterprise backends; only the
settlement code does. That is the property this contract pins:
operators write the same `sb.yml` whether they run OSS or an
enterprise build.

## Single-rail body

The default 402 body for legacy crawlers. Returned with the
`Crawler-Payment` response header and `Content-Type: application/json`.

```json
{
  "error": "payment_required",
  "price": "0.001",
  "currency": "USD",
  "target": "blog.example.com/article",
  "header": "crawler-payment"
}
```

The `header` field tells the crawler which header name to set on its
retry. The default is `crawler-payment`; operators override it via the
policy's `header:` config field.

## Multi-rail body

Emitted when the agent opted in. `Content-Type:
application/sbproxy-multi-rail+json`.

```json
{
  "rails": [
    {
      "kind": "x402",
      "version": "2",
      "chain": "base",
      "facilitator": "https://facilitator-base.x402.org",
      "asset": "USDC",
      "amount_micros": 1000,
      "currency": "USD",
      "pay_to": "0x0000000000000000000000000000000000000000",
      "expires_at": "2026-05-08T12:34:56Z",
      "quote_token": "eyJhbGc..."
    },
    {
      "kind": "mpp",
      "version": "1",
      "amount_micros": 1000,
      "currency": "USD",
      "expires_at": "2026-05-08T12:34:56Z",
      "quote_token": "eyJhbGc..."
    }
  ],
  "agent_choice_method": "header_negotiation",
  "policy": "first_match_wins"
}
```

Notes:

- `rails[].kind` is a closed enum: `x402`, `mpp`, `lightning`. Adding
  a rail follows the closed-enum amendment rule in
  [`adr-fast-track-amendment.md`](adr-fast-track-amendment.md).
- `rails[].quote_token` is a JWS. One nonce per rail per response, so
  the agent cannot replay a quote across rails. JWKS publication and
  token replay are covered by the
  `examples/quote-token-replay-jwks/` example.
- `rails[]` order is the operator's declared preference. Agents break
  ties on this order after q-value sorting their own preference set.
- Lightning entries appear in the body only when an enterprise
  `lightning-*` feature has registered a `BillingRail` named
  `lightning` into the trait registry. With the OSS-default build, a
  per-tier `rails: [lightning, x402]` declaration parses cleanly (the
  `Rail::Lightning` enum variant ships in OSS) and the proxy still
  negotiates against the `lightning` token on the wire; the body just
  carries the next surviving rail (here `x402`).

## 406 fallback

When the agent's `Accept-Payment` preference set has no overlap with
the operator's offered rails, the proxy returns `406 Not Acceptable`
with `Content-Type: application/json`:

```json
{
  "error": "no_acceptable_rail",
  "supported_rails": ["x402", "mpp"],
  "target": "blog.example.com/article"
}
```

`supported_rails` reflects the operator's declared offered set on the
matched tier (the per-tier `rails:` override, or the route default if
no override is set), not the runtime-emittable subset. The agent
retries with one of the listed rails on its `Accept-Payment` header.

## Opt-in signals

Per A3.1, any of the following signals on the request opts the agent
in to the multi-rail body:

- `Accept-Payment` request header carries a q-value list of rail
  names. Example: `Accept-Payment: lightning;q=1.0, x402;q=0.5`.
- `Accept` request header includes
  `application/sbproxy-multi-rail+json`,
  `application/x402+json`, or `application/mpp+json`. The latter two
  are narrowly opt-in: an agent that sends `Accept:
  application/x402+json` is asking specifically for the x402 entry,
  not for the full multi-rail body.

Without any opt-in signal, the proxy emits the single-rail body so
legacy crawlers keep working unchanged.

## Quote-token JWS

Each rail entry in the multi-rail body carries its own `quote_token`,
signed by the proxy under a key whose JWKS the operator publishes at
`/.well-known/sbproxy-quote-jwks`. The token binds the rail kind, the
amount, the route, and a per-rail nonce so the agent cannot replay a
quote across rails or reuse it after expiry.

The `accept_payment` policy verifies the JWS on the agent's retry
before consulting the ledger. A token whose claims do not match the
retry context (different rail, different route, expired) is rejected
without a ledger round-trip.

The token schema is OSS. The settlement that the token underwrites is
enterprise.

## Related

- [`ai-crawl-control.md`](ai-crawl-control.md) - policy configuration,
  agent classes, ledger, tiered pricing.
- [`enterprise.md`](enterprise.md) - the OSS / enterprise split,
  including the rail settlement features.
- `examples/rail-x402-base-sepolia/` - x402 rail with a hermetic
  mock facilitator.
- `examples/rail-mpp-stripe-test/` - MPP rail with Stripe test
  mode and a wiremock fallback.
- `examples/multi-rail-accept-payment/` - x402 + MPP wired
  together with q-value negotiation.
- `examples/rail-lightning/` - Lightning rail negotiation contract
  (settlement is enterprise-only).
- `examples/quote-token-replay-jwks/` - JWKS endpoint and
  single-use quote-token enforcement.
