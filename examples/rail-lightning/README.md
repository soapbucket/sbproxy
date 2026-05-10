# Lightning Network billing rail (BOLT-12)
*Last modified: 2026-05-07*

Lightning rail in the `Accept-Payment` negotiation contract alongside
x402 + MPP. The example shows how an operator declares `lightning` in
the per-tier `rails:` override and what the OSS multi-rail challenge
body looks like for an agent that opts into Lightning settlement.

OSS advertises Lightning in the multi-rail challenge body; settlement
requires the enterprise `lightning-cln`, `lightning-lnd`, or
`lightning-phoenixd` cargo features. This example exercises the
negotiation path only.

## Why this is a doc-only example

Examples 30 and 31 ship Docker stacks because their settlement paths
have hermetic stand-ins (a mock x402 facilitator and a wiremock
Stripe). Lightning has no equivalent OSS stand-in: the BillingRail
trait impl that talks to a Lightning node lives in the enterprise
build, gated behind one of:

- `lightning-cln`     - Core Lightning node backend.
- `lightning-lnd`     - LND node backend.
- `lightning-phoenixd` - Phoenix self-custodial backend.

Each enterprise feature registers a `BillingRail` named `lightning`
into the trait registry. The OSS proxy consumes the registry and
emits a Lightning entry in the multi-rail body whenever a registered
rail matches the operator's offered set; with no rail registered, the
OSS proxy still negotiates against the `lightning` token on the wire
and falls back to the next entry the operator declared (here `x402`).

The contract this example pins is the negotiation shape: how the
operator declares Lightning in YAML, how the policy filters the
rails through the agent's `Accept-Payment` header, and what the
challenge body looks like.

## How the YAML composes

The interesting blocks in `sb.yml` are the per-tier `rails:` override
and the top-level `rails:` block:

```yaml
tiers:
  - route_pattern: /article*
    price:
      amount_micros: 1000
      currency: USD
    content_shape: html
    paywall_position: top_of_page
    rails:
      - lightning
      - x402

rails:
  x402:
    chain: base
    facilitator: https://facilitator-base.x402.org
    asset: USDC
    pay_to: "0x0000000000000000000000000000000000000000"
    version: "2"
  mpp:
    version: "1"
```

Two things to notice:

1. The per-tier `rails:` override lists `lightning` first, then
   `x402`. The order is the operator's preference: q-value ties on
   the agent side fall through to this declared order.

2. The top-level `rails:` block configures x402 + MPP because those
   are the rails the OSS build can settle today. Lightning does not
   appear at the top level: the `Rail::Lightning` enum variant on the
   OSS side is what makes the per-tier `rails: [lightning]` filter
   parse cleanly, and the registered enterprise BillingRail is what
   makes a Lightning entry appear in the emitted body.

## What the negotiation looks like

Per A3.1 the proxy resolves the agent's preferred rail order from
two signals:

1. The `Accept-Payment` request header (q-value list).
2. The `Accept` request header, when it carries one of
   `application/sbproxy-multi-rail+json`, `application/x402+json`, or
   `application/mpp+json`.

The proxy then:

1. Parses the agent's preference set (`lightning`, `x402`, ...).
2. Filters it through the operator's offered rails (per-tier
   override on `/article*` allows `lightning` and `x402`).
3. Sorts the survivors by the agent's q-value, breaking ties on the
   operator's declared rail order.
4. Emits one rail entry per surviving rail, each carrying its own
   per-rail quote-token JWS (separate nonce per rail per A3.2).
5. Returns 402 with the multi-rail body, or 406 if no rail survives.

### 1. AI crawler, Accept-Payment: lightning, x402

Agent prefers Lightning, falls back to x402.

```bash
curl -i \
     -H 'Host: blog.test.sbproxy.dev' \
     -H 'User-Agent: GPTBot/1.0' \
     -H 'Accept-Payment: lightning, x402' \
     http://127.0.0.1:8080/article
# HTTP/1.1 402 Payment Required
# Content-Type: application/sbproxy-multi-rail+json
# {
#   "rails": [
#     {
#       "kind": "lightning",
#       "amount_micros": 1000,
#       "currency": "USD",
#       "expires_at": "2026-05-07T...",
#       "quote_token": "eyJhbGc..."
#     },
#     {
#       "kind": "x402",
#       "version": "2",
#       "chain": "base",
#       "facilitator": "https://facilitator-base.x402.org",
#       "asset": "USDC",
#       "amount_micros": 1000,
#       "currency": "USD",
#       "pay_to": "0x0000...",
#       "expires_at": "2026-05-07T...",
#       "quote_token": "eyJhbGc..."
#     }
#   ],
#   "agent_choice_method": "header_negotiation",
#   "policy": "first_match_wins"
# }
```

The `lightning` entry only surfaces when the proxy is built with one
of the enterprise `lightning-*` features and the corresponding
BillingRail is registered. The OSS-default build serves the same
negotiation but emits only the `x402` entry from the per-tier
override.

### 2. AI crawler, Accept-Payment: lightning (no fallback)

Agent only accepts Lightning. With the enterprise build, the body
carries one `lightning` entry. With the OSS-default build, the
proxy responds 406 because the agent's preference set has no overlap
with the OSS-emittable rails:

```bash
curl -i \
     -H 'Host: blog.test.sbproxy.dev' \
     -H 'User-Agent: GPTBot/1.0' \
     -H 'Accept-Payment: lightning' \
     http://127.0.0.1:8080/article
# HTTP/1.1 406 Not Acceptable
# {"error":"no_acceptable_rail","supported_rails":["lightning","x402"], ...}
```

The `supported_rails` list on the 406 reflects the operator's
declared offered set (the per-tier `rails:` override), not the
runtime-emittable subset. The agent retries with one of the listed
rails on its `Accept-Payment` header.

### 3. AI crawler, no opt-in

A crawler UA without an `Accept-Payment` header (and without the
multi-rail Accept MIME) gets the Wave 1 single-rail format with the
`Crawler-Payment` header. Legacy crawlers keep working unchanged.

## How to swap an enterprise build in

Operators on the enterprise tier select one of:

| Feature              | Backend                                  | Use when                                         |
|----------------------|------------------------------------------|--------------------------------------------------|
| `lightning-cln`      | Core Lightning node (lightningd / cln)   | Operator runs CLN and wants direct gRPC control. |
| `lightning-lnd`      | LND node                                 | Operator runs LND or uses an LND-API hosted node. |
| `lightning-phoenixd` | Phoenix self-custodial daemon            | Operator wants a self-custodial single-binary path. |

Each feature registers the same `BillingRail` name (`lightning`) so
the OSS proxy's negotiation path does not change between backends;
only the settlement code does. The OSS YAML schema in `sb.yml` is
unchanged across backends, which is the reason the negotiation
contract is OSS and the settlement is enterprise.

## Cargo features (OSS)

The example assumes a default-features `sbproxy` build. The
multi-rail emission path is unconditional in the `sbproxy-modules`
crate; the per-tier `rails: [lightning]` filter parses cleanly
without any operator-set OSS feature because the `Rail::Lightning`
enum variant ships in the OSS schema.

The `lightning-cln`, `lightning-lnd`, and `lightning-phoenixd`
features are part of the enterprise build only.

## Related docs

-  (A3.1) - wire shape of the
  402 body.
-  (A3.2) - quote-token JWS shape and
  JWKS publication.
- `examples/rail-x402-base-sepolia/` - x402 rail with a hermetic
  mock facilitator.
- `examples/rail-mpp-stripe-test/` - MPP rail with Stripe test
  mode + wiremock fallback.
- `examples/multi-rail-accept-payment/` - both x402 + MPP wired
  together with q-value negotiation.
- `examples/quote-token-replay-jwks/` - JWKS endpoint and
  single-use quote-token enforcement.
