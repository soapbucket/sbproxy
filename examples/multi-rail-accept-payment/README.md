# Three ways to pay for one route

*Last modified: 2026-08-01*

One article route that accepts x402, Payment HTTP Authentication, and
Stripe directly, all priced at $0.001. The example is about negotiation:
how a client states a preference, how the proxy picks one challenge, and
what happens when the preference and the offer do not overlap.

`Accept-Payment` is a preference list and nothing more. It carries no
token, no signature, no address, and no amount. It selects which challenge
comes back and never authorizes a request.

## What is in the bundle

| File | Role |
|---|---|
| `sb.yml` | x402 and Stripe rails plus the Payment Auth protocol, all in USD |
| `docker-compose.yml` | `sbproxy`, a mock origin, and the stubs from the sibling examples |
| `mock-origin/` | nginx serving one canned article |
| `Makefile` | `up`, `down`, `logs`, `test` |
| `smoke.json` | Liveness manifest for `scripts/examples-smoke.sh` |

## Run it

```bash
cargo build -p sbproxy --release --features payments,payment-mpp,payment-stripe,payment-x402
sbproxy validate -f examples/multi-rail-accept-payment/sb.yml
```

```bash
export SBPROXY_PAYMENT_BINDING_KEY="$(openssl rand -hex 32)"
export SBPROXY_PAYMENT_RECOVERY_KEY="$(openssl rand -hex 32)"
export STRIPE_SECRET_KEY=sk_test_...
docker compose up -d --wait
```

## The grammar

```http
Accept-Payment: x402;q=1.0, stripe;intent=charge;q=0.5
```

Each entry is a method token, optionally followed by `;intent=<token>` and
`;q=<quality>`. Absent `q` means `1.0`. Entries sort by descending
quality, and the client's own order is preserved within one quality, so
listing two methods at equal quality is a meaningful statement of
preference.

Parsing is per entry. A duplicate `intent`, a duplicate `q`, an unknown
parameter, a quality above 1.0, or a malformed token drops that one entry
and leaves the rest intact:

```http
Accept-Payment: stripe;spt=secret, lightning;q=0.25
```

The first entry is dropped because `spt` is not a preference parameter,
and the second survives. A malformed header is never a reason to refuse a
payable request, and proof material in this header is never read as proof
of anything.

## What each preference gets

```bash
curl -is -H 'Host: blog.test.sbproxy.dev' -H 'User-Agent: GPTBot/1.0' \
  -H 'Accept-Payment: x402' \
  http://127.0.0.1:8080/article
```

An x402 preference gets the 402 with one `PAYMENT-REQUIRED` field.

```bash
curl -is -H 'Host: blog.test.sbproxy.dev' -H 'User-Agent: ClaudeBot/1.0' \
  -H 'Accept-Payment: stripe;intent=charge' \
  http://127.0.0.1:8080/article
```

A `stripe` plus `charge` preference gets the 402 with one
`WWW-Authenticate: Payment` field. Two offered challenges would be two
separate fields, never one field carrying both.

```bash
curl -is -H 'Host: blog.test.sbproxy.dev' -H 'User-Agent: GPTBot/1.0' \
  http://127.0.0.1:8080/article
```

No preference at all gets the legacy `Crawler-Payment` shape, so crawlers
that predate any of this keep working unchanged.

```bash
curl -is -H 'Host: blog.test.sbproxy.dev' -H 'User-Agent: PerplexityBot/1.0' \
  -H 'Accept-Payment: carrier-pigeon' \
  http://127.0.0.1:8080/article
```

A preference with no overlap gets 406 and a list to choose from:

```json
{
  "error": "no_acceptable_rail",
  "supported_rails": ["x402", "mpp"],
  "target": "blog.test.sbproxy.dev/article"
}
```

## One currency per challenge

Every rail this route advertises declares `quote_currency: USD`. That is
required, not stylistic. The proxy performs no currency conversion, so a
mixed-currency challenge would offer the payer two different prices for
one resource. Adding a BTC Lightning rail to this route is refused at
load:

```text
advertised rails x402 and lightning are priced in USD and BTC; one
challenge cannot mix currencies because the proxy performs no
foreign-exchange conversion
```

Serving both means two routes, each priced in its own currency, each
advertising rails that agree.

## mpp and stripe settle on the same rail

`mpp` names Payment HTTP Authentication, which is a credential transport
rather than a network that moves funds. Its registered `stripe` plus
`charge` pair settles through `rails.stripe`, the same block the direct
Stripe mode uses. That is why the config has no `mpp` rail to configure
and why `protocols.payment_auth` without `rails.stripe` is a load error:

```text
proxy.payments.protocols.payment_auth uses method `stripe`, which settles
through proxy.payments.rails.stripe; configure that rail or remove the
protocol
```

The two differ in where the credential arrives and what comes back. Payment
Auth takes an `Authorization: Payment` credential and answers a settled
request with `Payment-Receipt`. Direct mode hands out a client secret at
challenge time and takes the retry after the client has confirmed.

## Only one rail is charged

A client presents one credential. The proxy reserves that credential's
digest against exactly one durable intent before any provider call, so a
credential replayed against a different intent stops there. Advertising
three ways to pay does not create three ways to be charged.

## Clean up

```bash
docker compose down -v
```

## Related

- [docs/payment-settlement.md](../../docs/payment-settlement.md) - every `proxy.payments` field, the state table, and the unsupported boundaries.
- [docs/402-challenge.md](../../docs/402-challenge.md) - the exact challenge, credential, error, and receipt bytes.
- `examples/rail-x402-base-sepolia/` - x402 v2 `exact` on its own.
- `examples/rail-mpp-stripe-test/` - Payment HTTP Authentication settling on Stripe.
- `examples/rail-lightning/` - CLN and LND as alternative backends.
