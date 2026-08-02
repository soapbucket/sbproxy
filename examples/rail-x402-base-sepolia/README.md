# x402 v2 settlement on a priced route

*Last modified: 2026-08-01*

An article route that costs $0.001 to a declared AI crawler and nothing to
a reader, with x402 v2 `exact` configured as the settlement rail. The point
of the example is the boundary: a crawler gets a price, a credential the
proxy never issued gets nothing, and the origin is never called until a
durable record says the payment settled.

![x402 challenge and the closed failure path](../../docs/assets/payment-settlement.gif)

## What is in the bundle

| File | Role |
|---|---|
| `sb.yml` | `proxy.payments` with the x402 rail, plus one priced route |
| `sb-testnet.yml` | The same config pointed at a real facilitator and a funded address |
| `docker-compose.yml` | Optional containerized run of the same config |
| `mock-x402-facilitator/` | Optional local stub that answers `/verify` and `/settle` with the pinned v2 shapes |
| `Makefile` | `run`, `test`, `up`, `down`, `logs` |
| `smoke.json` | Liveness manifest for `scripts/examples-smoke.sh` |

## Prerequisites

An `sbproxy` binary built with the payment features, and a value for the
challenge binding key. No wallet, no facilitator account, and no funded
address are needed for anything on this page.

```bash
cargo build -p sbproxy --release --features payments,payment-x402
export SBPROXY_PAYMENT_BINDING_KEY="$(openssl rand -hex 32)"
```

The key is named in the config, never inlined. This example uses
`env:SBPROXY_PAYMENT_BINDING_KEY`, which reads that exported variable at
startup with no further configuration; `file:/path` works the same way.
Provider URIs such as `secret://<backend>/<name>` need a backend declared
under `proxy.secrets.backends` first, or the proxy refuses to boot. See
[docs/secrets.md](../../docs/secrets.md).

## Check the config before running anything

Validation reads shape and cross-field rules only. It resolves no secret,
opens no SQLite file, and contacts no facilitator, so it runs on a machine
that holds none of this config's credentials:

```bash
sbproxy validate -f examples/rail-x402-base-sepolia/sb.yml
```

Break something on purpose to see how specific the refusal is. Change
`network` from `eip155:84532` to `base` and validation names the field and
the reason:

```text
proxy.payments.rails.x402.network is "base", which is not a CAIP-2
identifier; use the `namespace:reference` form such as `eip155:84532`
rather than a short chain name, because an authoritative payment
requirement must not depend on a nickname translation
```

Set `verify_timeout_ms: 1200` alongside `settle_timeout_ms: 1200` and it
refuses the pair, because both legs share one request-path deadline:

```text
proxy.payments.rails.x402 verify_timeout_ms + settle_timeout_ms is 2400
ms, above proxy.payments.authorization_timeout_ms of 2000 ms; the request
path must finish verify and settle inside one deadline
```

## Run it

```bash
sbproxy serve -f examples/rail-x402-base-sepolia/sb.yml
```

`make run` wraps the same command against `../../target/release/sbproxy`.

### A reader is never charged

No declared crawler User-Agent, so the policy does not price the request
and the proxy forwards it upstream.

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'Host: blog.test.sbproxy.dev' \
  http://127.0.0.1:8080/article
```

### A declared crawler gets a price

```bash
curl -is \
  -H 'Host: blog.test.sbproxy.dev' \
  -H 'User-Agent: GPTBot/1.0' \
  http://127.0.0.1:8080/article
```

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
  "target": "blog.test.sbproxy.dev/article",
  "header": "crawler-payment"
}
```

`header` names the request header to set on the retry. A client that sends
`Accept-Payment: x402` instead gets the x402 challenge described in
[docs/402-challenge.md](../../docs/402-challenge.md).

### A credential the proxy never issued buys nothing

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'Host: blog.test.sbproxy.dev' \
  -H 'User-Agent: GPTBot/1.0' \
  -H 'crawler-payment: not-a-token-this-proxy-issued' \
  http://127.0.0.1:8080/article
```

The answer is another 402. A credential can never create the intent a
challenge would have created, so a request with no matching challenge
fails closed before any facilitator is contacted. The origin is not
called.

### The free paths stay free

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'Host: blog.test.sbproxy.dev' \
  -H 'User-Agent: GPTBot/1.0' \
  http://127.0.0.1:8080/robots.txt
```

A crawler can always read the site's policy without paying to learn it.
`/robots.txt`, `/sitemap.xml`, `/security.txt`,
`/.well-known/security.txt`, and `/crawlers.json` are free regardless of
config, and `free_paths:` extends that list.

## The two blocks, and who owns what

`proxy.payments` owns how a payment settles. `ai_crawl_control` owns which
requests are payable and what they cost. Nothing reads a price, an
address, a network, or an expiry from two places.

The x402 rail's fields are documented one by one in
[docs/payment-settlement.md](../../docs/payment-settlement.md). Four are
worth calling out here because they are the ones people get wrong:

- `network` is CAIP-2. `base` is rejected on purpose, because a signed
  payment requirement must not depend on a nickname translation table.
- `facilitator_url` is the facilitator's complete API root over HTTPS. The
  adapter keeps every path segment, strips only trailing slashes, and
  appends exactly `/verify` or `/settle`. A root of
  `https://facilitator.example/base/` produces
  `https://facilitator.example/base/verify` and `.../settle` and nothing
  else. A root that already ends in `/verify` is rejected rather than
  normalized.
- `asset_decimals` drives an exact integer conversion from quote micros.
  A price that does not convert without remainder is a config error, not a
  rounding.
- `breaker.half_open_max` is exactly 1. A second concurrent probe against
  an unhealthy facilitator can dispatch a settlement whose response nobody
  is waiting to record.

## Point it at a real facilitator

`sb-testnet.yml` is the same configuration with the placeholder
facilitator root, recipient address, and asset replaced. Nothing in this
repository spends funds, and CI never runs that file.

```bash
export SBPROXY_PAYMENT_BINDING_KEY="$(openssl rand -hex 32)"
sbproxy validate -f examples/rail-x402-base-sepolia/sb-testnet.yml
```

You will need a facilitator that serves the pinned v2 `exact` contract at
an HTTPS API root, a recipient address on the network you configure, and a
client that can produce an x402 payload for that scheme. Edit the
`facilitators`, `pay_to`, `network`, and `asset` fields to match the
facilitator's published values before serving it.

## Inspect the facilitator wire shapes locally

The bundled stub answers the two endpoints an x402 rail calls, with the
pinned v2 response shapes, so you can read them without an account:

```bash
docker compose up -d --wait mock-x402-facilitator
curl -s -X POST http://127.0.0.1:8081/verify -d '{}'
curl -s -X POST http://127.0.0.1:8081/settle -d '{}'
```

```json
{"isValid":true}
{"success":true,"transaction":"0x0000000000000000000000000000000000000000000000000000000000000000","network":"eip155:84532"}
```

The stub serves plain HTTP, and `facilitator_url` requires HTTPS, so it is
a wire-shape reference rather than a settlement backend. Point the rail at
a facilitator that serves TLS.

## Clean up

```bash
make down
```

## Related

- [docs/payment-settlement.md](../../docs/payment-settlement.md) - every `proxy.payments` field, the state table, reconciliation, and the unsupported boundaries.
- [docs/402-challenge.md](../../docs/402-challenge.md) - the exact challenge, credential, error, and receipt bytes.
- [docs/ai-crawl-control.md](../../docs/ai-crawl-control.md) - pricing, tiers, agent classes, and the ledger.
- `examples/rail-mpp-stripe-test/` - Payment HTTP Authentication settling on Stripe.
- `examples/rail-lightning/` - CLN and LND as alternative backends.
- `examples/multi-rail-accept-payment/` - several rails on one route.
