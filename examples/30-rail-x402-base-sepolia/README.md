# 30 - rail-x402-base-sepolia
*Last modified: 2026-05-02*

x402 v2 paywall in front of an article origin, wired against a local
mock x402 facilitator so the example runs end-to-end without touching
a real testnet. The README covers two paths:

1. The default stack (mock facilitator). Brings up in seconds; uses
   no real keys; suitable for CI.
2. The Base Sepolia opt-in path (`sb-testnet.yml`). Points the proxy
   at the LF-stewarded Base Sepolia facilitator and uses an EIP-3009
   `transferWithAuthorization` flow with real (testnet) USDC.

The stack is shaped after `examples/24-ai-crawl-tiered/`: one proxy,
one mock facilitator, one mock origin, all on a private bridge
network.

## How it composes

| Service                | Image                              | Role                                                                        |
|------------------------|------------------------------------|-----------------------------------------------------------------------------|
| sbproxy                | built from `Dockerfile.cloudbuild` | Reverse proxy on `:8080` enforcing `ai_crawl_control` per `sb.yml`.         |
| mock-x402-facilitator  | `nginx:1.27.3-alpine`              | Stand-in for the LF facilitator. 200s on `/supported`, `/verify`, `/settle`. |
| mock-origin            | `nginx:1.27.3-alpine`              | Article server. Returns one canned HTML body on `/article`.                  |

All three run on a single bridge network (`x402sb`); only `sbproxy`
publishes a host port (`8080`).

## How the rail composes

The interesting block is `policies[].rails.x402` in `sb.yml`:

```yaml
rails:
  x402:
    chain: base
    facilitator: http://mock-x402-facilitator:80
    asset: USDC
    pay_to: "0x0000000000000000000000000000000000000000"
    version: "2"
quote_token:
  key_id: x402-base-sepolia-2026
  seed_hex: "1111..."
  issuer: "https://blog.test.sbproxy.dev"
  default_ttl_seconds: 300
```

`rails.x402` is the operator-side configuration: chain, facilitator
URL, the stablecoin asset to settle in, and the merchant address that
receives the settled payment. `quote_token` is the proxy's signing
material; the proxy mints one quote-token JWS per 402 challenge and
publishes the verifying half at the admin endpoint
`/.well-known/sbproxy/quote-keys.json` (see
`examples/33-quote-token-replay-jwks/` for the JWKS demo).

Per A3.1 (`docs/adr-multi-rail-402-challenge.md`) the proxy emits the
multi-rail 402 body whenever the agent opts in via either the
`Accept-Payment: x402` header or the `Accept:
application/x402+json` MIME type. Legacy crawlers that send neither
get the Wave 1 single-rail `Crawler-Payment` body so they keep
working unchanged.

## How to run (mock facilitator)

```bash
cd examples/30-rail-x402-base-sepolia
docker compose up -d --wait
```

Tear down:

```bash
docker compose down -v
```

The `Makefile` wraps the same calls (`make up`, `make down`, `make
logs`, `make test`).

## What to expect

### 1. Browser, no Accept-Payment

A browser UA never matches the crawler list, so the policy never
charges and the proxy forwards the request through to the mock
origin.

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
     -H 'Host: blog.test.sbproxy.dev' \
     http://127.0.0.1:8080/article
# => 200
```

### 2. AI crawler, Accept-Payment: x402

The agent opts in via `Accept-Payment: x402`. The policy emits a 402
with `Content-Type: application/sbproxy-multi-rail+json` and one
`x402` rail entry in the body. The body carries a per-request
quote-token JWS the agent verifies against the JWKS document before
spending anything.

```bash
curl -i \
     -H 'Host: blog.test.sbproxy.dev' \
     -H 'User-Agent: GPTBot/1.0' \
     -H 'Accept-Payment: x402' \
     http://127.0.0.1:8080/article
# HTTP/1.1 402 Payment Required
# Content-Type: application/sbproxy-multi-rail+json
# {
#   "rails": [
#     {
#       "kind": "x402",
#       "version": "2",
#       "chain": "base",
#       "facilitator": "http://mock-x402-facilitator:80",
#       "asset": "USDC",
#       "amount_micros": 1000,
#       "currency": "USD",
#       "pay_to": "0x0000...",
#       "expires_at": "2026-05-02T...",
#       "quote_token": "eyJhbGc..."
#     }
#   ],
#   "agent_choice_method": "header_negotiation",
#   "policy": "first_match_wins"
# }
```

### 3. AI crawler, Accept: application/x402+json

The MIME-type opt-in is equivalent. Useful for SDKs that stream
content negotiation through `Accept` rather than `Accept-Payment`.

```bash
curl -i \
     -H 'Host: blog.test.sbproxy.dev' \
     -H 'User-Agent: GPTBot/1.0' \
     -H 'Accept: application/x402+json' \
     http://127.0.0.1:8080/article
# => 402 with the same multi-rail body, filtered to just the x402 entry.
```

### 4. AI crawler, no opt-in

A crawler UA without either signal still gets a 402, but the body is
the Wave 1 single-rail format with the `Crawler-Payment` header.
This keeps legacy crawlers working without breaking the new path.

```bash
curl -i \
     -H 'Host: blog.test.sbproxy.dev' \
     -H 'User-Agent: GPTBot/1.0' \
     http://127.0.0.1:8080/article
# HTTP/1.1 402 Payment Required
# Crawler-Payment: realm="ai-crawl" currency="USD" price="0.001000"
```

## Verifying the EIP-3009 flow

The mock facilitator does not run real signature verification (that
is what makes the example hermetic), but the proxy still emits a
quote-token JWS the agent must verify before signing an EIP-3009
authorization. The end-to-end loop the README walks through is:

1. Agent issues a request; receives a 402 with one x402 rail entry.
2. Agent fetches `/.well-known/sbproxy/quote-keys.json` from the
   admin port; verifies the JWS in the rail entry against the
   matching kid.
3. Agent signs an EIP-3009 `transferWithAuthorization` for the
   `amount_micros` value listed in the rail entry, paying out to the
   `pay_to` address on the `chain` listed.
4. Agent posts the signed authorization to the `facilitator` URL.
   The mock returns a synthetic `txhash`; the LF facilitator returns
   the real one.
5. Agent retries the original request with the `Crawler-Payment`
   header set to the redeemed quote token. The proxy validates with
   the in-memory ledger (or the configured HTTP ledger) and
   forwards.

For a full walkthrough against the live Base Sepolia facilitator,
see `docs/billing-rails.md` (operator-facing billing docs).

## Simulating reorgs

The mock facilitator honours a `reorg=depth=N` query parameter on
`/settle`:

```bash
curl -s -X POST 'http://localhost:8080/settle?reorg=depth=3'
# {"settled":true,"txhash":"0xMOCK...","reorg_depth":3}
```

The proxy itself does not re-evaluate redemptions on reorg today
(Wave 3 ships the rail emission; the agent SDK is responsible for
re-issuing if the facilitator's response indicates a reorg). The
field is here so the README walkthrough has a way to demonstrate the
"facilitator says reorg happened" branch without a real testnet.

## Swapping in the Base Sepolia facilitator

The companion file `sb-testnet.yml` keeps everything except the
facilitator URL, the merchant `pay_to`, and the quote-token signing
key as-is. Three operator steps to flip:

```bash
export MERCHANT_ADDRESS=0xYOUR_BASE_SEPOLIA_ADDRESS
export SBPROXY_QUOTE_TOKEN_SEED_HEX=$(openssl rand -hex 32)
docker compose --env-file .env.testnet up -d --wait
```

Then mount `sb-testnet.yml` at `/etc/sbproxy/sb.yml` (override
`docker-compose.yml`'s `volumes:` block via a compose override file).
The proxy talks to
`https://facilitator.base-sepolia.x402.org` for verification and
settlement; the mock container is unused on the testnet path.

You will need:

- A funded Base Sepolia wallet (the merchant address). USDC test
  faucet: see the LF documentation linked from
  `docs/billing-rails.md`.
- An Ed25519 seed for the quote-token signer. `openssl rand -hex 32`
  produces a usable seed in 64-char hex form.
- An agent with Base Sepolia signing capability. The reference
  client is the LF agent SDK; any wallet that speaks EIP-3009 over
  the LF facilitator API works.

## Cargo features

The example assumes a default-features `sbproxy` build (which
includes `tiered-pricing`, `agent-class`, and `http-ledger`). The
multi-rail emission path is unconditional in the `sbproxy-modules`
crate; no operator-set cargo feature is needed to enable x402
itself. The `Dockerfile.cloudbuild` image used by `docker-compose.yml`
ships the default feature set.

## Related docs

- `docs/billing-rails.md` - operator-facing billing rails reference.
- `docs/adr-multi-rail-402-challenge.md` (A3.1) - wire shape of the
  402 body.
- `docs/adr-quote-token-jws.md` (A3.2) - quote-token JWS shape and
  JWKS publication.
- `docs/adr-billing-rail-x402-mpp-mapping.md` - rail / asset / chain
  mapping used by the multi-rail emission path.
- `examples/31-rail-mpp-stripe-test/` - MPP rail counterpart.
- `examples/32-multi-rail-accept-payment/` - both rails wired
  together with q-value negotiation.
- `examples/33-quote-token-replay-jwks/` - JWKS endpoint and
  single-use quote token enforcement.
