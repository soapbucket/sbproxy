# 32 - multi-rail-accept-payment
*Last modified: 2026-05-02*

Both rails (x402 + MPP) configured at once. The example demonstrates
the `Accept-Payment` header negotiation: q-value preference,
first-match-wins per A3.1, the multi-rail body shape, and the 406
fallback when no rail matches.

The stack reuses the mock x402 facilitator from `examples/30-...` and
the wiremock Stripe stand-in from `examples/31-...` so the demo runs
end-to-end without external dependencies.

## How it composes

| Service                | Image                              | Role                                                                |
|------------------------|------------------------------------|---------------------------------------------------------------------|
| sbproxy                | built from `Dockerfile.cloudbuild` | Reverse proxy on `:8080` enforcing `ai_crawl_control` per `sb.yml`. |
| mock-x402-facilitator  | `nginx:1.27.3-alpine`              | Reused from example 30; mounts the same nginx config.               |
| mock-origin            | `nginx:1.27.3-alpine`              | Article server. Returns one canned HTML body on `/article`.         |
| wiremock               | `wiremock/wiremock:3.10.1`         | Reused from example 31; serves Stripe-shaped JSON.                  |

All four containers run on a single bridge network (`multirailsb`);
only `sbproxy` publishes a host port (`8080`).

## How to run

```bash
cd examples/32-multi-rail-accept-payment
docker compose up -d --wait
```

Tear down:

```bash
docker compose down -v
```

## How the negotiation works

Per A3.1 (`docs/adr-multi-rail-402-challenge.md`) the proxy resolves
the agent's preferred rail order from two signals:

1. The `Accept-Payment` request header. Comma-separated list of rail
   tokens, optional q-value parameters (`x402;q=1, mpp;q=0.5`).
2. The `Accept` request header, when it carries one of
   `application/sbproxy-multi-rail+json`, `application/x402+json`, or
   `application/mpp+json`.

The proxy:

1. Parses the agent's preference set.
2. Filters it through the operator's configured rails (per-policy
   `rails:` block, optionally narrowed by per-tier `rails:`
   override).
3. Sorts the surviving rails by the agent's q-value (descending),
   breaking ties on the operator's declared rail order.
4. Emits one rail entry per surviving rail, each carrying its own
   quote-token JWS (separate nonce per rail per A3.2).
5. Returns 402 with the multi-rail body or, when no rail survives
   the filter, returns 406 with a body listing the rails the
   operator does support.

The "first match wins" `policy` field in the multi-rail body says:
the agent should pick the first entry it can settle, in the order
the body lists. The proxy does not ask the agent to nominate a rail;
it tells the agent which rail entries are available and in what
preference order.

## What to expect

### 1. q-value preference: x402 first

Agent declares `x402;q=1, mpp;q=0.5`. The proxy lists `x402` before
`mpp` in the `rails[]` array.

```bash
curl -i \
     -H 'Host: blog.test.sbproxy.dev' \
     -H 'User-Agent: GPTBot/1.0' \
     -H 'Accept-Payment: x402;q=1, mpp;q=0.5' \
     http://127.0.0.1:8080/article
# HTTP/1.1 402 Payment Required
# Content-Type: application/sbproxy-multi-rail+json
# {
#   "rails": [
#     {"kind":"x402", ...},
#     {"kind":"mpp",  ...}
#   ],
#   "agent_choice_method": "header_negotiation",
#   "policy": "first_match_wins"
# }
```

### 2. q-value preference: mpp first

Agent declares `mpp;q=1, x402;q=0.5`. The proxy lists `mpp` before
`x402`.

```bash
curl -i \
     -H 'Host: blog.test.sbproxy.dev' \
     -H 'User-Agent: ClaudeBot/1.0' \
     -H 'Accept-Payment: mpp;q=1, x402;q=0.5' \
     http://127.0.0.1:8080/article
# HTTP/1.1 402 Payment Required
# Content-Type: application/sbproxy-multi-rail+json
# {
#   "rails": [
#     {"kind":"mpp",  ...},
#     {"kind":"x402", ...}
#   ],
#   ...
# }
```

### 3. Unknown rail: 406 fallback

Agent declares only `foo`, which is not a valid rail token. The
proxy returns 406 with a body listing the rails it does support so
the agent can recover.

```bash
curl -i \
     -H 'Host: blog.test.sbproxy.dev' \
     -H 'User-Agent: PerplexityBot/1.0' \
     -H 'Accept-Payment: foo;q=1' \
     http://127.0.0.1:8080/article
# HTTP/1.1 406 Not Acceptable
# Content-Type: application/json
# {
#   "error": "no_acceptable_rail",
#   "supported_rails": ["x402","mpp"],
#   "target": "blog.test.sbproxy.dev/article",
#   "message": "Agent's Accept-Payment list does not overlap with this route's configured rails."
# }
```

### 4. Equal q-values, operator order breaks the tie

When the agent declares the same q-value for both rails, the
operator's declared order in `sb.yml` (here: x402 first, mpp
second) breaks the tie.

```bash
curl -i \
     -H 'Host: blog.test.sbproxy.dev' \
     -H 'User-Agent: GPTBot/1.0' \
     -H 'Accept-Payment: x402, mpp' \
     http://127.0.0.1:8080/article
# Both rails have q=1 (default). Operator order says x402 first.
```

### 5. MIME-type opt-in

Agents that prefer to negotiate via `Accept` (not `Accept-Payment`)
get the same multi-rail body when their `Accept` includes one of
the multi-rail MIME types:

```bash
curl -i \
     -H 'Host: blog.test.sbproxy.dev' \
     -H 'User-Agent: GPTBot/1.0' \
     -H 'Accept: application/sbproxy-multi-rail+json' \
     http://127.0.0.1:8080/article
# => 402 with both rails. The catch-all MIME accepts every rail.
```

`application/x402+json` and `application/mpp+json` work the same way
but filter the body to the named rail.

### 6. No opt-in: legacy single-rail

Crawlers that send neither `Accept-Payment` nor a multi-rail
`Accept` MIME type still see a 402, but the body is the Wave 1
single-rail format with the `Crawler-Payment` header. This keeps
legacy crawlers working without breaking the new path.

```bash
curl -i \
     -H 'Host: blog.test.sbproxy.dev' \
     -H 'User-Agent: GPTBot/1.0' \
     http://127.0.0.1:8080/article
# HTTP/1.1 402 Payment Required
# Crawler-Payment: realm="ai-crawl" currency="USD" price="0.001000"
```

## Per-tier rail override

Tiers can narrow the rails on a per-route basis. For example, an
operator might want all routes to advertise both rails by default
but force the high-value `/premium/*` route through MPP only:

```yaml
tiers:
  - route_pattern: /premium/*
    price:
      amount_micros: 50000
      currency: USD
    content_shape: html
    rails: ["mpp"]   # override; ignore policy-level x402 here.
```

The example does not configure a per-tier override. See the unit
test `multi_rail_per_tier_filter_overrides_policy_rails` in
`crates/sbproxy-modules/src/policy/ai_crawl.rs` for the full
behaviour.

## Cargo features

The example assumes a default-features `sbproxy` build. The
multi-rail emission path is unconditional in the `sbproxy-modules`
crate; no operator-set cargo feature is needed.

## Related docs

- `docs/billing-rails.md` - operator-facing billing rails reference.
- `docs/adr-multi-rail-402-challenge.md` (A3.1) - wire shape of the
  402 / 406 bodies and the negotiation rules.
- `docs/adr-quote-token-jws.md` (A3.2) - quote-token JWS shape.
- `examples/30-rail-x402-base-sepolia/` - x402 rail in isolation.
- `examples/31-rail-mpp-stripe-test/` - MPP rail in isolation.
- `examples/33-quote-token-replay-jwks/` - JWKS endpoint and
  single-use quote token enforcement.
