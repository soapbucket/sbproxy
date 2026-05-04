# 24 - AI Crawl Control with tiered pricing
*Last modified: 2026-04-30*

Demonstrates a three-tier paywall in front of an article-publishing
origin. Known AI crawlers see a free preview window for short URLs, a
charged Markdown feed for `/feed/articles/*`, and a charged HTML
article for `/article`. Browsers pass through unaffected.

The bundle bootstraps a self-contained stack (proxy + mock ledger +
mock origin) so an evaluator can hit the paywall in a minute without
needing a real ledger backend.

## How it composes

| Service       | Image                              | Role                                                              |
|---------------|------------------------------------|-------------------------------------------------------------------|
| sbproxy       | built from `Dockerfile.cloudbuild` | Reverse proxy on `:8080` enforcing `ai_crawl_control` per `sb.yml`. |
| mock-origin   | `nginx:1.27.3-alpine`              | Article server. Returns three canned shapes (HTML preview, Markdown feed, full HTML). |
| mock-ledger   | `nginx:1.27.3-alpine`              | Stand-in for the HTTP ledger. Always returns 200 on `POST /v1/ledger/redeem`. |

All three run on a single bridge network (`tieredsb`); only `sbproxy`
publishes a host port (`8080`).

## How to run

```bash
cd examples/24-ai-crawl-tiered
docker compose up -d --wait
```

Tear down:

```bash
docker compose down -v
```

The `Makefile` wraps the same calls (`make up`, `make down`, `make
logs`, `make test`).

## What to expect

The four scenarios below cover the tier matrix. The `Makefile`'s
`test` target runs them in sequence and prints the HTTP code per leg.

### 1. Browser, no token

A real browser User-Agent (`curl` defaults to `curl/x.y.z`, which is
not in the crawler list) skips the policy entirely. Returns 200.

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
     -H 'Host: blog.localhost' \
     http://127.0.0.1:8080/article
# => 200
```

### 2. AI crawler on the free-preview tier

`/preview/article` matches the `/preview/*` route pattern. Tier 1's
price is zero, so the request flows through and returns the
preview-shaped origin response.

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
     -H 'Host: blog.localhost' \
     -H 'User-Agent: GPTBot/1.0' \
     http://127.0.0.1:8080/preview/article
# => 200
```

### 3. AI crawler on the HTML default tier (no token)

`/article` matches the `/article*` tier. The crawler did not present
a `crawler-payment` header, so the policy returns 402 with the
matched tier price (`0.001 USD`) in the challenge body.

```bash
curl -s -i \
     -H 'Host: blog.localhost' \
     -H 'User-Agent: GPTBot/1.0' \
     http://127.0.0.1:8080/article
# HTTP/1.1 402 Payment Required
# crawler-payment: realm=...; price=0.001000 USD
# {"price": "0.001000", "currency": "USD", "header": "crawler-payment", ...}
```

### 4. AI crawler on the Markdown feed tier (paid)

The crawler retries with one of the seeded tokens and the request
succeeds. Each token redeems exactly once - subsequent calls with the
same token return 402 again.

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
     -H 'Host: blog.localhost' \
     -H 'User-Agent: ClaudeBot/1.0' \
     -H 'crawler-payment: token-feed-001' \
     http://127.0.0.1:8080/feed/articles/2026
# => 200
```

## How the tiers map

| Route pattern    | Price                | Shape    | Notes                                |
|------------------|----------------------|----------|--------------------------------------|
| `/preview/*`     | `0 USD`              | (none)   | 4 KiB free-preview window.           |
| `/feed/*`        | `0.005 USD`          | markdown | Paywall position: `top_of_page`.     |
| `/article*`      | `0.001 USD`          | html     | Paywall position: `top_of_page`.     |

The tier list is order-sensitive. Each request hits the first tier
whose `route_pattern` matches; the bundled order puts the free
preview first so a `/preview/...` request never falls through to a
charged tier.

## Crawler classes

The `crawler_user_agents` list in `sb.yml` is the OSS substring matcher.
Every entry maps conceptually to an "agent class" the request gets
bucketed into for downstream metrics + audit. Today the policy
charges every matched UA at the same tier price; the agent class
labelling lands as the per-agent metrics surface (see
`docs/ai-crawl-control.md`).

## Mock ledger

The `mock-ledger` container is a static stub. It accepts any `POST
/v1/ledger/redeem` and returns the happy-path JSON used by the e2e
suite (`e2e/tests/http_ledger.rs::handle_redeem`). The OSS build
ships an in-memory ledger seeded from `valid_tokens` in `sb.yml`, so
the proxy in this bundle does not actually call the mock service. The
mock exists so:

- Operators can repoint the policy at the mock by enabling the
  `http-ledger` cargo feature and adding a `ledger:` block to the
  config. The wiring is documented in `docs/ai-crawl-control.md`.
- The synthetic-nightly probe (`bench-synthetic --rail=none`) has a
  stable target it can hit when the bundle is brought up locally
  against an `http-ledger`-feature build.

## Related docs

- `docs/ai-crawl-control.md` - feature reference for the `ai_crawl_control` policy.
- `docs/adr-http-ledger-protocol.md` - HTTP ledger wire shape (the mock honours its happy-path response).
- `examples/95-ai-crawl-control/` - simpler single-tier counterpart of this bundle.
