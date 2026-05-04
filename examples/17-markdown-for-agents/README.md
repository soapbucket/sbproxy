# 17 - Markdown for agents
*Last modified: 2026-05-02*

Demonstrates the Wave 4 content negotiation surface end-to-end. A
single origin serves an article. Browsers asking for HTML get the
canned HTML body. AI crawlers asking for Markdown
(`Accept: text/markdown`) get the same article projected into Markdown,
plus two response headers that surface the projection metadata:

- `x-markdown-tokens` - rough token estimate (bytes * `token_bytes_ratio`).
- `Content-Signal: ai-train` - the operator's licensing assertion.

Pricing splits on the negotiated content shape:

| `Accept`           | Tier            | Price per request |
|--------------------|-----------------|-------------------|
| `text/html`        | html-default    | $0.001            |
| `text/markdown`    | markdown        | $0.005            |

The Markdown tier is more expensive because the projected document is
more compact and more useful for training than the raw HTML.

The `static` action serves a canned body in-process so the bundle has
no external dependencies. Swap for `type: proxy` + `url:` to front a
real upstream.

## How it composes

| Service     | Image                              | Role                                                                      |
|-------------|------------------------------------|---------------------------------------------------------------------------|
| sbproxy     | built from `Dockerfile.cloudbuild` | Reverse proxy on `:8080`. Resolves `Accept`, prices by tier, projects to Markdown. |

The proxy is the only container; there is no upstream service to
healthcheck. Compare with `examples/24-ai-crawl-tiered/` which fronts
a separate `mock-origin` to demonstrate the proxy mode.

## How to run

```bash
cd examples/17-markdown-for-agents
docker compose up -d --wait
```

Tear down:

```bash
docker compose down -v
```

The `Makefile` wraps the same calls (`make up`, `make down`,
`make logs`, `make test`).

## What to expect

The four scenarios below cover the matrix. The `Makefile`'s `test`
target runs them in sequence and prints the HTTP code per leg.

### 1. Browser, asking for HTML

A real browser User-Agent skips the policy entirely and gets the HTML
body unchanged.

```bash
curl -s -H 'Host: news.localhost' \
     -H 'Accept: text/html' \
     http://127.0.0.1:8080/article
# => 200, full <!doctype html> body
```

### 2. AI crawler asking for Markdown, no token

The Markdown tier's $0.005 price kicks in. The policy returns 402 with
the matched tier price in the challenge body.

```bash
curl -s -i -H 'Host: news.localhost' \
     -H 'User-Agent: GPTBot/1.0' \
     -H 'Accept: text/markdown' \
     http://127.0.0.1:8080/article
# HTTP/1.1 402 Payment Required
# crawler-payment: realm=...; price=0.005000 USD
# {"price":"0.005000","currency":"USD","header":"crawler-payment",...}
```

### 3. AI crawler asking for Markdown, with token

The crawler retries with one of the seeded tokens. The proxy redeems
the token, runs the `html_to_markdown` projection, and returns
Markdown plus the projection headers.

```bash
curl -s -i -H 'Host: news.localhost' \
     -H 'User-Agent: GPTBot/1.0' \
     -H 'Accept: text/markdown' \
     -H 'crawler-payment: token-md-001' \
     http://127.0.0.1:8080/article
# HTTP/1.1 200 OK
# Content-Type: text/markdown
# x-markdown-tokens: 27
# Content-Signal: ai-train
#
# # The Article
#
# The first paragraph carries the lede...
```

### 4. AI crawler asking for HTML, with token

The HTML default tier kicks in at $0.001. With a valid token the
policy returns the unchanged HTML body, no Markdown projection.

```bash
curl -s -i -H 'Host: news.localhost' \
     -H 'User-Agent: GPTBot/1.0' \
     -H 'Accept: text/html' \
     -H 'crawler-payment: token-html-001' \
     http://127.0.0.1:8080/article
# HTTP/1.1 200 OK
# Content-Type: text/html
# Content-Signal: ai-train
```

## How the tiers map

| Route pattern | Shape    | Price per request | Notes                                  |
|---------------|----------|-------------------|----------------------------------------|
| `/article`    | markdown | $0.005            | `html_to_markdown` + citation footer.  |
| `/article`    | html     | $0.001            | HTML pass-through.                     |

Tier match order is sensitive: the first tier whose `route_pattern`
and `content_shape` match the request wins. The Markdown tier is
listed first so an agent that asks for Markdown lands on the higher
price even though the path is the same.

## Headers an agent should expect

The proxy stamps these on every 200 response from this origin:

| Header                | Value                                    | Source                             |
|-----------------------|------------------------------------------|------------------------------------|
| `Content-Type`        | `text/markdown` or `text/html`           | Negotiated from `Accept`.          |
| `Content-Signal`      | `ai-train`                               | Per-origin `content_signal:`.      |
| `x-markdown-tokens`   | integer (Markdown only)                  | Markdown projection metadata.      |

## Token estimate calibration

The `x-markdown-tokens` value is `bytes * token_bytes_ratio`. The
default ratio is 0.25 (~four bytes per token, English prose). Tune
per-origin via the `token_bytes_ratio:` field if your content is
denser (technical docs, source code) or sparser (CJK languages).

## Related docs

- `docs/adr-content-negotiation-and-pricing.md` - G4.1 content-negotiate ADR.
- `docs/adr-json-envelope-schema.md` - A4.2 JSON envelope (Markdown carriage in API responses).
- `docs/ai-crawl-control.md` - feature reference for the `ai_crawl_control` policy.
- `examples/18-rsl-licensing/` - companion bundle for the RSL `/licenses.xml` projection.
- `examples/19-robots-llms-txt/` - companion bundle for `robots.txt` + `llms.txt`.
- `examples/24-ai-crawl-tiered/` - the canonical three-tier tiered-pricing example.
