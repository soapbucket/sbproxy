# AI crawl control with Pay Per Crawl

*Last modified: 2026-04-27*

The `ai_crawl_control` policy returns HTTP 402 Payment Required to known AI crawler User-Agents that arrive without a `Crawler-Payment` token. The 402 response body explains the price and the header to retry with; the response also stamps a `Crawler-Payment realm=...` challenge. The OSS ledger is in-memory: every token in `valid_tokens` redeems exactly once, after which the policy charges again. Enterprise builds swap in an HTTP-callable ledger that talks to a payments backend. Normal browser User-Agents pass through without paying.

## Run

```bash
sb run -c sb.yml
```

No setup required. Example seeds three single-use tokens and matches the standard AI crawler list (GPTBot, ChatGPT-User, ClaudeBot, anthropic-ai, Google-Extended, PerplexityBot, CCBot).

## Try it

```bash
# Known crawler UA without payment - 402 challenge.
curl -i -H 'Host: blog.local' \
     -H 'User-Agent: GPTBot/1.0' \
     http://127.0.0.1:8080/article
# HTTP/1.1 402 Payment Required
# Crawler-Payment: realm="..."
# {"price":0.001,"currency":"USD","header":"crawler-payment"}
```

```bash
# Redeem a valid token - 200, the request reaches the upstream. The
# token is single-use; the next call without a fresh token gets 402 again.
curl -s -H 'Host: blog.local' \
     -H 'User-Agent: GPTBot/1.0' \
     -H 'crawler-payment: token-aaa-001' \
     http://127.0.0.1:8080/article
```

```bash
# Same crawler, same path, second call after redeeming - 402 again.
curl -i -H 'Host: blog.local' \
     -H 'User-Agent: GPTBot/1.0' \
     -H 'crawler-payment: token-aaa-001' \
     http://127.0.0.1:8080/article
# HTTP/1.1 402 Payment Required (token already redeemed)
```

```bash
# Normal browser UA - passes through without paying.
curl -s -o /dev/null -w "%{http_code}\n" \
     -H 'Host: blog.local' http://127.0.0.1:8080/article
# 200
```

## What this exercises

- `ai_crawl_control` policy with `price`, `currency`, and configurable challenge `header`
- `crawler_user_agents` - case-insensitive User-Agent substrings that mark a crawler
- `valid_tokens` - in-memory single-use ledger for OSS deployments
- HTTP 402 challenge response with `Crawler-Payment realm=...` header and JSON body

## See also

- [docs/ai-crawl-control.md](../../docs/ai-crawl-control.md)
- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
