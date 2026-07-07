# Meter and monetize AI crawlers

*Last modified: 2026-07-06*

![Verify, meter, and charge AI crawlers with Web Bot Auth and HTTP 402](../../docs/assets/use-case-meter-crawlers.gif)

Two gates on one origin. The `bot_auth` provider verifies RFC 9421 HTTP Message Signatures (Web Bot Auth) and turns away unsigned crawlers with 401. The `ai_crawl_control` policy then charges verified crawlers per request: no `crawler-payment` token gets a 402 challenge naming the price, and each seeded token redeems exactly once against the OSS in-memory ledger. The full walkthrough, including the signing helper invocation, is the story doc at [docs/use-case-meter-crawlers.md](../../docs/use-case-meter-crawlers.md).

## Run

```bash
# Binary:
sbproxy serve -f sb.yml

# Or Docker:
docker compose up
```

No API keys needed; the upstream is the public echo service at `test.sbproxy.dev`.

## What to expect

```bash
# Unsigned crawler UA: 401 before the paywall is consulted.
curl -s -o /dev/null -w '%{http_code}\n' \
     -H 'Host: blog.local' -H 'User-Agent: GPTBot/1.0' \
     http://127.0.0.1:8080/anything/article
# => 401
```

A request signed with the demo key from the story doc (the RFC 8032 test vector matching the `public_key` in `sb.yml`) returns 402 with the price challenge, then 200 with `crawler-payment: demo-tok-001`, then 402 again on token replay. See the story doc for the `sign-request.sh` invocation that produces the signature headers.

## See also

- [docs/use-case-meter-crawlers.md](../../docs/use-case-meter-crawlers.md) - the walkthrough this example backs
- [docs/web-bot-auth.md](../../docs/web-bot-auth.md) - the `bot_auth` verifier
- [docs/ai-crawl-control.md](../../docs/ai-crawl-control.md) - tiers, agent classes, HTTPS ledger
- [docs/402-challenge.md](../../docs/402-challenge.md) - the 402 wire contract
