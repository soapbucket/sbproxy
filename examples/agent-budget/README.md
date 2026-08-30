# agent_budget: per-agent semantic rate limit

*Last modified: 2026-08-29*

![agent_budget: per-agent semantic rate limit](../../docs/assets/agent-budget.gif)

Demonstrates the `agent_budget` policy. Per-agent rate-limit primitive keyed on the resolved `agent_id` from the built-in agent-class catalog (User-Agent regex). That catalog includes coding agents such as Cursor, so `User-Agent: Cursor/0.42.0` resolves to a named id rather than the human sentinel. One bucket per named agent collapses "every request from the Cursor instance" or "every request from the same Assistant" into a single budget operators can actually size, while still letting an attacker get blocked cleanly because they cannot mint a fresh `agent_id` per request. This example does not enable `agent_detect`; the catalog match is enough.

Standard per-IP or per-key limits assume humans pause between requests; LLM loops do not. Per-agent limits are what catch the runaway loop without breaking legitimate background traffic.

## Run

```bash
make run CONFIG=examples/agent-budget/sb.yml
```

## Try it

```bash
# Same User-Agent (Cursor) → same agent_id → one shared bucket.
# The bucket starts full at 60 tokens (from requests_per_minute) and
# refills at 1 token/second, so the first ~60 requests return 200 and
# the rest return 429 once it's empty. The exact cutover isn't a clean
# 60/10 split: tokens keep trickling back in while the loop is still
# running, so a few extra requests past 60 can succeed depending on
# how long each round trip takes.
for i in $(seq 1 70); do
  curl -s -o /dev/null -w '%{http_code}\n' \
    -H 'Host: ai.local' \
    -H 'User-Agent: Cursor/0.42.0' \
    http://127.0.0.1:8080/echo
done
```

Switch the User-Agent string to one the resolver maps to a different `agent_id` and observe a separate bucket. Set `on_anonymous: shared` to put all anonymous traffic in one fallback bucket; set `on_exceed: downgrade` to have the AI gateway pick a cheaper provider instead of returning 429. Note that `burst` caps simultaneous in-flight requests per agent, not extra per-minute quota, so a serial loop like the one above never touches it.

See [docs/agent-budget.md](../../docs/agent-budget.md) for the full schema.
