# agent_budget: per-agent semantic rate limit

*Last modified: 2026-07-09*

![agent_budget: per-agent semantic rate limit](../../docs/assets/agent-budget.gif)

Demonstrates the `agent_budget` policy. Per-agent rate-limit primitive keyed on the resolved `agent_id` (from the agent-class resolver). One bucket per named agent collapses "every request from the Cursor instance" or "every request from the same Assistant" into a single budget operators can actually size, while still letting an attacker get blocked cleanly because they cannot mint a fresh `agent_id` per request.

Standard per-IP or per-key limits assume humans pause between requests; LLM loops do not. Per-agent limits are what catch the runaway loop without breaking legitimate background traffic.

## Run

```bash
make run CONFIG=examples/agent-budget/sb.yml
```

## Try it

```bash
# Same User-Agent (Cursor) → same agent_id → one shared bucket.
# First 60 in a 60s window return 200; the next 10 return 429.
for i in $(seq 1 70); do
  curl -s -o /dev/null -w '%{http_code}\n' \
    -H 'Host: ai.local' \
    -H 'User-Agent: Cursor/0.42.0' \
    http://127.0.0.1:8080/echo
done
```

Switch the User-Agent string to one the resolver maps to a different `agent_id` and observe a separate bucket. Set `on_anonymous: shared` to put all anonymous traffic in one fallback bucket; set `on_exceed: downgrade` to have the AI gateway pick a cheaper provider instead of returning 429.

See [docs/agent-budget.md](../../docs/agent-budget.md) for the full schema.
