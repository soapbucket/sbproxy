# Hedged / raced requests

![AI gateway: hedged / raced dispatch](../../docs/assets/ai-race-routing.gif)

The thinner sibling of [`ai-race`](../ai-race/): this one races two
same-vendor deployments (think two OpenAI regions/keys behind one logical
model) with no `resilience` block, to isolate the routing strategy itself.
`ai-race` races three different vendors (OpenAI, Anthropic, Groq) at once
and pairs the strategy with `outlier_detection` so a persistently slow
provider stops getting raced.

The `race` routing strategy fans a single request out to every eligible
provider concurrently and keeps the first 2xx response, cancelling the
losers. It trades extra upstream calls for lower tail latency.

See [`docs/ai-llm-aware-resilience.md`](../../docs/ai-llm-aware-resilience.md)
for the full reference.

## Run

```bash
export OPENAI_API_KEY=sk-...
make run CONFIG=examples/ai-race-routing/sb.yml
```

A single request fans out to both deployments; the first to return a 2xx
wins and the loser is dropped:

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}'
```

Every racer is charged, so reserve `race` for traffic where tail latency
matters more than the duplicate call. Streaming requests fall through to a
single dispatch.
