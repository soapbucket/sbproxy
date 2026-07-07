# Your own OpenRouter: one governed endpoint for every provider

*Last modified: 2026-07-06*

![Minting a virtual key, calling OpenAI and Anthropic through one endpoint, reading the spend ledger, and tripping a budget cap](../../docs/assets/use-case-own-openrouter.gif)

One `ai_proxy` origin in front of OpenAI and Anthropic with dynamic key management, a deliberately tiny per-key daily budget, and a hash-chained usage ledger. You mint a virtual key per team through the admin API, teams call one OpenAI-compatible endpoint where the `model` field picks the vendor, and every completed call lands in the ledger with cost and key attribution. The first request past the budget line is refused with `402`.

The full walkthrough is [docs/use-case-own-openrouter.md](../../docs/use-case-own-openrouter.md).

## Run

```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
sbproxy sb.yml

# or, from this directory, in Docker:
docker compose up
```

## Try it

```bash
# Mint a team key; the plaintext token is returned exactly once.
TOKEN=$(curl -s -u admin:admin -X POST http://127.0.0.1:9090/admin/keys \
  -d '{"name":"team-payments"}' | jq -r .token)

# Same endpoint, two vendors: the model field picks the provider.
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"In one sentence, what is a reverse proxy?"}]}' \
  | jq -r '.model, .choices[0].message.content'

curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"model":"claude-haiku-4-5","messages":[{"role":"user","content":"In about 120 words, why give each team its own gateway key?"}]}' \
  | jq '{model, usage}'

# Both calls are in the ledger, attributed to the key by name.
tail -n 2 /tmp/sbproxy-own-openrouter-ledger.jsonl \
  | jq -c '{provider: .event.provider, tokens: .event.total_tokens, cost_usd: .event.cost_usd, key: .event.key_id}'

# The key's 90-token daily budget is now spent; the next call is refused.
curl -is http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"one more?"}]}' \
  | sed -n '1p;$p'
```

Expect `.model` to read `gpt-4o-mini` on the first completion and `claude-haiku-4-5` on the second, two ledger lines naming `openai` and `anthropic` with the same `key`, and a final `HTTP/1.1 402 Payment Required` whose body carries `"type":"budget_exceeded"` and `"scope":"api_key"`. In Docker, run the ledger commands inside the container (`docker compose exec sbproxy sbproxy ai ledger verify /tmp/sbproxy-own-openrouter-ledger.jsonl`).
