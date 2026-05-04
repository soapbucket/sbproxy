# AI gateway: hierarchical budget with downgrade

*Last modified: 2026-04-27*

Two stacked budget limits with `on_exceed: downgrade`. The workspace-wide cap allows up to USD 500 of spend per month and downgrades to `claude-3-5-haiku-latest` when exceeded. The per-API-key cap allows up to 1,000,000 tokens per day and downgrades to `anthropic/claude-3-haiku` (served by OpenRouter) when exceeded. Whichever limit fires first applies its `downgrade_to` model rewrite to subsequent requests until the period rolls over. Requests below both caps run on `claude-3-5-sonnet-latest` (the configured default). Each downgrade fires the `sbproxy_ai_budget_utilization_ratio` gauge so dashboards can show how close each scope is to its cap.

## Run

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export OPENROUTER_API_KEY=sk-or-...
make run CONFIG=examples/13-ai-budget/sb.yml
```

Both API keys are required so the downgrade path can land on a real provider.

## Try it

A normal request runs on Sonnet:

```bash
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{
      "model": "claude-3-5-sonnet-latest",
      "messages": [{"role": "user", "content": "Summarise the budget config."}]
    }' \
  | jq -r '.model'
claude-3-5-sonnet-latest
```

After workspace monthly spend crosses USD 500, the same request body is rewritten to Haiku before reaching the upstream:

```bash
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{
      "model": "claude-3-5-sonnet-latest",
      "messages": [{"role": "user", "content": "Summarise the budget config."}]
    }' \
  | jq -r '.model'
claude-3-5-haiku-latest
```

If the API-key daily token cap fires first, the rewrite lands on the OpenRouter Haiku route:

```bash
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Authorization: Bearer some-virtual-key' \
    -H 'Content-Type: application/json' \
    -d '{"model":"claude-3-5-sonnet-latest","messages":[{"role":"user","content":"hi"}]}' \
  | jq -r '.model'
anthropic/claude-3-haiku
```

## What this exercises

- `ai_proxy` with stacked `budget.limits` - workspace and api_key scopes layered
- `period: monthly` and `period: daily` - independent rolling windows per limit
- `max_cost_usd` and `max_tokens` - cost-based and token-based caps
- `on_exceed: downgrade` plus `downgrade_to` - silent model rewrite instead of rejecting the request
- `sbproxy_ai_budget_utilization_ratio` gauge - emitted per scope for observability

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md) - AI gateway overview
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
- [docs/metrics-stability.md](../../docs/metrics-stability.md) - emitted AI metrics
