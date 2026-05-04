# AI gateway: per-team virtual keys

*Last modified: 2026-04-27*

Two virtual keys, two teams, two budgets. The frontend team's key is allowlisted to `claude-3-5-haiku-latest` only, capped at 30 RPM and 60,000 TPM, with a USD 10 / 500,000-token budget. The data team's key adds `claude-3-5-sonnet-latest`, raises the limits to 120 RPM and 400,000 TPM, and gets a USD 250 / 10,000,000-token budget. Tags propagate to the `sbproxy_ai_key_*` metric series for per-team attribution. The proxy validates the virtual key locally (in `Authorization: Bearer ...`) before any upstream call, so unauthorized clients never burn the upstream Anthropic key.

## Run

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export TEAM_FRONTEND_KEY=vk-frontend-...
export TEAM_DATA_KEY=vk-data-...
make run CONFIG=examples/14-ai-virtual-keys/sb.yml
```

All three env vars are required.

## Try it

Frontend team, allowed model:

```bash
$ curl -is http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H "Authorization: Bearer ${TEAM_FRONTEND_KEY}" \
    -H 'Content-Type: application/json' \
    -d '{
      "model": "claude-3-5-haiku-latest",
      "messages": [{"role": "user", "content": "Hello from frontend."}]
    }' | head -n 1
HTTP/1.1 200 OK
```

Frontend team, blocked model:

```bash
$ curl -is http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H "Authorization: Bearer ${TEAM_FRONTEND_KEY}" \
    -H 'Content-Type: application/json' \
    -d '{"model":"claude-3-5-sonnet-latest","messages":[{"role":"user","content":"Try Sonnet."}]}' \
    | head -n 5
HTTP/1.1 403 Forbidden
content-type: application/json

{"error":{"message":"model claude-3-5-sonnet-latest not allowed for this key","type":"virtual_key_violation"}}
```

Data team, allowed Sonnet:

```bash
$ curl -is http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H "Authorization: Bearer ${TEAM_DATA_KEY}" \
    -H 'Content-Type: application/json' \
    -d '{"model":"claude-3-5-sonnet-latest","messages":[{"role":"user","content":"Hello from data team."}]}' \
    | head -n 1
HTTP/1.1 200 OK
```

Unknown key, rejected before any upstream call:

```bash
$ curl -is http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Authorization: Bearer not-a-real-key' \
    -H 'Content-Type: application/json' \
    -d '{"model":"claude-3-5-haiku-latest","messages":[{"role":"user","content":"hi"}]}' \
    | head -n 1
HTTP/1.1 401 Unauthorized
```

## What this exercises

- `ai_proxy.virtual_keys` - per-key validation independent of upstream provider keys
- `allowed_providers` and `allowed_models` - per-key scoping
- `max_requests_per_minute` and `max_tokens_per_minute` - per-key sliding-window caps
- Per-key `budget.max_tokens` and `budget.max_cost_usd` - per-key spend ceilings
- `tags` - propagate to `sbproxy_ai_key_*` metrics for team attribution

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md) - AI gateway overview
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
- [docs/metrics-stability.md](../../docs/metrics-stability.md) - per-key metric labels
