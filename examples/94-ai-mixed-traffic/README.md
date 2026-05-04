# Mixed AI and non-AI traffic

*Last modified: 2026-04-27*

Pure AI gateway libraries assume the host is "the AI gateway" and that everything that lands on it should hit a model. A real proxy can do more: serve health checks, model catalog overrides, and SDK probe endpoints alongside live AI traffic without spinning up a second host or sidecar. Path routing uses `forward_rules` evaluated in order. The default `action` at the origin level is the AI proxy; specific paths peel off into static, proxy, or other actions before they reach the AI handler. `/healthz` returns a cheap static 200 so probes never bill model tokens. `/v1/models` returns a curated catalog override so clients see only the models actually wired into this gateway. `/docs/*` reverse-proxies to a docs backend. Anything else falls through to the AI handler.

## Run

```bash
export OPENAI_API_KEY=sk-...
sb run -c sb.yml
```

## Try it

```bash
# Cheap health probe - no AI provider contacted, no tokens billed.
curl -s -H 'Host: ai.local' http://127.0.0.1:8080/healthz
# {"status":"ok"}
```

```bash
# Curated model list - peeled off before reaching the AI handler.
curl -s -H 'Host: ai.local' http://127.0.0.1:8080/v1/models | jq
# {"object":"list","data":[{"id":"gpt-4o-mini","object":"model","owned_by":"openai"}]}
```

```bash
# Docs passthrough.
curl -s -H 'Host: ai.local' http://127.0.0.1:8080/docs/index.html
```

```bash
# Falls through to the default ai_proxy action.
curl -s -H 'Host: ai.local' \
     -H 'Content-Type: application/json' \
     -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
     http://127.0.0.1:8080/v1/chat/completions \
     | jq .choices[0].message
```

## What this exercises

- `forward_rules` evaluated in order, peeling specific paths off the default origin action
- Inline child origins (`origin: { id, hostname, workspace_id, version, action }`) for static, proxy, and other actions
- Default `action: ai_proxy` at the origin level catches anything that does not match a forward rule
- Path matchers: `prefix: /healthz`, `exact: /v1/models`, `prefix: /docs/`

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md)
- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
