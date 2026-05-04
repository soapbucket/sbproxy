# CEL tenant gate on AI traffic

*Last modified: 2026-04-27*

A proxy-native pattern: a CEL expression runs at the network layer before any AI provider is contacted. Pure AI gateway libraries cannot reject a request based on the surrounding request context (auth claims, tenant headers, IP, geo) without taking on the proxy role themselves. Two CEL policies layer here: the first requires a non-empty `X-Tenant` header (anything without one gets a 403 before the AI handler reads the body, a hard tenant boundary); the second requires the tenant value to appear in an allow-list (unknown tenants are rejected with a different message so operators can spot misconfigured clients vs. unprovisioned ones). Both checks happen in the same place per-request rate limits and WAF rules run, so a single denial path covers AI, REST, and any other action behind the same hostname.

## Run

```bash
export OPENAI_API_KEY=sk-...
sbproxy serve -f sb.yml
```

## Try it

```bash
# No tenant header - 403 before the AI handler runs.
curl -i http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
# HTTP/1.1 403 Forbidden
# X-Tenant header required for AI access
```

```bash
# Unknown tenant - 403 with a different message.
curl -i http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'X-Tenant: stranger' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
# HTTP/1.1 403 Forbidden
# tenant not provisioned for AI access
```

```bash
# Allowed tenant - the AI provider answers.
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'X-Tenant: acme' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
  | jq .choices[0].message
```

## What this exercises

- `policy.type: expression` running CEL against `request.headers["x-tenant"]`
- Multiple CEL policies stacked so tenant presence and tenant allow-list are separate denials
- `deny_status` and `deny_message` per policy so the operator distinguishes misconfigured clients from unprovisioned ones
- AI traffic gated at the policy layer, before the `ai_proxy` handler reads the body

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md)
- [docs/scripting.md](../../docs/scripting.md)
- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
