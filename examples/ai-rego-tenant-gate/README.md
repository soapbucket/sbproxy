# Rego tenant gate on AI traffic

*Last modified: 2026-08-16*

The Rego twin of [`examples/ai-cel-tenant-gate/`](../ai-cel-tenant-gate/): the same tenant gate, the same request-time behavior, expressed as `policy: rego` instead of `policy: expression`. Two Rego policies layer here, evaluated in process on the Regorus interpreter before any AI provider is contacted. The first requires a non-empty `X-Tenant` header (anything without one gets a 403 before the AI handler reads the body, a hard tenant boundary); the second requires the tenant value to appear in an allow-list kept in `data`, separate from the policy logic, so an operator edits the allow-list without reading a line of Rego (unknown tenants are rejected with a different message so operators can spot misconfigured clients vs. unprovisioned ones). See [docs/opa-rego-policies.md](../../docs/opa-rego-policies.md) for the full field reference.

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
# {"error":"X-Tenant header required for AI access"}
```

```bash
# Unknown tenant - 403 with a different message.
curl -i http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'X-Tenant: stranger' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
# HTTP/1.1 403 Forbidden
# {"error":"tenant not provisioned for AI access"}
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

- `policy.type: rego` evaluating a Rego module against `input.request.headers["x-tenant"]`
- Multiple Rego policies stacked so tenant presence and tenant allow-list are separate denials
- `data` carrying the allow-list separately from the module, so the table changes without the policy changing
- `deny_status` and `deny_message` per policy so the operator distinguishes misconfigured clients from unprovisioned ones
- AI traffic gated at the policy layer, before the `ai_proxy` handler reads the body

## See also

- [docs/opa-rego-policies.md](../../docs/opa-rego-policies.md)
- [examples/ai-cel-tenant-gate/](../ai-cel-tenant-gate/) - the CEL twin of this example
- [docs/scripting.md](../../docs/scripting.md)
- [docs/ai-gateway.md](../../docs/ai-gateway.md)
- [docs/configuration.md](../../docs/configuration.md)
