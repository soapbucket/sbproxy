# Multi-tenant SaaS: three credential scopes, resolved per request

![Multi-tenant SaaS: three credential scopes, resolved per request](../../docs/assets/multi-tenant-saas.gif)

The runnable half of [docs/multi-tenant.md](../../docs/multi-tenant.md). One binary, three tenants, one shared upstream. Credentials are declared at three scopes and resolution walks origin to tenant to proxy, most-specific-wins by name.

That rule is invisible from a config listing and obvious from a curl, so this config makes each half of it reachable:

| Scope | Credential name | Inbound key | Effect |
|---|---|---|---|
| `proxy.credentials` | `openai-shared` | `sk-shared-default` | The operator default every tenant starts from |
| `tenants[acme-corp]` | `openai-shared` | `sk-acme-shared` | Same name, so it shadows the default for acme's origins only |
| `tenants[beta-corp]` | `openai-experimental` | `sk-beta-experimental` | A new name, so beta sees both it and the default |

`require_governed_key: true` on each origin is what makes the resolution observable: a key that resolved at no scope is refused rather than dispatching ungoverned. The provider points at the example's own OpenAI-shaped fixture, so every tenant reaches the same upstream and anything that differs between them came from the config.

## Run

```bash
python3 examples/multi-tenant-saas/fixture.py &
make run CONFIG=examples/multi-tenant-saas/sb.yml
```

Or under compose, which is what the smoke runner uses:

```bash
cd examples/multi-tenant-saas
docker compose up -d --wait
```

## Test

Acme's own copy of `openai-shared`:

```bash
curl -sS http://127.0.0.1:8080/v1/chat/completions -H 'Host: acme.local' \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer sk-acme-shared' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

```
{"id":"chatcmpl-fixture","object":"chat.completion","created":0,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"fixture response"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}
```

The proxy default carries the same credential name, so acme's copy shadowed it. At acme's origin that key does not exist:

```bash
curl -sS -i http://127.0.0.1:8080/v1/chat/completions -H 'Host: acme.local' \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer sk-shared-default' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

```
HTTP/1.1 401 Unauthorized
content-type: application/json
content-length: 40
Date: Sun, 02 Aug 2026 05:24:23 GMT
Connection: close

{"error":"governed credential required"}
```

Beta declared a credential under a new name, which adds rather than replaces. Both keys resolve at beta's origin, and each keeps its own model allow list, so the shared key refuses a model beta's own key is allowed:

```bash
curl -sS http://127.0.0.1:8080/v1/chat/completions -H 'Host: beta.local' \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer sk-beta-experimental' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}'
curl -sS http://127.0.0.1:8080/v1/chat/completions -H 'Host: beta.local' \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer sk-shared-default' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}'
```

```
{"id":"chatcmpl-fixture","object":"chat.completion","created":0,"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"fixture response"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}
{"error":"model 'gpt-4o' is not allowed for this key"}
```

`shared.local` declares no `tenant_id`, so it resolves to the synthetic `__default__` tenant: the proxy defaults, and nothing a tenant declared:

```bash
curl -sS -i http://127.0.0.1:8080/v1/chat/completions -H 'Host: shared.local' \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer sk-beta-experimental' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

```
HTTP/1.1 401 Unauthorized
content-type: application/json
content-length: 40
Date: Sun, 02 Aug 2026 05:24:23 GMT
Connection: close

{"error":"governed credential required"}
```

Every request the proxy served is filed under the tenant that served it. After the calls above, the attribution counter carries one series per tenant:

```
sbproxy_ai_requests_attributed_total{api_key_id="",model="",origin="acme.local",outcome="auth_denied",provider="",surface="chat_completions",tenant_id="acme-corp"} 2
sbproxy_ai_requests_attributed_total{api_key_id="",model="",origin="shared.local",outcome="auth_denied",provider="",surface="chat_completions",tenant_id="__default__"} 2
sbproxy_ai_requests_attributed_total{api_key_id="cfg:9:acme-corp:10:acme.local:openai-shared",model="gpt-4o-mini",origin="acme.local",outcome="ok",provider="openai",surface="chat_completions",tenant_id="acme-corp"} 2
sbproxy_ai_requests_attributed_total{api_key_id="cfg:9:beta-corp:10:beta.local:openai-experimental",model="gpt-4o",origin="beta.local",outcome="ok",provider="openai",surface="chat_completions",tenant_id="beta-corp"} 1
sbproxy_ai_requests_attributed_total{api_key_id="cfg:9:beta-corp:10:beta.local:openai-shared",model="",origin="beta.local",outcome="auth_denied",provider="",surface="chat_completions",tenant_id="beta-corp"} 1
```

Run the checked smoke cases from the repository root with:

```bash
bash scripts/examples-smoke.sh examples/multi-tenant-saas
```

## What this does not give you

Tenants share the proxy process. A tenant whose policy panics takes the whole proxy with it, and per-tenant CPU and memory caps need an outer orchestrator. Mutually untrusting tenants belong behind one proxy per trust boundary. [docs/multi-tenant.md](../../docs/multi-tenant.md) has the full list of what is and is not guaranteed.

## Clean up

```bash
docker compose down -v
```

## Read more

- [docs/multi-tenant.md](../../docs/multi-tenant.md) - the three scopes, isolation guarantees, and the adoption path
- [examples/vault-reference/](../vault-reference/) - the same shape with provider keys resolved from secret backends
- [examples/ai-virtual-keys/](../ai-virtual-keys/) - single-tenant credentials with two team-scoped keys
