# n8n through SBproxy

The runnable half of [docs/n8n.md](../../docs/n8n.md). n8n workflows normally call model providers directly: you paste an OpenAI key into a credential and every AI Agent run hits `api.openai.com`. Point that credential's Base URL at an SBproxy you run instead, and every workflow run crosses one gateway that scopes models, meters spend, screens traffic, and records what happened.

The `sb.yml` here is the doc's config with one substitution: the `openai` provider points at a local OpenAI-shaped fixture (`fixture.py`) instead of `api.openai.com`, so the whole flow (virtual key match, model allow list, attribution) runs without a provider account. The fixture answers every chat completion with the fixed string `fixture response` and echoes the requested model back.

## Run it

```bash
cd examples/n8n
docker compose up -d --wait
```

The first run compiles SBproxy into a local image. The gateway listens on `127.0.0.1:8080`; the fixture stays private to the compose network namespace.

## The n8n side

The doc's n8n steps are unchanged. In n8n, create an OpenAI credential with:

- **Base URL:** `http://127.0.0.1:8080/v1`
- **API Key:** `sk-your-virtual-key`

Every OpenAI Chat Model node built on that credential, and every AI Agent that uses it, now runs through the gateway. No custom node is needed.

## Verify the gateway side

Before opening n8n, send the request its OpenAI Chat Model node will send. This is the same wire bytes, so no n8n install is needed to confirm the wiring:

```bash
$ curl -sS http://127.0.0.1:8080/v1/chat/completions \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer sk-your-virtual-key' \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hi in one sentence."}]}'
{"id":"chatcmpl-fixture","object":"chat.completion","created":0,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"fixture response"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}
```

The completion came back, so the whole path works: key matched, model allowed, provider (the fixture) reached.

A model outside the credential's `models.allow` list is rejected before any upstream call, which is the scoping doing its job:

```bash
$ curl -sS -i http://127.0.0.1:8080/v1/chat/completions \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer sk-your-virtual-key' \
    -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Try the expensive model."}]}'
HTTP/1.1 403 Forbidden
content-type: application/json
content-length: 54

{"error":"model 'gpt-4o' is not allowed for this key"}
```

Run the checked smoke cases from the repository root with:

```bash
bash scripts/examples-smoke.sh examples/n8n
```

## What this shows

- An n8n OpenAI credential routed through the gateway by changing one Base URL field
- The virtual key matching a credential, enforcing the model allow list, and stamping attribution
- The provider key staying in the gateway's environment, never in n8n

## Clean up

```bash
docker compose down -v
```

## Read more

[docs/n8n.md](../../docs/n8n.md) walks through the n8n credential fields, the virtual key semantics, and budgets. [docs/ai-gateway.md](../../docs/ai-gateway.md) is the full AI gateway reference.
