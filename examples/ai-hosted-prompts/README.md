# Hosted model + prompt management

This example runs one hosted provider (Anthropic) behind the gateway and
uses the admin server to manage prompt versions and try the model from a
browser. Clients speak the OpenAI chat-completions shape; the gateway
translates to Anthropic and back.

The prompt store is runtime state managed over the admin API, not config,
so `sb.yml` only declares the provider and turns the admin server on.

## Run it

```bash
export ANTHROPIC_API_KEY=sk-ant-...
make run CONFIG=examples/ai-hosted-prompts/sb.yml
```

The data plane listens on `127.0.0.1:8080`; the admin server on
`127.0.0.1:9090` (HTTP Basic `admin` / `change-this`, change it before
exposing anything).

## Manage a prompt

Add a version. `version` is your label, `template` is the prompt text
(with optional `{{ variables.* }}` placeholders):

```bash
curl -u admin:change-this http://127.0.0.1:9090/admin/prompts/ai.local/greeting/versions \
  -H 'Content-Type: application/json' \
  -d '{"version": "1", "template": "You are a terse assistant. Answer in one sentence."}'
```

Pin it as the default:

```bash
curl -u admin:change-this -X PUT http://127.0.0.1:9090/admin/prompts/ai.local/greeting/pin \
  -H 'Content-Type: application/json' \
  -d '{"version": "1"}'
```

List what is stored (returns each prompt with its versions and the pinned
`default_version`):

```bash
curl -u admin:change-this http://127.0.0.1:9090/admin/prompts
```

Editing is live: add a `"2"` version and pin it, and the next request
picks it up with no restart.

## Send a request

An OpenAI-shaped chat completion to `ai.local`, served by Claude on the
upstream:

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "claude-haiku-4-5",
    "messages": [{"role": "user", "content": "Write a haiku about caching."}]
  }'
```

The response comes back in OpenAI shape (`choices[0].message.content`,
`usage.prompt_tokens`, ...) even though Claude served it.

## Or use the dashboard

Build the admin UI (`cd ui && npm run build`, then build sbproxy with
`--features embed-admin-ui`) and open `http://127.0.0.1:9090/admin/ui`:

- **Prompts** lists your versions and lets you add and pin them.
- **Playground** sends a chat completion to the `ai.local` endpoint and
  shows the response with token usage, cost, and latency.

See [`ai-gateway.md`](../../docs/ai-gateway.md) for provider translation
details and [`admin.md`](../../docs/admin.md) for the admin surface.
