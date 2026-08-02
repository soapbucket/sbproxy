# Mastra through SBproxy

The runnable half of [docs/mastra.md](../../docs/mastra.md). The sb.yml here is the doc's config with one substitution: the `openai` provider points at a local OpenAI-shaped fixture instead of `api.openai.com`, so the whole flow (virtual key match, model allow list, provider dispatch) runs without a provider account. The fixture answers every chat completion with the fixed string `fixture response` and echoes the requested model back.

## Run it

```bash
cd examples/mastra
docker compose up -d --wait
```

The first run compiles SBproxy into a local image. The gateway listens on `127.0.0.1:8080`; the fixture stays private to the compose network namespace.

## The doc's client, unchanged

The snippet from the doc works against this stack as written. Save it as `agent.mjs`, install with `npm install @mastra/core @ai-sdk/openai zod`, run with `node agent.mjs`:

```typescript
import { Agent } from "@mastra/core/agent";
import { createOpenAI } from "@ai-sdk/openai";

const openai = createOpenAI({
  baseURL: "http://127.0.0.1:8080/v1",
  apiKey: "sk-your-virtual-key",
});

const agent = new Agent({
  name: "gateway-agent",
  instructions: "You are a concise assistant.",
  model: openai.chat("gpt-4o-mini"),
});

const result = await agent.generate("In one sentence, what does an AI gateway do?");
console.log(result.text);
```

It prints `fixture response`: the agent's call crossed the gateway, matched the `mastra-app` credential, and reached the fixture model.

## Test

The curl equivalent of what the agent sends, so no npm install is needed to verify the wiring:

```bash
curl -sS http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer sk-your-virtual-key' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"In one sentence, what does an AI gateway do?"}]}'
```

<!-- CAPTURE: curl -sS http://127.0.0.1:8080/v1/chat/completions -H 'Content-Type: application/json' -H 'Authorization: Bearer sk-your-virtual-key' -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"In one sentence, what does an AI gateway do?"}]}' -->

A model outside the credential's `models.allow` list is rejected before any upstream call:

```bash
curl -sS -i http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer sk-your-virtual-key' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Try the expensive model."}]}'
```

<!-- CAPTURE: curl -sS -i http://127.0.0.1:8080/v1/chat/completions -H 'Content-Type: application/json' -H 'Authorization: Bearer sk-your-virtual-key' -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Try the expensive model."}]}' -->

Run the checked smoke cases from the repository root with:

```bash
bash scripts/examples-smoke.sh examples/mastra
```

## Clean up

```bash
docker compose down -v
```

## Read more

[docs/mastra.md](../../docs/mastra.md) walks through the config, the virtual key semantics, and the MCP tool path. [docs/ai-gateway.md](../../docs/ai-gateway.md) is the full AI gateway reference.
