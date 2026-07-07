# AI gateway quickstart: one OpenAI-compatible binary, every vendor

*Last modified: 2026-06-24*

![sbproxy routing one OpenAI-shaped request to OpenAI, Anthropic, and Google](../../docs/assets/ai-gateway.gif)

Point any OpenAI-shaped client at sbproxy and reach OpenAI, Anthropic, or Google without changing how you build requests or parse responses. Each vendor is a separate origin here, so you pick the upstream by host (`openai.local`, `claude.local`, `gemini.local`); sbproxy translates the request on the way out and the response on the way back, so every answer returns in OpenAI chat-completion shape.

Each provider declares a `models:` list, so the requested model first narrows which providers are eligible; routing strategies such as `round_robin` and `fallback_chain` then choose among the eligible providers, and the model name is forwarded as-is. One endpoint, one key, and the `model` field picks the vendor.

## Run

```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
export GEMINI_API_KEY=...
make run CONFIG=examples/ai-gateway-quickstart/sb.yml
```

## Try it

Same request shape, pick the vendor by host:

```bash
# OpenAI
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: openai.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"In one sentence, what is a reverse proxy?"}]}' \
  | jq -r '.model, .choices[0].message.content'

# Anthropic Claude (same request, different host)
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: claude.local' -H 'Content-Type: application/json' \
  -d '{"model":"claude-haiku-4-5","messages":[{"role":"user","content":"In one sentence, what is a reverse proxy?"}]}' \
  | jq -r '.model, .choices[0].message.content'

# Google Gemini
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: gemini.local' -H 'Content-Type: application/json' \
  -d '{"model":"gemini-3.5-flash","messages":[{"role":"user","content":"In one sentence, what is a reverse proxy?"}]}' \
  | jq -r '.model, .choices[0].message.content'
```

Each response carries the upstream model id in `.model`, so you can see which vendor served it. The GIF above shows the cassette recorded with `scripts/record-tapes.sh ai-gateway`.
