# Hybrid local + cloud AI gateway

*Last modified: 2026-04-27*

Routes cheap traffic to a locally-hosted model (Ollama, vLLM, LM Studio, Hugging Face TGI, or llama.cpp) and the long tail or tougher prompts to a hosted provider. The proxy presents an OpenAI-compatible interface to clients; each backend listed here also speaks OpenAI-compatible (`/v1/chat/completions` directly), so no format translation is needed and bytes pass through. Strategy is `fallback_chain`: try local first, fall through to OpenAI on error or unavailability. Switch to `cost_optimized` to send cheaper traffic to local even when both are healthy, or `weighted` to mix at a fixed ratio. The example provider list points at Ollama; the bottom of the `sb.yml` shows the same shape for vLLM, LM Studio, TGI, and llama.cpp.

## Run

```bash
ollama serve &
ollama pull llama3.1
export OPENAI_API_KEY=sk-...
sb run -c sb.yml
```

Set `OPENAI_API_KEY` so the cloud fallback works. If you do not have a local runtime yet, the request still succeeds because the chain falls through to OpenAI on connect failure.

## Try it

```bash
# Default chat completion. Local Ollama answers when it is up.
curl -s -H 'Host: localhost' -H 'Content-Type: application/json' \
     -d '{"model":"llama3.1","messages":[{"role":"user","content":"hi"}]}' \
     http://127.0.0.1:8080/v1/chat/completions | jq .choices[0].message
```

```bash
# Stop Ollama and rerun. The same call now falls through to OpenAI.
pkill ollama
curl -s -H 'Host: localhost' -H 'Content-Type: application/json' \
     -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
     http://127.0.0.1:8080/v1/chat/completions | jq .choices[0].message
```

```bash
# List the models the gateway exposes; the response is OpenAI-shaped.
curl -s -H 'Host: localhost' http://127.0.0.1:8080/v1/models | jq '.data[].id'
```

## What this exercises

- `ai_proxy` action with the `fallback_chain` routing strategy
- Local model providers (`ollama`, `vllm`, `lmstudio`, `tgi`, `llamacpp`) registered with their default base URLs
- Cloud fallback to `openai` keyed on `${OPENAI_API_KEY}`
- OpenAI-compatible client interface regardless of which provider answers

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md)
- [docs/providers.md](../../docs/providers.md)
- [docs/routing-strategies.md](../../docs/routing-strategies.md)
- [docs/features.md](../../docs/features.md)
