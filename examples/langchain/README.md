# LangChain through SBproxy

![LangChain through SBproxy](../../docs/assets/langchain.gif)

The runnable half of [docs/langchain.md](../../docs/langchain.md). The sb.yml here is the doc's config with one substitution: the `openai` provider points at a local OpenAI-shaped fixture instead of `api.openai.com`, so the whole flow (virtual key match, model allow list, provider dispatch) runs without a provider account. The fixture answers every chat completion with the fixed string `fixture response` and echoes the requested model back.

## Run it

```bash
cd examples/langchain
docker compose up -d --wait
```

The first run compiles SBproxy into a local image. The gateway listens on `127.0.0.1:8080`; the fixture stays private to the compose network namespace.

## The doc's client, unchanged

The snippet from the doc works against this stack as written. Save it as `chat.py`, install with `pip install langchain-openai`, run with `python chat.py`:

```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    model="gpt-4o-mini",
    base_url="http://127.0.0.1:8080/v1",
    api_key="sk-your-virtual-key",
)

reply = llm.invoke("In one sentence, what does an AI gateway do?")
print(reply.content)
```

It prints `fixture response`: the `invoke` call crossed the gateway, matched the `langchain-app` credential, and reached the fixture model.

## Test

The doc's curl check, the same wire bytes `ChatOpenAI` sends, so no pip install is needed to verify the wiring:

```bash
curl -sS http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer sk-your-virtual-key' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hello."}]}'
```

```
{
  "id": "chatcmpl-fixture",
  "object": "chat.completion",
  "created": 0,
  "model": "gpt-4o-mini",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "fixture response"
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 1,
    "completion_tokens": 1,
    "total_tokens": 2
  }
}
```

A model outside the credential's `models.allow` list is rejected before any upstream call:

```bash
curl -sS -i http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer sk-your-virtual-key' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Try the expensive model."}]}'
```

```
HTTP/1.1 403 Forbidden
content-type: application/json
content-length: 54
Date: Sun, 02 Aug 2026 03:43:49 GMT
Connection: keep-alive

{"error":"model 'gpt-4o' is not allowed for this key"}
```

Run the checked smoke cases from the repository root with:

```bash
bash scripts/examples-smoke.sh examples/langchain
```

## Clean up

```bash
docker compose down -v
```

## Read more

[docs/langchain.md](../../docs/langchain.md) walks through the config, the virtual key semantics, the Anthropic-native path, and the MCP tool path. [docs/ai-gateway.md](../../docs/ai-gateway.md) is the full AI gateway reference.

This example covers the chat-completions half of the page only. For the MCP tool half, [examples/mcp-federation](../mcp-federation/) is the runnable federation stack the doc sends you to: it ships its own upstream, so `tools/list` and `tools/call` complete without an external tool server.
