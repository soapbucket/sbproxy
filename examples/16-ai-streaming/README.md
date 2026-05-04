# AI gateway: SSE streaming

*Last modified: 2026-04-27*

Streaming is on by default in the AI gateway. The minimal Anthropic origin in this example handles `"stream": true` requests end-to-end: sbproxy opens a server-sent-events connection to the upstream, forwards each chunk as it arrives, and harvests token usage from the final chunk into the `sbproxy_ai_tokens_total` counter. The streaming analytics module records time-to-first-token, tokens per second, and average inter-token latency for every streamed request. No special config is required; the behaviour is selected by the client request body.

## Run

```bash
export ANTHROPIC_API_KEY=sk-ant-...
make run CONFIG=examples/16-ai-streaming/sb.yml
```

Requires `ANTHROPIC_API_KEY`.

## Try it

curl, OpenAI-compatible streaming body:

```bash
$ curl --no-buffer -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{
      "model": "claude-3-5-sonnet-latest",
      "stream": true,
      "messages": [{"role": "user", "content":
        "Stream a short story about a lighthouse keeper, six sentences."}]
    }'
data: {"id":"chatcmpl-...","object":"chat.completion.chunk","model":"claude-3-5-sonnet-latest","choices":[{"index":0,"delta":{"role":"assistant","content":"The "},"finish_reason":null}]}

data: {"id":"chatcmpl-...","object":"chat.completion.chunk","model":"claude-3-5-sonnet-latest","choices":[{"index":0,"delta":{"content":"lighthouse "},"finish_reason":null}]}

data: {"id":"chatcmpl-...","object":"chat.completion.chunk","model":"claude-3-5-sonnet-latest","choices":[{"index":0,"delta":{"content":"keeper "},"finish_reason":null}]}

...

data: {"id":"chatcmpl-...","object":"chat.completion.chunk","model":"claude-3-5-sonnet-latest","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":18,"completion_tokens":97,"total_tokens":115}}

data: [DONE]
```

Python, OpenAI SDK:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:8080/v1",
    api_key="unused",
    default_headers={"Host": "ai.local"},
)
stream = client.chat.completions.create(
    model="claude-3-5-sonnet-latest",
    messages=[{"role": "user", "content": "Count to ten."}],
    stream=True,
)
for chunk in stream:
    if chunk.choices[0].delta.content:
        print(chunk.choices[0].delta.content, end="", flush=True)
```

A non-streaming request to the same endpoint still works and returns a single JSON document with the full response.

## What this exercises

- `ai_proxy` action - SSE streaming front door over Anthropic upstream
- `text/event-stream` response framing - one `data:` line per delta, `data: [DONE]` terminator
- Token accounting on the final chunk - `sbproxy_ai_tokens_total` increment
- Streaming analytics - TTFT, TPS, and inter-token latency metrics emitted per stream

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md) - AI gateway overview
- [docs/providers.md](../../docs/providers.md) - per-provider streaming notes
- [docs/metrics-stability.md](../../docs/metrics-stability.md) - streaming analytics metrics
