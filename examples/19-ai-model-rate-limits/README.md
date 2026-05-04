# AI gateway: per-model rate limits

*Last modified: 2026-04-27*

Different models cost and behave differently, so they each need their own rate cap. The `model_rate_limits` map keys by model name and applies sliding one-minute windows for both requests and tokens. The cap fires regardless of which provider serves the model, so an alias or fallback chain that lands on the same upstream model still counts against the same window. Three caps are configured: `claude-3-5-sonnet-latest` at 60 RPM / 200,000 TPM, `claude-3-5-haiku-latest` at 240 RPM / 600,000 TPM, and the OpenRouter passthrough `anthropic/claude-3.5-sonnet` at 30 RPM / 100,000 TPM.

## Run

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export OPENROUTER_API_KEY=sk-or-...
make run CONFIG=examples/19-ai-model-rate-limits/sb.yml
```

Both env vars are required.

## Try it

A request well within the Sonnet cap succeeds:

```bash
$ curl -is http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{
      "model": "claude-3-5-sonnet-latest",
      "messages": [{"role": "user", "content": "Quick check."}]
    }' | head -n 1
HTTP/1.1 200 OK
```

Burst past the Sonnet cap (60 RPM):

```bash
$ for i in $(seq 1 80); do
    curl -s -o /dev/null -w '%{http_code}\n' \
      http://127.0.0.1:8080/v1/chat/completions \
      -H 'Host: ai.local' -H 'Content-Type: application/json' \
      -d '{"model":"claude-3-5-sonnet-latest","messages":[{"role":"user","content":"ping"}]}'
  done | sort | uniq -c
     60 200
     20 429
```

A 429 response carries `Retry-After`:

```bash
$ curl -is http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' -H 'Content-Type: application/json' \
    -d '{"model":"claude-3-5-sonnet-latest","messages":[{"role":"user","content":"ping"}]}' \
    | head -n 4
HTTP/1.1 429 Too Many Requests
content-type: application/json
retry-after: 14

{"error":{"message":"model rate limit exceeded","type":"rate_limit_error"}}
```

Other models are unaffected. While Sonnet is throttled, Haiku continues to serve traffic:

```bash
$ curl -s -o /dev/null -w '%{http_code}\n' \
    http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' -H 'Content-Type: application/json' \
    -d '{"model":"claude-3-5-haiku-latest","messages":[{"role":"user","content":"ping"}]}'
200
```

## What this exercises

- `ai_proxy.model_rate_limits` - per-model sliding-window caps
- `requests_per_minute` and `tokens_per_minute` - independent counters per model
- Provider-agnostic accounting - the same upstream model counts together regardless of which provider name served it
- 429 with `Retry-After` - well-behaved clients can back off

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md) - AI gateway overview
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
- [docs/metrics-stability.md](../../docs/metrics-stability.md) - per-model rate limit metrics
