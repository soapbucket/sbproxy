# LLM-aware resilience

Classify each upstream failure into an LLM-specific cause and apply a retry
count per error class, instead of treating every 5xx the same.

See [`docs/ai-llm-aware-resilience.md`](../../docs/ai-llm-aware-resilience.md)
for the full reference.

## What this config does

Failover runs across two deployments. The `retry_policy` sets a retry count
per error class:

- `rate_limit: 3`: a `429` retries up to 3 times.
- `server_error: 2`: a `5xx` retries up to 2.
- `content_policy: 0` and `bad_request: 0`: a refusal or malformed request
  never retries in place (it would only fail again).

A class with no entry falls back to its default retryability (timeouts,
rate limits, and server errors are retryable; auth, bad-request,
content-policy, and context-window are not).

## Run

```bash
export OPENAI_API_KEY=sk-...
make run CONFIG=examples/ai-llm-aware-resilience/sb.yml
```

## Try it

```bash
# Ordinary chat request against the primary deployment.
curl -s -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hi in one word."}]}' \
  http://127.0.0.1:8080/v1/chat/completions
# 200 (with a valid OPENAI_API_KEY)

# Malformed body: rejected before the retry policy or either deployment
# is touched.
curl -s -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d 'not json' \
  http://127.0.0.1:8080/v1/chat/completions
# 400 {"error":"invalid JSON body"} - no API key needed to see this one
```

Watch the log for `retry attempt=` lines to see the per-error-class retry
count in action: a `429` from the primary deployment retries up to 3
times before the chain advances to the secondary.

## Stateful context compression

The `context_compress` boolean above is the legacy deterministic window-fit
path. For the ordered pipeline with running summaries, explicit state, session
lifecycle operations, and compression telemetry, use this runnable example:

- [Redis-backed AI context compression](../ai-context-compression-redis/)
