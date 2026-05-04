# AI shadow / side-by-side evaluation

*Last modified: 2026-04-27*

Each request is forwarded to the primary provider as usual; a copy is also sent to the shadow provider concurrently. The shadow response is drained and never reaches the client; metadata is logged at `target=sbproxy_ai_shadow` so it can be filtered into a dedicated stream with provider, status, latency_ms, prompt_tokens, completion_tokens, and finish_reason. Useful for validating a model swap before flipping primary traffic, comparing finish_reason or token counts across providers, and spot-checking guardrail or routing changes without exposing experimental output to users. `sample_rate: 0.1` mirrors 10% of traffic; set to 1.0 to mirror every request (doubles spend on the shadow leg).

## Run

```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
sbproxy serve -f sb.yml
```

## Try it

```bash
# Real chat completion. The client always sees the OpenAI response.
# The Anthropic shadow runs in parallel and is logged but discarded.
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"What is 2+2?"}]}' \
  | jq .choices[0].message
```

```bash
# Tail the proxy logs to see shadow events. The fire-and-forget mirror
# never affects the client response status or body.
sbproxy serve -f sb.yml 2>&1 | grep sbproxy_ai_shadow
```

```bash
# Drive 20 requests; with sample_rate 0.1 you should see ~2 shadow logs.
for i in $(seq 1 20); do
  curl -s -o /dev/null -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
    http://127.0.0.1:8080/v1/chat/completions
done
```

## What this exercises

- `ai_proxy.shadow.provider` - which provider receives the mirrored request
- `ai_proxy.shadow.sample_rate` - probability that a given request is mirrored
- `ai_proxy.shadow.timeout_ms` - upper bound on the shadow leg before it is dropped
- Fire-and-forget mirroring: shadow latency and outcome do NOT affect the client response
- Structured shadow events emitted under `sbproxy_ai_shadow` for offline analysis

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md)
- [docs/routing-strategies.md](../../docs/routing-strategies.md)
- [docs/features.md](../../docs/features.md)
