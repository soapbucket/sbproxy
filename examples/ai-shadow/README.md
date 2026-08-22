# AI shadow / side-by-side evaluation

*Last modified: 2026-08-21*

![AI shadow / side-by-side evaluation](../../docs/assets/ai-shadow.gif)

Each request is forwarded to the primary provider as usual; a copy is also sent to every configured shadow target concurrently. This config runs two, Anthropic and Gemini. The shadow response is drained and never reaches the client; metadata is logged at `target=sbproxy_ai_shadow` so it can be filtered into a dedicated stream with provider, status, latency_ms, prompt_tokens, completion_tokens, and finish_reason. Useful for validating a model swap before flipping primary traffic, comparing finish_reason or token counts across providers, and spot-checking guardrail or routing changes without exposing experimental output to users.

`sample_rate: 0.1` mirrors 10% of traffic; set to 1.0 to mirror every request (doubles spend on that leg). One draw is taken per request and every target is compared against it, so the 0.1 Anthropic target only ever fires on requests the 0.5 Gemini target also fired on. That nesting is what makes two targets comparable: their measurements come from the same requests, not from two independent samples.

## Run

```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
export GEMINI_API_KEY=...
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
# Shadow events show up in the log output of the proxy started in the
# Run step; watch that terminal for target=sbproxy_ai_shadow lines. To
# see only shadow events, stop that proxy (both would bind port 8080)
# and restart it with the serve command piped through grep:
sbproxy serve -f sb.yml 2>&1 | grep sbproxy_ai_shadow
# The fire-and-forget mirror never affects the client response status
# or body.
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

```bash
# Per-target counters, read off the loopback admin listener this
# example enables. Both targets get their own series, so a slow or
# truncating target is visible without reading a log line.
curl -su admin:changeme http://127.0.0.1:9090/metrics | grep sbproxy_ai_shadow_calls_total
```

```
sbproxy_ai_shadow_calls_total{target="anthropic",status_class="2xx",finish_reason="stop"} 2
sbproxy_ai_shadow_calls_total{target="gemini",status_class="2xx",finish_reason="stop"} 9
sbproxy_ai_shadow_calls_total{target="gemini",status_class="2xx",finish_reason="length"} 1
```

## What this exercises

- `ai_proxy.shadow.targets[]` - the list of providers that receive the mirrored request; the single-target `shadow.provider` form still parses as a one-entry list
- `ai_proxy.shadow.targets[].sample_rate` - probability that a given request reaches that target, drawn once per request and shared across targets
- `ai_proxy.shadow.targets[].timeout_ms` - upper bound on that leg before it is dropped
- Fire-and-forget mirroring: shadow latency and outcome do NOT affect the client response
- One shared admission ceiling: each target takes a slot out of the same 16-task / 64 MiB budget, and a target that cannot get one is dropped as `saturated` while the others run
- Structured shadow events emitted under `sbproxy_ai_shadow` for offline analysis, one per target
- Per-target usage rows tagged `shadow`, joined to the primary by `shadow_of` and carrying `finish_reason`
- `sbproxy_ai_shadow_calls_total` and `sbproxy_ai_shadow_latency_seconds`, both labeled by target

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md)
- [docs/routing-strategies.md](../../docs/routing-strategies.md)
- [docs/features.md](../../docs/features.md)
