# Outcome-aware routing

Route by the realized cost-per-success fed back from completed requests,
not list price or live latency alone. The gateway folds each call's
outcome (success / refusal / cost / latency) into a per-provider rolling
estimate and sends traffic to the provider that is succeeding most cheaply,
demoting one whose refusal or error rate is climbing.

See [`docs/ai-outcome-aware-routing.md`](../../docs/ai-outcome-aware-routing.md)
for the full reference.

## Run

```bash
export OPENAI_API_KEY=sk-...
make run CONFIG=examples/ai-outcome-aware-routing/sb.yml
```

## Try it

```bash
# Ordinary chat request. Fire this in a loop and traffic converges on
# whichever of the two deployments is succeeding most cheaply.
curl -s -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hi in one word."}]}' \
  http://127.0.0.1:8080/v1/chat/completions
# 200 (with a valid OPENAI_API_KEY)

# Malformed body: rejected before either provider is chosen.
curl -s -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d 'not json' \
  http://127.0.0.1:8080/v1/chat/completions
# 400 {"error":"invalid JSON body"} - no API key needed to see this one
```

Set `routing: outcome_aware` on any multi-provider `ai_proxy` origin. While
providers warm up it round-robins; once each has a handful of samples it
commits to the best realized cost-per-success. It is safe to enable with no
other change.
