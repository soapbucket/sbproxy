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

Set `routing: outcome_aware` on any multi-provider `ai_proxy` origin. While
providers warm up it round-robins; once each has a handful of samples it
commits to the best realized cost-per-success. It is safe to enable with no
other change.
