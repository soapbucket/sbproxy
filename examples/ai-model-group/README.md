# AI gateway: model group (one public name, several deployments)

*Last modified: 2026-06-24*

A model group is LiteLLM's core load-balancing abstraction: several deployments share one public model name, and requests to that name are spread across them. SBproxy expresses it directly. List each deployment as a provider whose `models` list declares the same model. The requested model selects the group (model-based provider routing), and the `routing` strategy load-balances across the matching deployments. Outlier detection ejects a failing deployment without taking the group offline.

This is also the shape the LiteLLM importer emits: two `model_list` entries that share a `model_name` become two providers declaring that model. See [docs/migration-litellm.md](../../docs/migration-litellm.md).

## Run

```bash
export OPENAI_API_KEY=sk-...
make run CONFIG=examples/ai-model-group/sb.yml
```

## Try it

Every request addresses the single public name; the group load-balances across the deployments:

```bash
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' -H 'Content-Type: application/json' \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"In one sentence, what is load balancing?"}]}' \
    | jq -r '.model, .choices[0].message.content'
```

## Group info and health (LiteLLM-parity endpoints)

The gateway serves read-only metadata endpoints from this config, no upstream call:

```bash
# Deployments grouped by public model name.
curl -s -H 'Host: ai.local' http://127.0.0.1:8080/model_group/info | jq
# => {"data":[{"model_group":"gpt-4o-mini","num_deployments":2,"providers":["openai-deployment-a","openai-deployment-b"]}]}

# Flat list of every deployment.
curl -s -H 'Host: ai.local' http://127.0.0.1:8080/model/info | jq

# Health (also /health/readiness and /health/liveliness).
curl -s -H 'Host: ai.local' http://127.0.0.1:8080/health
# => {"status":"healthy"}
```

## What this exercises

- Model-based provider routing: the `model` field selects the group of providers that declare it.
- `routing: round_robin` (swap for `weighted`, `least_connections`, `lowest_latency`, etc.) to distribute across deployments.
- Per-deployment ejection via outlier detection keeps the group available when one deployment fails.

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md) - routing strategies and model-based selection.
- [examples/ai-routing-fallback](../ai-routing-fallback) - priority failover instead of load balancing.
