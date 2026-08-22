# AI gateway: model group (one public name, several deployments)

*Last modified: 2026-08-21*

![AI gateway: model group (one public name, several deployments)](../../docs/assets/ai-model-group.gif)

A model group is one public name your callers send as `model`, served by several deployments. A `model_groups:` entry names the members: each one is a provider on this action, the upstream model id that provider serves, and its share of traffic. Members may serve **different** model ids, which is what a same-model-name pool cannot express.

This example splits the public name `chat` 9:1 across two deployments that serve two different model ids: `gpt-4o-mini` on one and `gpt-3.5-turbo` on the other. Both are real OpenAI model ids, so the walkthrough runs as written against one key; in a real deployment the second member would be another vendor's endpoint with its own key and base URL. The group carries its own `routing: weighted`, independent of the action's `routing: round_robin`.

The simpler shape still works and is still right when every deployment serves the same model id: list each one as a provider whose `models:` declares that model, and the action's `routing` load-balances across them. The LiteLLM importer emits that shape from a `model_list` whose entries share a `model_name`. See [docs/migration-litellm.md](../../docs/migration-litellm.md).

## Run

```bash
export OPENAI_API_KEY=sk-...
make run CONFIG=examples/ai-model-group/sb.yml
```

## Try it

Every request addresses the single public name; the group picks a member and rewrites the model on the way out:

```bash
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' -H 'Content-Type: application/json' \
    -d '{"model":"chat","messages":[{"role":"user","content":"In one sentence, what is load balancing?"}]}' \
    | jq -r '.model, .choices[0].message.content'
```

The `model` in the response is the member's id, `gpt-4o-mini` or `gpt-3.5-turbo`, never `chat`. Nine of every ten requests take the first.

Every gate below the pick sees the member's real id, so a group is never a way around one. Block every member's model and the group is refused outright, even though the group name itself is not blocked:

```bash
# with `blocked_models: [gpt-4o-mini, gpt-3.5-turbo]` on the action
$ curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' -H 'Content-Type: application/json' \
    -d '{"model":"chat","messages":[{"role":"user","content":"hi"}]}'
403
```

Block only `gpt-4o-mini` and the split shows through: the nine requests in ten that
pick that member answer `403`, and the tenth is served by `gpt-3.5-turbo`. The gate
judges the member, never the name.

## Group info and health (LiteLLM-parity endpoints)

The gateway serves read-only metadata endpoints from this config, no upstream call:

```bash
# The configured group, with its members.
curl -s -H 'Host: ai.local' http://127.0.0.1:8080/model_group/info | jq '.data[] | select(.model_group=="chat")'
# => {"model_group":"chat","num_deployments":2,
#     "providers":["openai-deployment-a","openai-deployment-b"],
#     "capabilities":["audio_speech","audio_transcription","chat_completions",
#                     "embeddings","image_edits","image_generation",
#                     "image_variations","messages","moderations","realtime",
#                     "responses","streaming"],
#     "members":[{"provider":"openai-deployment-a","model":"gpt-4o-mini","weight":9},
#                {"provider":"openai-deployment-b","model":"gpt-3.5-turbo","weight":1}],
#     "routing":"weighted"}
#
# `capabilities` is the union across the group's members. Both are
# `provider_type: openai` here, so the union is one member's array; a group
# mixing an OpenAI deployment with an embeddings-only provider would list the
# surfaces of both.

# The OpenAI-shaped listing carries the group beside the model ids.
curl -s -H 'Host: ai.local' http://127.0.0.1:8080/v1/models | jq '.data[].id'
# => "chat", "gpt-3.5-turbo", "gpt-4o-mini"

# Flat list of every deployment, each with the same capabilities array.
curl -s -H 'Host: ai.local' http://127.0.0.1:8080/model/info | jq

# Health (also /health/readiness and /health/liveliness).
curl -s -H 'Host: ai.local' http://127.0.0.1:8080/health
# => {"status":"healthy"}
```

## What this exercises

- A `model_groups:` entry whose members serve different upstream model ids behind one public name.
- A per-group `routing: weighted` with per-member weights, independent of the action's own strategy.
- Resolution before every model gate, so `blocked_models`, per-key allowlists, per-model rate limits, and the budget scope all judge the member's id.
- Per-deployment ejection via outlier detection or a circuit breaker moves the group's traffic to a sibling member rather than taking the group offline.

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md) - the model groups section, and routing strategies.
- [examples/ai-routing-fallback](../ai-routing-fallback) - priority failover instead of load balancing.
