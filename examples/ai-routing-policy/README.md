# AI gateway: an operator-authored routing policy

*Last modified: 2026-08-15*

The built-in routing strategies pick from a fixed menu. `ai_routing_policy` hands the routing decision itself to operator code: one sandboxed CEL expression reads the gateway-computed `ai` decision view and returns a plan (an ordered candidate list plus a reason), or `null` to decline to the configured `routing` strategy. Declining is the cheap common path, so a policy with an opinion about a few kinds of request costs nothing for the rest.

This example composes three signals no fixed strategy can weigh together:

- `ai.prompt.difficulty`: a heuristic in `[0.0, 1.0]` over prompt shape (length, code, math, multi-step reasoning), the same score the built-in `cost_quality` strategy routes on.
- `ai.providers`: each provider's live health, p50 latency, in-flight count, and circuit-breaker state, the same signals the latency- and load-aware strategies select on.
- `ai.catalog`: per-model prices (USD per million tokens, resolved exactly as cost accounting resolves them) and context windows, rebuilt on config reload.

The decision order in `sb.yml`: shed everything to the cheap tier while the frontier provider is unhealthy or circuit-open; send hard prompts (difficulty above 0.7) to the frontier model; downgrade pricey models for callers without the `pro` tier tag; decline everything else to `least_token_usage`.

Every plan carries a `reason` that reaches the access log and a `reason_code` from the config's bounded allowlist that becomes the `sbproxy_ai_routing_policy_decisions_total{outcome, reason_code}` metric label. A plan can never route around the model allowlist (a plan naming a blocked model refuses with 403), and the policy does not run for bring-your-own-key requests.

## Run

```bash
export OPENAI_API_KEY=sk-...
make run CONFIG=examples/ai-routing-policy/sb.yml
```

## Try it

A trivial prompt scores near zero difficulty, no rule fires, and the policy declines: the request load-balances through `least_token_usage` as if the policy were not there.

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "What is the capital of France?"}]
  }'
```

A hard prompt (code plus step-by-step reasoning) scores above the 0.7 threshold, so the plan routes it to the frontier model and the access log carries `hard prompt` as the route reason:

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role": "user",
      "content": "Prove step by step that the following function terminates:\n```\ndef f(n):\n    while n > 1:\n        n = n // 2\n    return n\n```"}]
  }'
```

## Watch the decisions

Each policy decision ticks `sbproxy_ai_routing_policy_decisions_total{outcome, reason_code}`: `plan` when a plan executed (labeled with its reason code), `decline` when the strategy ran, `overridden` when a security `ai_policy route_to` cleared the plan, and `error` when evaluation faulted and `on_error` decided.

```bash
curl -s http://127.0.0.1:8080/metrics | grep ai_routing_policy_decisions
```

The same decision can be authored in Lua, JavaScript, or Rego with the `engine` + `source` form; see the routing policy section of [the AI gateway doc](../../docs/ai-gateway.md).
