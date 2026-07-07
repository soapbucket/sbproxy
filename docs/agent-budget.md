# agent_budget policy
*Last modified: 2026-05-31*

![70 rapid requests from a Cursor user agent: 200s until the per-agent budget trips and the rest return 429](assets/agent-budget.gif)

The budget keys on the resolved agent_id, not the client IP ([config](../examples/agent-budget/)).

The `agent_budget` policy is a semantic rate-limit primitive keyed on the resolved `agent_id`. Standard per-IP / per-user / per-key limits assume humans pause between requests; agents driven by an LLM loop fire at network speed and trip those buckets immediately. Datadog reports roughly a third of LLM-span errors in production are rate-limit denials for exactly that reason.

One bucket per named agent collapses "every request from the Cursor instance" or "every request from the same OpenAI Assistant" into a single budget that an operator can actually size. The `agent_id` comes from the agent-class resolver (`sbproxy-agent-detect` / `sbproxy-classifiers`); when no `agent_id` resolved, the policy applies the `on_anonymous` rule.

## Config

```yaml
origins:
  "ai.example.com":
    upstream: https://api.openai.com
    auth:
      type: bearer
    policies:
      - type: agent_budget
        # Token-bucket refill rate, per agent_id.
        requests_per_minute: 60
        # Rolling LLM-token budget per agent_id. The token bucket
        # exists in the policy API; consumption is wired in via the
        # AI-usage tracker. Configuring without that wiring is a no-op
        # on the token field today.
        tokens_per_hour: 100000
        # Max simultaneous in-flight requests per agent_id. RAII guard
        # releases the slot when the request completes.
        burst: 10
        # What to do when the cap fires.
        # - deny (default): respond 429.
        # - log: emit the decision metric, pass the request through.
        # - downgrade: dispatcher routes to a cheaper model.
        on_exceed: deny
        # What to do when the request has no resolved agent_id.
        # - skip (default): no enforcement.
        # - shared: all anonymous requests share one bucket.
        on_anonymous: skip
```

## Decisions

The policy reports its verdict to the dispatcher; the dispatcher maps the verdict to a real action:

| Verdict | `on_exceed` | HTTP outcome |
|---|---|---|
| Within budget | n/a | pass through |
| Cap fired, deny | `deny` | 429 with `Retry-After` |
| Cap fired, log | `log` | pass through, metric increments |
| Cap fired, downgrade | `downgrade` | dispatcher picks the cheaper AI provider for this request |

## Observability

* `sbproxy_policy_triggers_total{origin, policy_type="agent_budget", action="block"}` increments on `deny` denials.
* `sbproxy_ai_budget_utilization_ratio{origin, agent_id}` gauge reports the current utilisation per agent.
* Access log: `policy_action` set to the verdict; `agent_id`, `agent_class`, `agent_vendor` carry the resolved agent identity.

## Why per-agent

A standard rate-limit policy keyed on IP or API key cannot distinguish "Cursor making 200 background completions while the user types" from "an attacker fanning out 200 distinct concurrent prompts". Both look identical to an IP-keyed bucket. Keying on `agent_id` (the resolved agent identity, not the network address) lets the operator size the legitimate background traffic without hardening to it, and lets the abuse path get blocked cleanly because the attacker cannot produce a fresh `agent_id` per request without re-resolving against the agent registry.

## Out of scope for slice 1

* Cluster-shared budgets. Each proxy enforces its own local view; an attacker spreading across replicas sees N times the per-instance budget. A cluster-shared backend (Redis or shared KV) is the obvious follow-up; for now, treat the per-instance budget as the floor.
* Upstream token accounting. `tokens_per_hour` is wired into the policy API but only consumed when the AI gateway calls `AgentBudgetPolicy::consume_tokens`. A follow-up wires that into `sbproxy-ai`'s usage tracker.

## See also

* [features.md](./features.md) - tour with policy examples.
* [examples/agent-budget/](../examples/agent-budget/) - runnable per-agent rate-limit fixture.
* [ai-gateway.md](./ai-gateway.md) - the AI surfaces the budget protects.
* [configuration.md](./configuration.md) - the full schema.
