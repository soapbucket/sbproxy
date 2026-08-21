# Typed fallback triggers

*Last modified: 2026-08-20*

Typed fallback lists for two failure classes: `context_window_fallbacks:` reroutes an oversized prompt to a provider serving a larger-window model, and `content_policy_fallbacks:` reroutes a content-policy refusal to a more permissive provider, instead of the generic chain's next-in-order hop.

The generic chain (`routing.strategy: fallback_chain`) answers "the provider is unavailable, try the next one"; a typed list answers "this prompt needs a different model". Each list names providers from the same action, each trigger only acts on its own failure class, and the example is fully self-contained: the "providers" are two local sbproxy mock fixtures, so no API keys are needed.

## Run

Three processes: the two fixtures, then the gateway.

```bash
make run CONFIG=examples/typed-fallbacks/upstream-strict.yml &
make run CONFIG=examples/typed-fallbacks/upstream-permissive.yml &
make run CONFIG=examples/typed-fallbacks/sb.yml
```

The `window.local` origin has a small-window primary (`small`, serving `gpt-4` with an 8,192-token window) and a `context_window_fallbacks` entry pointing at `big-window`, whose `model_map` sends `gpt-4-turbo` (128,000 tokens). The `policy.local` origin has a refusing primary (`strict`, wired to the fixture that answers every request with an OpenAI-shaped content-policy error), a `backup` that the generic chain would try next, and a `content_policy_fallbacks` entry aiming refusals at `permissive` instead.

## Scenario 1: a prompt that fits stays put

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: window.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"In one sentence, what is a reverse proxy?"}]}' \
  | jq -r '.choices[0].message.content'
```

Recorded output:

```text
Hello from the answering fixture.
```

Nothing rerouted: the estimate fits `gpt-4`'s window, so `small` serves it.

## Scenario 2: an oversized prompt reroutes before dispatch

Build a prompt past 8,192 tokens and send it to the same origin:

```bash
PROMPT=$(python3 -c "print('lorem ipsum dolor sit amet ' * 1700)")
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: window.local' -H 'Content-Type: application/json' \
  -d "{\"model\":\"gpt-4\",\"messages\":[{\"role\":\"user\",\"content\":\"$PROMPT\"}]}" \
  | jq -r '.choices[0].message.content'
```

Recorded output:

```text
Hello from the answering fixture.
```

The call still answers, but the gateway's log shows the pre-flight reroute; the request never touched `small`:

```text
WARN sbproxy_core::server::ai_dispatch: AI proxy: pre-flight estimate exceeds the primary model's context window; rerouting to the context_window_fallbacks list from=small to=big-window estimated_tokens=8509 context_window=8192
```

The decision is pre-flight, from the same token estimate the compression levers use, which is what lets streaming requests reroute too: the choice is made before the stream opens. If a provider rejects with a `context_length_exceeded` error that the estimate missed, the same list catches it mid-loop.

## Scenario 3: a refusal reroutes to the aimed provider, not the next one

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: policy.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}' \
  | jq -r '.choices[0].message.content'
```

Recorded output:

```text
Hello from the answering fixture.
```

The caller sees a 200, not the refusal. The log names both hops and shows the typed list skipping `backup`, the provider the generic chain had queued next:

```text
WARN sbproxy_ai::routing: ai provider placed on per-error-class cooldown provider=strict cause="content_policy" cooldown_secs=60
WARN sbproxy_core::server::ai_dispatch: AI proxy: content-policy refusal, rerouting to the content_policy_fallbacks list provider=strict to=permissive
```

The first line is `resilience.cooldown_policy` at work: the same classification that picked the reroute list also parks `strict` for 60 seconds. Repeat the curl inside that window and it answers with no refusal hop at all, and no second pair of log lines: `strict` is out of rotation, so the request goes straight to a provider that can answer.

## Scenario 4: a trigger only fires for its own class

`window.local` configures only `context_window_fallbacks`. Send it a request while pointing its primary at a refusing upstream (or simply note the behavior in the e2e test `a_trigger_only_reroutes_its_own_failure_class`): a content-policy refusal there is returned to the caller unchanged, because the context-window list is not an any-error fallback. The reverse holds too: a typed list never widens what a request may reach, since candidates pass the same credential provider policy and model eligibility checks as every other selection.

## The admin decision view

Every rerouted request carries the trigger that fired. With the admin server from this config:

```bash
curl -s -u admin:admin 'http://127.0.0.1:9090/api/requests?limit=3' \
  | jq '[.[] | {path, status, failover_from, failover_to, failover_trigger}]'
```

Recorded output, newest first (the cooldown repeat, scenario 3's refusal reroute, scenario 2's oversized prompt, scenario 1's fitting prompt):

```json
[
  {
    "path": "/v1/chat/completions",
    "status": 200,
    "failover_from": null,
    "failover_to": null,
    "failover_trigger": null
  },
  {
    "path": "/v1/chat/completions",
    "status": 200,
    "failover_from": "strict",
    "failover_to": "permissive",
    "failover_trigger": "content_policy"
  },
  {
    "path": "/v1/chat/completions",
    "status": 200,
    "failover_from": "small",
    "failover_to": "big-window",
    "failover_trigger": "context_window"
  },
  {
    "path": "/v1/chat/completions",
    "status": 200,
    "failover_from": null,
    "failover_to": null,
    "failover_trigger": null
  }
]
```

`failover_trigger` distinguishes "the prompt outgrew the model" (`context_window`) from "the provider refused" (`content_policy`) from an ordinary availability failover (`generic`); a request that never rerouted carries none. The LogsView in the admin console prefixes its failover badge with the same vocabulary, so the row above reads `context window: small → big-window`. The pre-flight reroute records its `failover_from`/`failover_to` pair even though `small` was never dispatched to: the route is the decision, and a trigger with no route to explain it would be unreadable.

## What this exercises

- `context_window_fallbacks:` / `content_policy_fallbacks:`, the typed reroute lists (unknown provider names fail config load; nesting them under `routing:` is refused)
- `resilience.retry_policy` and `resilience.cooldown_policy`, per-error-class retry counts and provider cooldowns sharing the same failure classification
- `failover_trigger` on the admin request log, the visible record of which trigger fired

## See also

- [docs/ai-llm-aware-resilience.md](../../docs/ai-llm-aware-resilience.md) - the decision-path diagram, scope notes (streaming, race, cascade), and the failure-cause table.
- [docs/ai-gateway.md](../../docs/ai-gateway.md) - the AI gateway guide's routing and resilience sections.
- [`examples/ai-content-policy-fallback/`](../ai-content-policy-fallback/) - the older next-in-order boolean form.
